#!/usr/bin/env bash
# Exercises stage-from-release.sh against fixture releases made from a release's assets, served over HTTP on
# 127.0.0.1 through PFAI_RELEASE_BASE_URL by Python's http.server (its own file handler, with every request's
# path and Authorization header written to a log). No Maven, no PingFederate, a few seconds.
#
#   build/pingfederate/test-stage-from-release.sh <dist-dir>
#
# <dist-dir> is what tools/ci/assemble-dist.sh writes, with a SHA256SUMS over it (and a PROVENANCE.txt, as a
# release has); its war-assembler-<version>.jar names the version the fixtures are published as. Build's image
# job runs this after it has staged that directory both ways. The script under test runs from a copy in a
# scratch directory, so its .release/ cache is the scratch directory's and never this one's.
#
# Cases: a good release stages for both profiles, from the fixture server and then from the cache alone; a
# tampered jar, a jar missing from SHA256SUMS, a SHA256SUMS naming a file the release lacks (fetched and as a
# directory), a stray file in a directory source, a release with no war assembler (the shape of every release
# before 0.7.0) and an unknown profile are each refused with their own message, and stage nothing; no request
# carries an Authorization header, although GH_TOKEN and GITHUB_TOKEN are set; and the production profile never
# stages the CIBA simulator. Exit status: 0 when every case passes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[[ $# -eq 1 && -f "$1/SHA256SUMS" ]] || { echo "usage: test-stage-from-release.sh <dist-dir with a SHA256SUMS>" >&2; exit 2; }
DIST="$(cd "$1" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required" >&2; exit 2; }
# shellcheck source=stage-lib.sh
. "$HERE/stage-lib.sh"

assembler="$(cd "$DIST" && ls war-assembler-*.jar 2>/dev/null || true)"
[[ "$assembler" =~ ^war-assembler-(.+)\.jar$ ]] || { echo "ERROR: $DIST holds no single war-assembler-<version>.jar" >&2; exit 2; }
VERSION="${BASH_REMATCH[1]}"

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
T="$WORK/image"; SRV="$WORK/srv"; LOG="$WORK/requests.log"
mkdir -p "$T" "$SRV"; : > "$LOG"
cp "$HERE/stage-from-release.sh" "$HERE/stage-lib.sh" "$T/"

# One fixture release per case, each under $SRV/<case>/v<version>/, made from the dist and then spoiled.
fixture() {
  local dir="$SRV/$1/v$VERSION"
  mkdir -p "$dir"; cp "$DIST"/* "$dir/"
  echo "$dir"
}
resum() { ( cd "$1" && rm -f SHA256SUMS && for f in *; do echo "$(pfai_sha256 "$f")  $f"; done > "$WORK/sums" && mv "$WORK/sums" SHA256SUMS ); }
module="$(sed -n 's/^[0-9a-f]\{64\}  //p' "$DIST/MANIFEST" | head -n 1)"

fixture good >/dev/null
d="$(fixture tampered)"; printf 'x' >> "$d/$module"
d="$(fixture unlisted)"; grep -v "  $module\$" "$d/SHA256SUMS" > "$d/S" && mv "$d/S" "$d/SHA256SUMS"
d="$(fixture ghost)"; echo "$(printf '0%.0s' $(seq 64))  ghost.jar" >> "$d/SHA256SUMS"
d="$(fixture pre-0.7.0)"; rm "$d/$assembler"; resum "$d"

# Python's own file handler; each request's path and Authorization header (empty when absent) logged.
cat > "$WORK/serve.py" <<'PY'
import functools, http.server, sys
root, log, portfile = sys.argv[1:4]
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        with open(log, "a") as f:
            f.write(f"{self.path}\t{self.headers.get('Authorization', '')}\n")
        super().do_GET()
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=root))
with open(portfile, "w") as f:
    f.write(str(server.server_port))
server.serve_forever()
PY
python3 "$WORK/serve.py" "$SRV" "$LOG" "$WORK/port" &
SERVER_PID=$!
for _ in $(seq 1 50); do [[ -s "$WORK/port" ]] && break; sleep 0.1; done
[[ -s "$WORK/port" ]] || { echo "ERROR: the fixture server did not start" >&2; exit 1; }
URL="http://127.0.0.1:$(cat "$WORK/port")"

failures=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }
# stage <case> <profile> <source>: runs the copy, with tokens in its environment that must never be sent.
stage() {
  GH_TOKEN=never-sent GITHUB_TOKEN=never-sent PFAI_RELEASE_BASE_URL="$URL/$1" STAGE_DEST="$WORK/out-$1-$2/modules" \
    bash "$T/stage-from-release.sh" --profile "$2" "$3" > "$WORK/$1-$2.out" 2>&1
}
# refused <name> <case> <profile> <source> <message>: refused, saying <message>, and nothing staged or cached.
refused() {
  rm -rf "$T/.release"
  if stage "$2" "$3" "$4"; then fail "$1: staged"; return; fi
  if ! grep -qF -- "$5" "$WORK/$2-$3.out"; then fail "$1: refused, but not with '$5':"; sed 's/^/     /' "$WORK/$2-$3.out"; return; fi
  if [[ -e "$WORK/out-$2-$3/modules/MANIFEST" || -e "$T/.release/$VERSION" ]]; then fail "$1: refused, but left a stage or a cache behind"; return; fi
  pass "$1"
}

# A good release, both profiles: the jars the MANIFEST names (and the simulator for conformance), byte for byte.
for profile in conformance production; do
  rm -rf "$T/.release"
  if ! stage good "$profile" "$VERSION"; then fail "good release, $profile: refused"; sed 's/^/     /' "$WORK/good-$profile.out"; continue; fi
  out="$WORK/out-good-$profile"
  ok=1
  head -n 1 "$out/modules/MANIFEST" | grep -q "^MANIFEST/2 profile=$profile " || ok=0
  while read -r digest name; do
    [[ "$(pfai_sha256 "$out/modules/$name")" == "$digest" ]] || ok=0
  done < <(grep -E '^[0-9a-f]{64}  ' "$DIST/MANIFEST")
  cmp -s "$DIST/$assembler" "$out/assembler/war-assembler.jar" || ok=0
  if [[ "$profile" == conformance ]]; then
    cmp -s "$DIST/demo-only-ciba-sim.jar" "$out/modules/pf.plugins.ciba-sim.jar" || ok=0
    tail -n 2 "$out/modules/MANIFEST" | head -n 1 | grep -qx '\[plugins\]' || ok=0
  else
    # The production profile never stages the simulator, under either name.
    [[ ! -e "$out/modules/pf.plugins.ciba-sim.jar" && ! -e "$out/modules/demo-only-ciba-sim.jar" ]] || ok=0
    grep -q 'ciba-sim\|\[plugins\]' "$out/modules/MANIFEST" && ok=0
  fi
  jars="$(find "$out/modules" -name '*.jar' | wc -l | tr -d ' ')"
  want="$(grep -cE '^[0-9a-f]{64}  ' "$out/modules/MANIFEST")"
  [[ "$jars" == "$want" ]] || ok=0
  if [[ $ok == 1 ]]; then pass "good release, $profile: $jars jars and the assembler, as the release's MANIFEST says"; else fail "good release, $profile"; fi
done
# The cache alone: the fixture is gone, and the cached copy still verifies and stages.
mv "$SRV/good" "$SRV/good.gone"
if stage good conformance "$VERSION" && grep -q 'cached copy' "$WORK/good-conformance.out"; then pass "a cached release stages with nothing to fetch"; else fail "the cached release"; fi
mv "$SRV/good.gone" "$SRV/good"

refused "a tampered jar" tampered conformance "$VERSION" "does not match its SHA256SUMS"
refused "a jar missing from SHA256SUMS" unlisted conformance "$VERSION" "which its SHA256SUMS does not list"
refused "SHA256SUMS naming a missing file" ghost conformance "$VERSION" "could not fetch $URL/ghost/v$VERSION/ghost.jar, which SHA256SUMS lists"
refused "SHA256SUMS naming a missing file, as a directory" ghost conformance "$SRV/ghost/v$VERSION" "SHA256SUMS lists ghost.jar, which is not in"
cp -R "$SRV/good/v$VERSION" "$WORK/stray"; echo stray > "$WORK/stray/stray.jar"
refused "a stray file in a directory source" stray conformance "$WORK/stray" "stray.jar is not listed in SHA256SUMS"
refused "a release with no war assembler" pre-0.7.0 production "$VERSION" "The first release this script can stage is 0.7.0"
refused "an unknown profile" good staging "$VERSION" "--profile must be production or conformance, not 'staging'"

requests="$(wc -l < "$LOG" | tr -d ' ')"
if [[ "$requests" -gt 0 ]] && ! cut -f 2 "$LOG" | grep -q .; then pass "$requests requests, none with an Authorization header"; else fail "requests with an Authorization header (or none at all):"; sed 's/^/     /' "$LOG"; fi

if [[ $failures -gt 0 ]]; then echo "$failures case(s) failed"; exit 1; fi
echo "every case passed"
