#!/usr/bin/env bash
# Exercises pf-entrypoint.sh's decisions with PingFederate stubbed out: the base image's bootstrap is
# replaced by a script that records its environment, umask and working directory, and each case boots
# from a fresh data directory. No licence, no PingFederate, a few seconds.
#
#   build/pingfederate/test-entrypoint.sh                  here: needs age, age-keygen, zip, unzip and
#                                                          sha256sum or shasum on the PATH
#   build/pingfederate/test-entrypoint.sh --image IMAGE    the same, inside IMAGE (built from this
#                                                          directory's Dockerfile, which installs age),
#                                                          with this directory's scripts mounted read-only
#
# Becomes a CI step in Phase 2 (plan item R-CI6). Exit status: 0 when every case passes.
#
# Each check is a bash condition in single quotes that `check` evals after the case has run, so it reads
# the case's results and not the values at the time the line was written - hence the directive:
# shellcheck disable=SC2016
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [[ "${1:-}" == --image ]]; then
  [[ -n "${2:-}" ]] || { echo "usage: test-entrypoint.sh --image IMAGE" >&2; exit 2; }
  exec docker run --rm -v "$HERE:/src:ro" --entrypoint bash "$2" /src/test-entrypoint.sh
fi
ENTRYPOINT="${ENTRYPOINT:-$HERE/pf-entrypoint.sh}"
for tool in age age-keygen zip unzip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool is required (or run with --image)" >&2; exit 2; }
done
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || { echo "ERROR: sha256sum or shasum is required" >&2; exit 2; }
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

WORK="$(mktemp -d)"
# The fixtures hold the identity by design, so they get a directory of their own, outside every tree the
# leak sweep below reads.
FIX="$(mktemp -d)"
trap 'rm -rf "$WORK" "$FIX"' EXIT
# physical DIR: DIR with its symlinks resolved and no trailing slash, so the paths find prints and the paths
# it is told to skip are spelled the same way (macOS: /tmp is /private/tmp, and TMPDIR ends in a slash).
physical() { (cd "$1" 2>/dev/null && pwd -P); }
WORK_P="$(physical "$WORK")"; FIX_P="$(physical "$FIX")"

# --- fixtures: a configArchive-shaped zip, an identity, its ciphertext (binary and armored), and a second identity ---
mkdir -p "$FIX/archive/config-store"
printf '{"keys":[{"kty":"oct","k":"not-a-real-master-key"}]}\n' > "$FIX/archive/pf.jwk"
printf '<system-keys/>\n' > "$FIX/archive/pingfederate-system-keys.xml"
printf '<config/>\n' > "$FIX/archive/config-store/example.xml"
( cd "$FIX/archive" && zip -q -r "$FIX/data.zip" pf.jwk pingfederate-system-keys.xml config-store )
( cd "$FIX" && zip -q "$FIX/stripped.zip" archive/config-store/example.xml )
age-keygen -o "$FIX/identity.txt" 2>/dev/null
age-keygen -o "$FIX/other-identity.txt" 2>/dev/null
IDENTITY="$(grep '^AGE-SECRET-KEY-1' "$FIX/identity.txt")"
OTHER_IDENTITY="$(grep '^AGE-SECRET-KEY-1' "$FIX/other-identity.txt")"
age -r "$(age-keygen -y "$FIX/identity.txt")" -o "$FIX/data.zip.age" "$FIX/data.zip"
age -a -r "$(age-keygen -y "$FIX/identity.txt")" -o "$FIX/data.zip.age.armored" "$FIX/data.zip"
SUM_AGE="$(sha256_of "$FIX/data.zip.age")"
SUM_ZIP="$(sha256_of "$FIX/data.zip")"

# --- one case: a fresh data directory, a stub bootstrap, a clean environment ---
CASE=""; DATA=""; DROP=""; OUT=""; RC=0; LOG=""
prepare() {
  CASE="$1"
  DATA="$WORK/$CASE/data"; DROP="$DATA/drop-in-deployer"; OUT="$WORK/$CASE/out"
  mkdir -p "$DROP" "$OUT" "$WORK/$CASE/opt"
  cat > "$WORK/$CASE/opt/bootstrap.sh" <<'STUB'
#!/bin/sh
pwd > "$STUB_OUT/cwd"
umask > "$STUB_OUT/umask"
env > "$STUB_OUT/env"
printf '%s\n' "$*" > "$STUB_OUT/args"
STUB
  chmod +x "$WORK/$CASE/opt/bootstrap.sh"
}
# run VAR=value ... : the entrypoint under `env -i`, so only what a case sets is in its environment.
run() {
  set +e
  env -i PATH="$PATH" HOME="$WORK" STUB_OUT="$OUT" PF_DATA_DIR="$DATA" PF_BOOTSTRAP="$WORK/$CASE/opt/bootstrap.sh" "$@" \
    sh "$ENTRYPOINT" start-server > "$OUT/stdout" 2> "$OUT/stderr"
  RC=$?
  set -e
  LOG="$(cat "$OUT/stderr")"
}

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); echo "  ok   $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; while IFS= read -r line; do echo "       | $line"; done <<< "$LOG"; }
check() { if eval "$2"; then ok "$CASE: $1"; else fail "$CASE: $1"; fi; }
booted()  { [[ $RC -eq 0 && -f "$OUT/env" ]]; }
refused() { [[ $RC -ne 0 && ! -f "$OUT/env" ]]; }
logged()  { [[ "$LOG" == *"$1"* ]]; }
env_lacks() { ! grep -q "^$1=" "$OUT/env"; }
env_has()   { grep -q "^$1=" "$OUT/env"; }
# identity_on_disk MARKER: is the inline identity in any file a run could have written - anything under the
# work directory, or a regular file newer than MARKER under a temp directory: the script's own TMPDIR, and
# /tmp, where a `mktemp` in the entrypoint would land (`run` gives it no TMPDIR)? The fixtures are skipped;
# they hold the identity by design. Only options busybox grep and find have, because the image's are
# busybox: a `--include` here once made busybox grep exit 2, and the negated check pass whatever the
# entrypoint had written. The control checks below plant the identity to prove the sweep can fail.
identity_on_disk() {
  grep -rqsF "$IDENTITY" "$WORK" && return 0
  local dir found
  for dir in "${TMPDIR:-/tmp}" /tmp; do
    dir="$(physical "$dir")" || continue
    found="$(find "$dir" -type f -newer "$1" ! -path "$FIX_P/*" ! -path "$WORK_P/*" \
               -exec grep -lsF "$IDENTITY" {} + 2>/dev/null || true)"
    [[ -n "$found" ]] && return 0
  done
  return 1
}

echo "pf-entrypoint.sh: $ENTRYPOINT"

prepare no-archive
run
check "boots with nothing to import" 'booted && logged "no config archive present"'
check "hands over from the bootstrap directory with the arguments" '[[ "$(cat "$OUT/cwd")" == "$WORK/$CASE/opt" && "$(cat "$OUT/args")" == start-server ]]'
check "PingFederate inherits umask 077" '[[ "$(cat "$OUT/umask")" == 0077 ]]'

prepare plaintext-default-profile
cp "$FIX/data.zip" "$DROP/"
run
check "a plaintext archive is refused when the profile is unset" 'refused && logged "refused when OIDF_DEPLOYMENT_PROFILE is production"'
check "and the keys were not extracted" '[[ ! -f "$DATA/pf.jwk" ]]'

prepare plaintext-production
cp "$FIX/data.zip" "$DROP/"
run OIDF_DEPLOYMENT_PROFILE=production
check "a plaintext archive is refused when the profile says production" 'refused'

prepare plaintext-unknown-profile
cp "$FIX/data.zip" "$DROP/"
run OIDF_DEPLOYMENT_PROFILE=staging
check "an unknown profile counts as production" 'refused && logged "it is '"'"'staging'"'"'"'

prepare plaintext-development
cp "$FIX/data.zip" "$DROP/"
run OIDF_DEPLOYMENT_PROFILE=development
check "development boots from a plaintext archive, with the warning" 'booted && logged "WARNING: booting from a PLAINTEXT archive"'
check "the keys come out of the archive, private to this user" '[[ -f "$DATA/pf.jwk" && "$(mode_of "$DATA/pf.jwk")" == 600 && "$(mode_of "$DATA/pingfederate-system-keys.xml")" == 600 ]]'
check "the archive stays for the drop-in deployer" '[[ -f "$DROP/data.zip" && "$(mode_of "$DROP/data.zip")" == 600 ]]'

prepare encrypted-no-key
cp "$FIX/data.zip.age" "$DROP/"
run
check "an encrypted archive with no identity is refused" 'refused && logged "neither PF_ARCHIVE_AGE_KEY_FILE nor PF_ARCHIVE_AGE_KEY is set"'
check "nothing was decrypted" '[[ ! -f "$DROP/data.zip" && -f "$DROP/data.zip.age" ]]'

prepare encrypted-inline-key
cp "$FIX/data.zip.age" "$DROP/"
# The sweep looks for files newer than this marker; the second between them is for a filesystem whose
# timestamps are whole seconds.
MARK="$WORK/$CASE/marker"; touch "$MARK"; sleep 1
run PF_ARCHIVE_AGE_KEY="$IDENTITY"
check "an inline identity decrypts the archive, on the default profile" 'booted && logged "config archive ready"'
check "the decrypted archive and the keys are in place and private" '[[ -f "$DROP/data.zip" && "$(mode_of "$DROP/data.zip")" == 600 && "$(mode_of "$DATA/pf.jwk")" == 600 && -f "$DATA/pingfederate-system-keys.xml" ]]'
check "the ciphertext the image carried is gone" '[[ ! -f "$DROP/data.zip.age" ]]'
check "PingFederate does not see the identity" 'env_lacks PF_ARCHIVE_AGE_KEY && env_lacks PF_ARCHIVE_AGE_KEY_FILE'
check "the identity is in no file: not under the work directory, not written to a temp directory" '! identity_on_disk "$MARK"'

# A sweep that cannot fail proves nothing (this one's first version could not, under busybox grep): plant
# the identity where a leak would land, in both places, and make sure the same predicate finds it.
CASE=control-planted-identity; mkdir -p "$WORK/$CASE"
printf '%s\n' "$IDENTITY" > "$WORK/$CASE/leak"
check "the sweep finds an identity planted under the work directory" 'identity_on_disk "$MARK"'
rm -f "$WORK/$CASE/leak"
LEAK="$(mktemp "${TMPDIR:-/tmp}/pf-entrypoint-test.XXXXXX")"
printf '%s\n' "$IDENTITY" > "$LEAK"
check "and one planted in the temp directory" 'identity_on_disk "$MARK"'
rm -f "$LEAK"
check "and nothing once both are removed" '! identity_on_disk "$MARK"'

prepare encrypted-armored
cp "$FIX/data.zip.age.armored" "$DROP/data.zip.age"
run PF_ARCHIVE_AGE_KEY="$IDENTITY"
check "an archive armored with age -a is encrypted, not plaintext: it boots on the default profile" 'booted && logged "decrypting" && [[ -f "$DROP/data.zip" && -f "$DATA/pf.jwk" ]]'

prepare encrypted-key-file
cp "$FIX/data.zip.age" "$DROP/"
cp "$FIX/identity.txt" "$WORK/$CASE/identity.txt"
run PF_ARCHIVE_AGE_KEY_FILE="$WORK/$CASE/identity.txt"
check "an identity file decrypts the archive" 'booted && logged "config archive ready" && [[ -f "$DROP/data.zip" ]]'
check "the operator's file is read, not deleted" '[[ -f "$WORK/$CASE/identity.txt" ]]'
check "PingFederate sees neither variable" 'env_lacks PF_ARCHIVE_AGE_KEY && env_lacks PF_ARCHIVE_AGE_KEY_FILE'

prepare encrypted-file-preferred
cp "$FIX/data.zip.age" "$DROP/"
cp "$FIX/identity.txt" "$WORK/$CASE/identity.txt"
run PF_ARCHIVE_AGE_KEY_FILE="$WORK/$CASE/identity.txt" PF_ARCHIVE_AGE_KEY="$OTHER_IDENTITY"
check "the file wins over the variable (the variable holds the wrong key)" 'booted && [[ -f "$DROP/data.zip" ]]'
check "and both are gone from the environment" 'env_lacks PF_ARCHIVE_AGE_KEY && env_lacks PF_ARCHIVE_AGE_KEY_FILE'

prepare encrypted-missing-key-file
cp "$FIX/data.zip.age" "$DROP/"
run PF_ARCHIVE_AGE_KEY_FILE="$WORK/$CASE/absent.txt" PF_ARCHIVE_AGE_KEY="$IDENTITY"
check "a named identity file that does not exist is a refusal, not a fall-through to the variable" 'refused && logged "does not exist"'

prepare encrypted-wrong-key
cp "$FIX/data.zip.age" "$DROP/"
run PF_ARCHIVE_AGE_KEY="$OTHER_IDENTITY"
check "a wrong identity is refused" 'refused && logged "could not decrypt"'
check "and leaves no plaintext behind" '[[ ! -f "$DROP/data.zip" && ! -f "$DATA/pf.jwk" ]]'

prepare integrity-ok
cp "$FIX/data.zip.age" "$DROP/"
run PF_ARCHIVE_AGE_KEY="$IDENTITY" PF_ARCHIVE_SHA256="$(printf '%s' "$SUM_AGE" | tr 'a-f' 'A-F')"
check "a matching PF_ARCHIVE_SHA256 (any case) passes" 'booted && logged "archive integrity"'

prepare integrity-mismatch
cp "$FIX/data.zip.age" "$DROP/"
run PF_ARCHIVE_AGE_KEY="$IDENTITY" PF_ARCHIVE_SHA256="$SUM_ZIP"
check "a mismatching PF_ARCHIVE_SHA256 stops the boot" 'refused && logged "does not match PF_ARCHIVE_SHA256"'
check "before anything was decrypted" '[[ ! -f "$DROP/data.zip" && -f "$DROP/data.zip.age" ]]'

prepare integrity-malformed
cp "$FIX/data.zip.age" "$DROP/"
run PF_ARCHIVE_AGE_KEY="$IDENTITY" PF_ARCHIVE_SHA256="abc123"
check "a PF_ARCHIVE_SHA256 that is not a digest is refused" 'refused && logged "PF_ARCHIVE_SHA256 is not a hex SHA-256"'

prepare integrity-plaintext
cp "$FIX/data.zip" "$DROP/"
run OIDF_DEPLOYMENT_PROFILE=development PF_ARCHIVE_SHA256="$SUM_AGE"
check "the plaintext path is checked too" 'refused && logged "does not match PF_ARCHIVE_SHA256"'

prepare archive-file-encrypted
cp "$FIX/data.zip.age" "$WORK/$CASE/mounted.age"
run PF_ARCHIVE_FILE="$WORK/$CASE/mounted.age" PF_ARCHIVE_AGE_KEY="$IDENTITY" PF_ARCHIVE_SHA256="$SUM_AGE"
check "PF_ARCHIVE_FILE selects a mounted encrypted archive" 'booted && logged "decrypting $WORK/$CASE/mounted.age" && [[ -f "$DROP/data.zip" ]]'
check "the mounted file is left alone" '[[ -f "$WORK/$CASE/mounted.age" ]]'

prepare archive-file-over-baked
cp "$FIX/data.zip.age" "$DROP/"
age -r "$(age-keygen -y "$FIX/other-identity.txt")" -o "$WORK/$CASE/mounted.age" "$FIX/data.zip"
run PF_ARCHIVE_FILE="$WORK/$CASE/mounted.age" PF_ARCHIVE_AGE_KEY="$OTHER_IDENTITY"
check "PF_ARCHIVE_FILE wins over the archive baked into the image" 'booted && logged "decrypting $WORK/$CASE/mounted.age"'
check "and the baked ciphertext, which was not used, is left where it was" '[[ -f "$DROP/data.zip.age" ]]'

prepare archive-file-plaintext-development
cp "$FIX/data.zip" "$WORK/$CASE/mounted.zip"
run PF_ARCHIVE_FILE="$WORK/$CASE/mounted.zip" OIDF_DEPLOYMENT_PROFILE=development
check "a mounted plaintext archive is copied into place on a rig" 'booted && [[ -f "$DROP/data.zip" && -f "$DATA/pf.jwk" ]]'

prepare archive-file-plaintext-production
cp "$FIX/data.zip" "$WORK/$CASE/mounted.zip"
run PF_ARCHIVE_FILE="$WORK/$CASE/mounted.zip"
check "and refused in production" 'refused && [[ ! -f "$DROP/data.zip" ]]'

prepare archive-file-missing
run PF_ARCHIVE_FILE="$WORK/$CASE/absent.zip" OIDF_DEPLOYMENT_PROFILE=development
check "a PF_ARCHIVE_FILE that does not exist is a refusal, not a boot with nothing" 'refused && logged "is not a file"'

prepare not-a-config-archive
age -r "$(age-keygen -y "$FIX/identity.txt")" -o "$DROP/data.zip.age" "$FIX/stripped.zip"
run PF_ARCHIVE_AGE_KEY="$IDENTITY"
check "an archive without pf.jwk is refused" 'refused && logged "pf.jwk is not in the archive"'

echo
echo "test-entrypoint: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
