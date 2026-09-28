#!/usr/bin/env bash
# Stage the reactor's module jars into build/pingfederate/modules/ for the Docker build, and write the
# MANIFEST that assemble-pf-runtime-war.sh checks the directory against.
#
#   stage-modules.sh [--profile production|conformance]
#
# Run after `mvn -q -DskipTests package` at the repo root. The production profile (the default) stages
# the jars ENTRIES lists below - the modular equivalent of the old monolith pf-oidf-modules.jar (same
# packages, superset of its classes) - and the MANIFEST it writes names each one; prose elsewhere points at
# the MANIFEST rather than counting them. The conformance profile stages one more, the CIBA simulator,
# which exists for the OpenID conformance suite's FAPI-CIBA plan and must never reach a production image -
# the assembler refuses a stage whose profile is not the one the image is built for. Their external deps
# (jose4j, jackson, commons-logging) are already on PF's server classpath.
# platform and platform-pf ride along because oidf-jose depends on platform and pf-integration on
# platform-pf (plan item F-1), so every staged module can reach them. platform is JDK-only and platform-pf
# needs nothing PF does not ship; a plugin that uses platform shades and relocates its own copy, as the RAR
# plugin does rar-model, so the copies never meet (docs/development/classloaders.md).
# rar-model rides along because client-attestation's token gate and attestation-issuer's mint ask it
# (plan item S1b) - without it the attestation filter refuses to start and the issuance criterion and
# servlet fail at first use with NoClassDefFoundError. It is JDK-only, so it adds no library to PF's
# classpath; the RAR plugin shades and relocates its own copy, so the two never meet.
# agent-registry rides along because attestation-issuer's servlets import it (agent_id minting) —
# without it the issuance servlet fails at first use with NoClassDefFoundError. device-instance rides
# along too: servlets/ssf's InstanceRegistryReceiverHandler imports it to turn inbound CAEP signals
# into agent-instance registry changes (CaepSignalApplier, IomInstanceRegistry) — without it the SSF
# servlets fail at first use the same way, even when receiverInstanceRegistry is off. It is a pure
# library (no App Attest, no HTTP, no PingFederate SDK), unlike app-attest, which stays out: App Attest
# verification lives in services/device-enrolment, not in the AS.
# shared-signals rides along because servlets/ssf is built on it (plan item X-A14): the SET model, minting,
# verification and subjects live there, so without it the SSF servlets fail with NoClassDefFoundError.
set -euo pipefail
PROFILE=production
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) [[ $# -ge 2 ]] || { echo "ERROR: --profile needs a value" >&2; exit 2; }; PROFILE="$2"; shift 2 ;;
    --profile=*) PROFILE="${1#--profile=}"; shift ;;
    *) echo "ERROR: unknown argument '$1' - usage: stage-modules.sh [--profile production|conformance]" >&2; exit 2 ;;
  esac
done
case "$PROFILE" in
  production | conformance) ;;
  *) echo "ERROR: --profile must be production or conformance, not '$PROFILE'" >&2; exit 2 ;;
esac
# The reactor root is two levels up (build/pingfederate/ -> repo root). PF_AGENTIC_IDENTITY_HOME
# lets a consuming repo run this script from its own checkout against a sibling clone of this one.
ROOT="${PF_AGENTIC_IDENTITY_HOME:-$(cd "$(dirname "$0")/../.." && pwd)}"
[[ -f "$ROOT/pom.xml" ]] || { echo "ERROR: $ROOT is not a pf-agentic-identity checkout (no pom.xml) - set PF_AGENTIC_IDENTITY_HOME" >&2; exit 1; }
DEST="${STAGE_DEST:-$ROOT/build/pingfederate/modules}"

# The version comes from the BOM, not from eight hardcoded filenames. Those filenames pinned 0.1.0,
# so the first version bump broke staging with "attestation-issuer-0.1.0.jar not built" - the jars were
# fine, the list was stale. Read it once and let every entry follow.
VERSION="$(sed -n 's|.*<version.internal>\(.*\)</version.internal>.*|\1|p' "$ROOT/bom/pom.xml" | head -1)"
[[ -n "$VERSION" ]] || { echo "ERROR: could not read version.internal from $ROOT/bom/pom.xml" >&2; exit 1; }

# "<section> <path>": the section is the module group the MANIFEST lists the jar under.
ENTRIES=(
  "servlets servlets/pf-integration/target/oidf.jar"
  "servlets servlets/attestation-issuer/target/attestation-issuer-$VERSION.jar"
  "servlets servlets/ssf/target/ssf-$VERSION.jar"
  "libs libs/platform/target/platform-$VERSION.jar"
  "libs libs/platform-pf/target/platform-pf-$VERSION.jar"
  "libs libs/oidf-jose/target/oidf-jose-$VERSION.jar"
  "libs libs/rar-model/target/rar-model-$VERSION.jar"
  "libs libs/client-attestation/target/client-attestation-$VERSION.jar"
  "libs libs/openid-federation/target/openid-federation-$VERSION.jar"
  "libs libs/agent-registry/target/agent-registry-$VERSION.jar"
  "libs libs/device-instance/target/device-instance-$VERSION.jar"
  "libs libs/shared-signals/target/shared-signals-$VERSION.jar"
)
if [[ "$PROFILE" == conformance ]]; then
  # The CIBA simulator: an OOBAuthPlugin plus its decision servlet in one jar. The Dockerfile puts every
  # staged jar in BOTH places, which is what this one needs - loose in deploy/ (PF-INF discovery, the
  # pf.plugins. prefix) for the plugin, merged into the war for the servlet. It is an approval oracle
  # keyed by nothing but an auth_req_id, so it is staged only here, and even then runs only where
  # OIDF_CIBA_SIM_ENABLED=true, OIDF_DEPLOYMENT_PROFILE=development and OIDF_CIBA_SIM_DIR passes its
  # checks; see plugins/ciba-sim/README.md.
  ENTRIES+=("plugins plugins/ciba-sim/target/pf.plugins.ciba-sim.jar")
fi

# The same digest the assembler and the release workflow compute; GNU and busybox have sha256sum, macOS
# has shasum.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

mkdir -p "$DEST"
rm -f "$DEST"/*.jar "$DEST/MANIFEST"
for entry in "${ENTRIES[@]}"; do
  j="${entry#* }"
  [[ -f "$ROOT/$j" ]] || { echo "ERROR: $j not built — run 'mvn -q -DskipTests package' first" >&2; exit 1; }
  cp "$ROOT/$j" "$DEST/"
done
# A manifest of exactly what this run staged. assemble-pf-runtime-war.sh refuses to build from a
# modules/ directory that does not match it — because the failure mode otherwise is silent and
# expensive: a hand-populated or stale modules/ assembles a war that boots fine and then throws
# NoClassDefFoundError at the first request that touches the missing module. That has now happened
# twice (agent-registry, then device-instance), each time discovered from a 500 in staging rather
# than from the build.
#
# MANIFEST v2: one header line naming the format, the profile, the build time and the commit; then a
# [section] per module group, and one "<sha256>  <file>" line per jar - sha256sum's own format, so
# `grep -E '^[0-9a-f]{64}  ' MANIFEST | sha256sum -c` checks the directory by hand. The profile is
# what the assembler compares with the image's; the digests catch a jar rebuilt or swapped after
# staging, which the v1 list of bare filenames could not.
commit="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
if [[ "$commit" != unknown && -n "$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
  commit="$commit-dirty"
fi
{
  echo "MANIFEST/2 profile=$PROFILE built=$(date -u +%Y-%m-%dT%H:%M:%SZ) commit=$commit"
  section=""
  for entry in "${ENTRIES[@]}"; do
    s="${entry%% *}"; b="$(basename "${entry#* }")"
    if [[ "$s" != "$section" ]]; then echo "[$s]"; section="$s"; fi
    echo "$(sha256_of "$DEST/$b")  $b"
  done
} > "$DEST/MANIFEST"

echo "staged ${#ENTRIES[@]} jars ($PROFILE profile) into $DEST:"
cat "$DEST/MANIFEST"

# The war assembler assemble-pf-runtime-war.sh runs (build/war-assembler), into assembler/ beside modules/ -
# so a context composed from STAGE_DEST's parent carries it too. It is a build tool, not a module, so it is
# not in ENTRIES or the MANIFEST: it never goes into the war or server/default/deploy.
ASSEMBLER_JAR="$ROOT/build/war-assembler/target/war-assembler-$VERSION.jar"
ASSEMBLER_DEST="$(dirname "$DEST")/assembler"
[[ -f "$ASSEMBLER_JAR" ]] || { echo "ERROR: build/war-assembler/target/war-assembler-$VERSION.jar not built - run 'mvn -q -DskipTests package' first" >&2; exit 1; }
mkdir -p "$ASSEMBLER_DEST"
cp "$ASSEMBLER_JAR" "$ASSEMBLER_DEST/war-assembler.jar"
echo "staged the war assembler into $ASSEMBLER_DEST/war-assembler.jar"
