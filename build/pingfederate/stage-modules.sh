#!/usr/bin/env bash
# Stage the reactor's module jars into build/pingfederate/modules/ for the Docker build.
# Run after `mvn -q -DskipTests package` at the repo root. These seven jars are the modular
# equivalent of the old monolith pf-oidf-modules.jar (same packages, superset of its classes):
# their external deps (jose4j, jackson, commons-logging) are already on PF's server classpath.
# agent-registry rides along because attestation-issuer's servlets import it (agent_id minting) —
# without it the issuance servlet fails at first use with NoClassDefFoundError. device-instance rides
# along too: servlets/ssf's InstanceRegistryReceiverHandler imports it to turn inbound CAEP signals
# into agent-instance registry changes (CaepSignalApplier, IomInstanceRegistry) — without it the SSF
# servlets fail at first use the same way, even when receiverInstanceRegistry is off. It is a pure
# library (no App Attest, no HTTP, no PingFederate SDK), unlike app-attest, which stays out: App Attest
# verification lives in services/device-enrolment, not in the AS.
set -euo pipefail
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

JARS=(
  servlets/pf-integration/target/oidf.jar
  "servlets/attestation-issuer/target/attestation-issuer-$VERSION.jar"
  "servlets/ssf/target/ssf-$VERSION.jar"
  "libs/oidf-jose/target/oidf-jose-$VERSION.jar"
  "libs/client-attestation/target/client-attestation-$VERSION.jar"
  "libs/openid-federation/target/openid-federation-$VERSION.jar"
  "libs/agent-registry/target/agent-registry-$VERSION.jar"
  "libs/device-instance/target/device-instance-$VERSION.jar"
)

mkdir -p "$DEST"
rm -f "$DEST"/*.jar
for j in "${JARS[@]}"; do
  [[ -f "$ROOT/$j" ]] || { echo "ERROR: $j not built — run 'mvn -q -DskipTests package' first" >&2; exit 1; }
  cp "$ROOT/$j" "$DEST/"
done
# A manifest of exactly what this run staged. assemble-pf-runtime-war.sh refuses to build from a
# modules/ directory that does not match it — because the failure mode otherwise is silent and
# expensive: a hand-populated or stale modules/ assembles a war that boots fine and then throws
# NoClassDefFoundError at the first request that touches the missing module. That has now happened
# twice (agent-registry, then device-instance), each time discovered from a 500 in staging rather
# than from the build.
: > "$DEST/MANIFEST"
for j in "${JARS[@]}"; do basename "$j" >> "$DEST/MANIFEST"; done

echo "staged $(ls "$DEST"/*.jar | wc -l | tr -d ' ') jars into $DEST:"
ls -la "$DEST"
