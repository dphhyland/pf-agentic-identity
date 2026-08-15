#!/usr/bin/env bash
# Stage the monorepo's module jars into deploy/pingfederate/modules/ for the Docker build.
# Run after `mvn -q -DskipTests package` at the repo root. These seven jars are the modular
# equivalent of the old monolith pf-oidf-modules.jar (same packages, superset of its classes):
# their external deps (jose4j, jackson, commons-logging) are already on PF's server classpath.
# agent-registry rides along because attestation-issuer's servlets import it (agent_id minting) —
# without it the issuance servlet fails at first use with NoClassDefFoundError. The device-bound
# libs (device-instance, app-attest) are NOT staged — App Attest verification lives in
# services/device-enrolment, not in the AS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DEST="$ROOT/deploy/pingfederate/modules"

JARS=(
  servlets/pf-integration/target/oidf.jar
  servlets/attestation-issuer/target/attestation-issuer-0.1.0.jar
  servlets/ssf/target/ssf-0.1.0.jar
  libs/oidf-jose/target/oidf-jose-0.1.0.jar
  libs/client-attestation/target/client-attestation-0.1.0.jar
  libs/openid-federation/target/openid-federation-0.1.0.jar
  libs/agent-registry/target/agent-registry-0.1.0.jar
)

mkdir -p "$DEST"
rm -f "$DEST"/*.jar
for j in "${JARS[@]}"; do
  [[ -f "$ROOT/$j" ]] || { echo "ERROR: $j not built — run 'mvn -q -DskipTests package' first" >&2; exit 1; }
  cp "$ROOT/$j" "$DEST/"
done
echo "staged $(ls "$DEST" | wc -l | tr -d ' ') jars into deploy/pingfederate/modules/:"
ls -la "$DEST"
