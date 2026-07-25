#!/usr/bin/env bash
# Merge the monorepo's module jars into ONE pf-oidf-modules.jar — the exact shape the PF image build
# (deploy/pingfederate/Dockerfile) expects. The legacy pf-oidf-modules repo shipped a single jar of
# com/pingidentity/ps/oidf classes; this reproduces it from the canonical monorepo build, so the demo
# image carries the new discovery servlet + GKE evidence adapter.
#
# Run `mvn -q -DskipTests package` at the repo root first.
# Usage: ./build-module-jar.sh [output-jar]   (default: ../../pingfederate/pf-oidf-modules.jar)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="${1:-$REPO_ROOT/deploy/pingfederate/pf-oidf-modules.jar}"

# Guard: merging stale module jars silently ships old code (the merged jar looks fine, but classes
# added since the last `mvn package` are simply absent). Rebuild unless SKIP_BUILD=1.
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "==> mvn package (set SKIP_BUILD=1 to skip)"
  ( cd "$REPO_ROOT" && mvn -q -o -B -DskipTests package )
fi

JARS=(
  "$REPO_ROOT/libs/oidf-jose/target/oidf-jose-0.1.0.jar"
  "$REPO_ROOT/libs/client-attestation/target/client-attestation-0.1.0.jar"
  "$REPO_ROOT/libs/openid-federation/target/openid-federation-0.1.0.jar"
  "$REPO_ROOT/servlets/pf-integration/target/oidf.jar"
  "$REPO_ROOT/servlets/attestation-issuer/target/attestation-issuer-0.1.0.jar"
  "$REPO_ROOT/servlets/ssf/target/ssf-0.1.0.jar"
)

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
for jar in "${JARS[@]}"; do
  [ -f "$jar" ] || { echo "missing $jar — run 'mvn -q -DskipTests package' at the repo root" >&2; exit 1; }
  unzip -oq "$jar" -d "$work" -x "META-INF/*"
done
mkdir -p "$(dirname "$OUT")"
( cd "$work" && zip -qr - . ) > "$OUT"
echo "wrote $OUT ($(unzip -l "$OUT" | grep -c '\.class$') classes)"
