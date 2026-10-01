#!/usr/bin/env bash
# The files a release publishes, copied from a built reactor into one directory: what release.yml's
# "assemble the release artifacts" step puts in dist/, and what Build's image job stages a release from to
# prove stage-from-release.sh makes the stage stage-modules.sh does.
#
#   tools/ci/assemble-dist.sh <outdir> <version>
#
# Run after `mvn package` (or verify, or install) and `build/pingfederate/stage-modules.sh --profile production`.
#   MODULES_DIR   the production stage to copy (default build/pingfederate/modules); a stage for any other
#                 profile is refused, because a release never ships the conformance stage
#
# Every copy is unconditional: a missing war or plugin jar fails the release instead of quietly shipping without
# it, which is how a consumer would first learn of it. Two files are build and test tools, not deployables:
#   war-assembler-<version>.jar  the war assembler the image build runs (stage-from-release.sh stages it into
#                                assembler/); never deployed
#   demo-only-ciba-sim.jar       plugins/ciba-sim's pf.plugins.ciba-sim.jar, renamed so that nothing globbing
#                                pf.plugins.* picks it up; stage-from-release.sh stages it under its real name for
#                                the conformance profile only, and it refuses every request outside
#                                OIDF_DEPLOYMENT_PROFILE=development
# It writes neither PROVENANCE.txt nor SHA256SUMS: release.yml writes both, from what is here.
set -euo pipefail
[[ $# -eq 2 ]] || { echo "usage: tools/ci/assemble-dist.sh <outdir> <version>" >&2; exit 2; }
VERSION="$2"
# Both directories as the caller named them, before the cd to the repository root.
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
if [[ -n "${MODULES_DIR:-}" ]]; then MODULES_DIR="$(cd "$MODULES_DIR" && pwd)"; fi
cd "$(dirname "$0")/../.."
MODULES_DIR="${MODULES_DIR:-build/pingfederate/modules}"
MANIFEST="$MODULES_DIR/MANIFEST"
[[ -f "$MANIFEST" ]] || { echo "ERROR: no $MANIFEST - run build/pingfederate/stage-modules.sh --profile production first" >&2; exit 1; }
case "$(head -n 1 "$MANIFEST")" in
  "MANIFEST/2 profile=production "*) ;;
  *) echo "ERROR: $MANIFEST is not a production stage ($(head -n 1 "$MANIFEST")); a release ships the production profile" >&2; exit 1 ;;
esac

cp "$MODULES_DIR"/*.jar "$MANIFEST" "$OUT/"
cp servlets/oidf-war/target/oidf.war "$OUT/"
cp plugins/rar-paz-plugin/target/pf.plugins.pf-rar-paz-plugin.jar "$OUT/"
cp plugins/instance-registry-datasource/target/pf.plugins.instance-registry-datasource.jar "$OUT/"
cp services/gm-api/servlet/target/gm-api.war "$OUT/"
# The preflight an operator runs on an env file before upgrading (docs/operator/preflight.md); never staged.
cp tools/preflight/target/oidf-preflight.jar "$OUT/"
cp "build/war-assembler/target/war-assembler-$VERSION.jar" "$OUT/"
cp plugins/ciba-sim/target/pf.plugins.ciba-sim.jar "$OUT/demo-only-ciba-sim.jar"
echo "assembled $(find "$OUT" -maxdepth 1 -type f | wc -l | tr -d ' ') files for $VERSION into $OUT"
