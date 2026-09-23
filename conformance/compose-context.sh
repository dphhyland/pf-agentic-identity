#!/usr/bin/env bash
# Compose the PingFederate image's build context.
#
# The image build is ../build/pingfederate/ (Dockerfile, war assembly, entrypoint, staged module jars);
# this directory owns what configures it: the archive export.sh produced and the cipher-list overlay.
# `docker build` (and a deploy tool such as `railway up`) want one directory, so this assembles
# .context/ (git-ignored) and prints its path.
#
# PF_AGENTIC_IDENTITY_HOME defaults to this repo. Point it at another checkout or worktree to build a
# branch's modules with this configuration.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CAP="${PF_AGENTIC_IDENTITY_HOME:-$(cd "$HERE/.." && pwd)}"
BUILD="$CAP/build/pingfederate"
[[ -f "$BUILD/Dockerfile" ]] || { echo "ERROR: no PF image build at $BUILD" >&2; exit 1; }
[[ -f "$BUILD/modules/MANIFEST" ]] || { echo "ERROR: no staged modules - run mvn package and $BUILD/stage-modules.sh" >&2; exit 1; }
for f in data.zip overlay/pf.jwk overlay/pingfederate-system-keys.xml; do
  [[ -f "$HERE/$f" ]] || { echo "ERROR: missing $f - run ./export.sh" >&2; exit 1; }
done

CTX="$HERE/.context"
rm -rf "$CTX"; mkdir -p "$CTX/overlay"
cp "$BUILD/Dockerfile" "$BUILD/assemble-pf-runtime-war.sh" "$BUILD/pf-entrypoint.sh" "$CTX/"
cp -R "$BUILD/modules" "$CTX/modules"
cp -R "$BUILD/overlay/config-store" "$CTX/overlay/config-store"
# This rig's own config-store files, laid over the image as well as carried in the archive - see
# config-store/com.pingidentity.crypto.SunJCEManager.xml for why it takes both.
cp "$HERE"/config-store/*.xml "$CTX/overlay/config-store/"
cp "$HERE/data.zip" "$CTX/"
cp "$HERE/overlay/pf.jwk" "$HERE/overlay/pingfederate-system-keys.xml" "$CTX/overlay/"
# No oidf-mock-attesters.json: this PF trusts no attester, and the Dockerfile treats the file as optional.

echo "composed $CTX from $CAP ($(ls "$CTX/modules"/*.jar | wc -l | tr -d ' ') module jars, $(cat "$CTX/modules/MANIFEST" | wc -l | tr -d ' ') manifest lines)" >&2
echo "$CTX"
