#!/usr/bin/env bash
# Start the LOCAL PingFederate that terraform/ is applied to and that export.sh exports from.
#
# It is the stock 13.0.3 image the rig's own image is built FROM, not the rig's image: authoring needs
# an admin API and an empty server, and the rig's image imports an archive at boot and would overwrite
# whatever terraform had applied the next time it restarted.
#
#   PF_AUTHOR_ENV   a KEY=VALUE file holding PING_IDENTITY_PASSWORD - the admin password this server is
#                   created with. Generate one (umask 177; never commit it) and keep using it: apply.sh
#                   and export.sh read the same file. It becomes the archive's admin password.
#   ~/.pingidentity/config  the DevOps user and key the image fetches its evaluation licence with
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${PF_AUTHOR_ENV:?set PF_AUTHOR_ENV to a KEY=VALUE file holding PING_IDENTITY_PASSWORD}"
NAME="${PF_AUTHOR_NAME:-pf-conformance-author}"
PING_CONFIG="${PING_DEVOPS_CONFIG:-$HOME/.pingidentity/config}"
IMAGE="pingidentity/pingfederate:13.1.3-alpine_3.24.1-al21-latest"   # keep in step with the rig's FROM
ADMIN_PORT="${PF_AUTHOR_ADMIN_PORT:-19999}"; RUNTIME_PORT="${PF_AUTHOR_RUNTIME_PORT:-19031}"

docker rm -f "$NAME" >/dev/null 2>&1 || true
# CREATE_INITIAL_ADMIN_USER: the image defaults it to false and then never accepts the licence
# agreement or creates the administrator, and every admin API call answers 403
# license_agreement_not_accepted for as long as you care to wait.
docker create --name "$NAME" \
  --env-file "$PING_CONFIG" --env-file "$PF_AUTHOR_ENV" \
  -e PING_IDENTITY_ACCEPT_EULA=YES -e CREATE_INITIAL_ADMIN_USER=true \
  -p "127.0.0.1:$RUNTIME_PORT:9031" -p "127.0.0.1:$ADMIN_PORT:9999" "$IMAGE" >/dev/null
# Staged BEFORE first start so the server comes up with it and the exported archive carries it; see
# config-store/com.pingidentity.crypto.SunJCEManager.xml for why the archive has to.
# (docker cp will not create missing parents, and the stock image's /opt/in is empty - hence the tree.)
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/instance/server/default/data/config-store" "$STAGE/instance/server/default/deploy"
cp "$HERE"/config-store/*.xml "$STAGE/instance/server/default/data/config-store/"
# The CIBA simulator plugin, so terraform/ciba.tf can create an instance of it: PingFederate lists a
# plugin descriptor only for a jar in its deploy directory. Built by the reactor (up.sh builds before
# it authors); refused rather than skipped, because an archive authored without it has no CIBA and the
# first sign would be the FAPI-CIBA plan failing on every module.
PLUGIN="${PF_AGENTIC_IDENTITY_HOME:-$HERE/..}/plugins/ciba-sim/target/pf.plugins.ciba-sim.jar"
[[ -f "$PLUGIN" ]] || { echo "ERROR: $PLUGIN not built - run 'mvn -q -DskipTests package' at the repo root first" >&2; exit 1; }
cp "$PLUGIN" "$STAGE/instance/server/default/deploy/"
docker cp "$STAGE/instance" "$NAME:/opt/in/"
docker start "$NAME" >/dev/null

PW="$(sed -n 's/^PING_IDENTITY_PASSWORD=//p' "$PF_AUTHOR_ENV")"
for _ in $(seq 1 60); do
  code="$(curl -sk --max-time 8 -u "administrator:$PW" -H 'X-XSRF-Header: PingFederate' -o /dev/null \
    -w '%{http_code}' "https://127.0.0.1:$ADMIN_PORT/pf-admin-api/v1/version" || true)"
  [[ "$code" == "200" ]] && { echo "authoring PingFederate ready: admin https://localhost:$ADMIN_PORT, runtime https://localhost:$RUNTIME_PORT"; exit 0; }
  sleep 5
done
echo "ERROR: admin API never answered 200 (last: $code). docker logs $NAME" >&2; exit 1
