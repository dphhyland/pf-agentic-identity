#!/usr/bin/env bash
# Clone, run this, and have a PingFederate with every module in it answering on https://localhost:9031.
#
# Nothing here is a deploy. It is the one-machine version of what a conformance run or a demo needs:
#
#   1. gen-keys.sh          the suite clients' key pairs and two generated secrets   (git-ignored)
#   2. author.sh            a stock PF 13.0.3 with an admin API, on localhost:29999
#   3. apply.sh apply       terraform/ -> that server: OAuth server, tokens, clients, login form
#   4. export.sh            its realised config as data.zip - PF's own saved state    (git-ignored)
#   5. mvn package + stage  the module jars from this repo (run FIRST: author.sh needs the CIBA plugin)
#   6. compose-context.sh   the image build context: this repo's Dockerfile + that archive
#   7. docker compose up    the image, built and running, with vars.env and your licence details
#
# You supply ONE thing: licence details. The image bakes no licence; the base image fetches an
# evaluation licence at boot with PING_IDENTITY_DEVOPS_USER and PING_IDENTITY_DEVOPS_KEY, read from
# $PING_DEVOPS_CONFIG (default ~/.pingidentity/config, a KEY=VALUE file). Nothing licensed and no key
# is ever written under this directory in a form git would take.
#
#   PF_PORT_HTTPS / PF_PORT_HTTP / PF_PORT_ADMIN
#                   host ports for PF's 9031 / 9080 / 9999 (defaults the same), when another PF has them.
#   PF_BASE_URL     the origin PF advertises as its issuer. Default https://localhost:$PF_PORT_HTTPS,
#                   which is what a suite on this machine reaches. For a PF on a public address, set it
#                   to that origin - it is baked into the archive at step 3.
#   SKIP_AUTHOR=1   reuse an existing data.zip (steps 1-4 skipped); rebuild the image only.
#   SKIP_BUILD=1    reuse the staged module jars (step 5 skipped).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
export PF_AGENTIC_IDENTITY_HOME="$REPO"
# The authoring container: named and ported for this repo, so it never collides with another rig's.
export PF_AUTHOR_NAME="${PF_AUTHOR_NAME:-pf-agentic-identity-author}"
export PF_AUTHOR_ADMIN_PORT="${PF_AUTHOR_ADMIN_PORT:-29999}" PF_AUTHOR_RUNTIME_PORT="${PF_AUTHOR_RUNTIME_PORT:-29031}"
export PF_ADMIN_HOST="https://localhost:$PF_AUTHOR_ADMIN_PORT"
export PF_PORT_HTTPS="${PF_PORT_HTTPS:-9031}" PF_PORT_HTTP="${PF_PORT_HTTP:-9080}" PF_PORT_ADMIN="${PF_PORT_ADMIN:-9999}"
export PF_BASE_URL="${PF_BASE_URL:-https://localhost:$PF_PORT_HTTPS}"
LOCAL="https://localhost:$PF_PORT_HTTPS"
export TF_VAR_pf_base_url="$PF_BASE_URL"

PING_CONFIG="${PING_DEVOPS_CONFIG:-$HOME/.pingidentity/config}"
[[ -f "$PING_CONFIG" ]] || {
  echo "ERROR: no licence details at $PING_CONFIG." >&2
  echo "       Create a KEY=VALUE file with PING_IDENTITY_DEVOPS_USER and PING_IDENTITY_DEVOPS_KEY (your" >&2
  echo "       Ping DevOps credentials), or point PING_DEVOPS_CONFIG at one. See README.md." >&2
  exit 1; }
for tool in docker terraform mvn node curl unzip; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool is required" >&2; exit 1; }
done

# The authoring PF's admin password: generated once, kept git-ignored, reused so apply/export agree.
export PF_AUTHOR_ENV="${PF_AUTHOR_ENV:-$HERE/.author.env}"
if [[ ! -f "$PF_AUTHOR_ENV" ]]; then
  ( umask 177; printf 'PING_IDENTITY_PASSWORD=%s\n' "$(openssl rand -base64 30 | tr -d '/+=')Aa1" > "$PF_AUTHOR_ENV" )
  echo "generated $PF_AUTHOR_ENV (the authoring PF's admin password; git-ignored)"
fi

# Build first: author.sh stages plugins/ciba-sim into the authoring server, because terraform/ciba.tf
# can only instantiate a plugin PingFederate can see.
if [[ "${SKIP_BUILD:-0}" != 1 || ! -f "$REPO/build/pingfederate/modules/MANIFEST" ]]; then
  ( cd "$REPO" && mvn -q -DskipTests package && build/pingfederate/stage-modules.sh )
fi

if [[ "${SKIP_AUTHOR:-0}" != 1 ]]; then
  "$HERE/gen-keys.sh"
  "$HERE/author.sh"
  "$HERE/apply.sh" apply -auto-approve
  "$HERE/export.sh"
  docker rm -f "$PF_AUTHOR_NAME" >/dev/null 2>&1 || true
else
  [[ -f "$HERE/data.zip" ]] || { echo "ERROR: SKIP_AUTHOR=1 but no data.zip - run without it first" >&2; exit 1; }
fi

CTX="$("$HERE/compose-context.sh")"

# The running PF's environment: vars.env with the issuer substituted on the lines that carry it (the
# introspection endpoint is the container's own loopback and stays), plus the one generated secret the
# servlet needs (its other half is in the archive). Rendered into the git-ignored context.
sed -E "/^(OIDF_SSF_ISSUER|OIDF_FEDERATION_[A-Z_]+)=/ s#https://localhost:9031#$PF_BASE_URL#" "$HERE/vars.env" > "$CTX/vars.env"
sed -n 's/^TF_VAR_ssf_introspection_client_secret=/OIDF_SSF_INTROSPECTION_CLIENT_SECRET=/p' "$HERE/secrets.env" >> "$CTX/vars.env"
chmod 600 "$CTX/vars.env"

( cd "$HERE" && PING_DEVOPS_CONFIG="$PING_CONFIG" docker compose up -d --build )

echo "waiting for PingFederate (licence fetch + archive import take a minute or two)..."
for _ in $(seq 1 60); do
  if curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$LOCAL/.well-known/openid-configuration" | grep -q 200; then
    echo
    echo "PingFederate is up (issuer $PF_BASE_URL):"
    echo "  OAuth/OIDC discovery  $LOCAL/.well-known/openid-configuration"
    echo "  SSF transmitter       $LOCAL/.well-known/ssf-configuration"
    echo "  OpenID Federation     $LOCAL/.well-known/openid-federation"
    echo "  plain HTTP listener   http://localhost:$PF_PORT_HTTP/"
    echo "  admin console         https://localhost:$PF_PORT_ADMIN/pingfederate  (administrator / the password in $PF_AUTHOR_ENV)"
    echo
    echo "Next: README.md 'Testing it' - render the suite configurations and run a plan."
    exit 0
  fi
  sleep 5
done
echo "ERROR: PingFederate did not answer on $PF_PORT_HTTPS within five minutes. docker compose -f $HERE/docker-compose.yml logs pingfederate" >&2
exit 1
