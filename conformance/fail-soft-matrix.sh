#!/usr/bin/env bash
# The Phase 3 plan's exit check 4 (fail-soft), on this rig: one boot per component with its failure injected, and for
# each - PingFederate's own token endpoint serves its own client, the component's surfaces answer as plan item S-9's
# table says (docs/operator/components.md), and ready is 503 exactly when an enabled component is not READY or
# DEGRADED. Two more boots: a PingFederate that is its own trust anchor before its keys are pinned (F-0192), and a
# component that fails on a dependency and is retried to READY without a restart.
#
# What it does:
#   1. up.sh, once, unless SKIP_UP=1 (SKIP_AUTHOR and SKIP_BUILD pass through): the image and .context/vars.env
#   2. for each case, the container recreated with the case's variables added (a compose override in a temporary
#      directory, never in the repository), then the case's requests
#   3. the rig taken down at the end, unless KEEP_RIG=1
#
#   ./fail-soft-matrix.sh                 every case
#   ./fail-soft-matrix.sh ssf fapi        only those
#
# The rig's slot comes from the same variables as up.sh's (PF_RIG_NAME, PF_PORT_*, PF_AUTHOR_*). Each line printed is
# "case  check  expected  got  ok|FAIL"; the exit status is the number of FAIL lines (0: every row held).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export PF_RIG_NAME="${PF_RIG_NAME:-pf-agentic-identity}"
if [[ "$PF_RIG_NAME" == pf-agentic-identity ]]; then
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-conformance}"
else
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$PF_RIG_NAME}"
fi
export PF_PORT_HTTPS="${PF_PORT_HTTPS:-9031}"
export PF_BASE_URL="${PF_BASE_URL:-https://localhost:$PF_PORT_HTTPS}"
PF="https://localhost:$PF_PORT_HTTPS"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fail-soft-matrix.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILS=0

[[ "${SKIP_UP:-0}" == 1 ]] || "$HERE/up.sh"
# The PingFederate client every case asks for a token as: a client secret the rig generated (secrets.env, git-ignored).
EMITTER_SECRET="$(sed -n 's/^TF_VAR_ssf_emitter_client_secret=//p' "$HERE/secrets.env")"
[[ -n "$EMITTER_SECRET" ]] || { echo "ERROR: no emitter secret in $HERE/secrets.env - run up.sh first" >&2; exit 1; }

# boot NAME=VALUE ...: the container recreated with these variables on top of vars.env, and PingFederate answering.
boot() {
  { echo "services:"; echo "  pingfederate:"; echo "    labels:"; echo "      owner: fail-soft-matrix"; echo "    environment:"
    for kv in "$@"; do printf '      %s: %s\n' "${kv%%=*}" "$(printf '%s' "${kv#*=}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"; done
  } > "$WORK/override.yml"
  [[ $# -gt 0 ]] || printf 'services:\n  pingfederate:\n    labels:\n      owner: fail-soft-matrix\n' > "$WORK/override.yml"
  ( cd "$HERE" && COMPOSE_FILE="docker-compose.yml:$WORK/override.yml" docker compose up -d --force-recreate >/dev/null 2>&1 )
  for _ in $(seq 1 60); do
    if [[ "$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$PF/.well-known/openid-configuration")" == 200 ]]; then
      sleep 5   # the load-on-startup servlets' parts are registered before the war serves; let the audit settle
      return 0
    fi
    sleep 5
  done
  echo "ERROR: PingFederate did not come back within five minutes" >&2
  exit 1
}

# expect CASE CHECK EXPECTED GOT: one line, and a FAIL counted when GOT does not start with EXPECTED.
expect() {
  local ok=ok
  [[ "$4" == "$3"* ]] || { ok=FAIL; FAILS=$((FAILS + 1)); }
  printf '%-19s %-58s %-34s %-44s %s\n' "$1" "$2" "$3" "${4:0:44}" "$ok"
}

# code METHOD PATH [curl args...]: the status and, after a space, the body's error member, "a token" for a token
# response (nothing of the token is printed), or the body's first 30 characters.
code() {
  local method="$1" path="$2"; shift 2
  local out status body err
  out="$(curl -sk --max-time 20 -X "$method" -w '\n%{http_code}' "$@" "$PF$path" || true)"
  status="${out##*$'\n'}"; body="${out%$'\n'*}"
  err="$(printf '%s' "$body" | python3 -c 'import json,sys
try:
    body = json.load(sys.stdin)
    print(body.get("error") or ("a token" if "access_token" in body else ""))
except Exception:
    print("")' 2>/dev/null)"
  echo "$status ${err:-${body:0:30}}"
}

ready() { code GET /agentic-identity/health/ready | cut -d' ' -f1; }
own_token() { code POST /as/token.oauth2 -d grant_type=client_credentials -d client_id=conformance-ssf-emitter --data-urlencode "client_secret=$EMITTER_SECRET"; }
federation_client() { code POST /as/token.oauth2 -d grant_type=client_credentials -d client_id=https://rp.example -d client_secret=x; }
attested() { code POST /as/token.oauth2 -d grant_type=client_credentials -H 'OAuth-Client-Attestation: a.b.c' -H 'DPoP: d.e.f'; }

case_baseline() {   # the rig as vars.env has it: federation, automatic registration and attestation switched off
  boot
  expect baseline "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect baseline "/.well-known/openid-federation (FEDERATION off)" "404 not_found" "$(code GET /.well-known/openid-federation)"
  expect baseline "a federation client at the token endpoint" "401 invalid_client" "$(federation_client)"
  expect baseline "attestation headers at the token endpoint" "401 invalid_client" "$(attested)"
  expect baseline "ready (disabled components never count)" "200" "$(ready)"
}

case_federation() {   # switched on with no trust anchor named: FAILED_CONFIG
  boot OIDF_FEDERATION_ENABLED=true
  expect federation "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect federation "/.well-known/openid-federation" "503 temporarily_unavailable" "$(code GET /.well-known/openid-federation)"
  expect federation "/federation/fetch" "503 temporarily_unavailable" "$(code GET '/federation/fetch?sub=https://x.example')"
  expect federation "ready" "503" "$(ready)"
}

case_bootstrap_anchor() {   # F-0192: its own trust anchor and controller, no keys pinned, automatic registration off
  boot OIDF_FEDERATION_ENABLED=true "OIDF_FEDERATION_TRUST_ANCHORS=$PF_BASE_URL" "OIDF_FEDERATION_TRUST_CONTROLLER_HOST=$PF_BASE_URL"
  expect bootstrap-anchor "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect bootstrap-anchor "/.well-known/openid-federation (the keys to pin)" "200" "$(code GET /.well-known/openid-federation)"
  expect bootstrap-anchor "/federation/register (explicit registration)" "503 temporarily_unavailable" \
    "$(code POST /federation/register -H 'Content-Type: application/entity-statement+jwt' --data a.b.c)"
  expect bootstrap-anchor "ready (FEDERATION DEGRADED)" "200" "$(ready)"
}

case_auto_registration() {   # switched on with no trust controller: FAILED_CONFIG
  boot OIDF_AUTO_REGISTRATION_ENABLED=true
  expect auto-registration "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect auto-registration "a federation client at the token endpoint" "503 temporarily_unavailable" "$(federation_client)"
  expect auto-registration "a federation client at PAR" "503 temporarily_unavailable" \
    "$(code POST /as/par.oauth2 -d client_id=https://rp.example -d response_type=code)"
  expect auto-registration "ready" "503" "$(ready)"
}

case_attestation() {   # switched on with no bridge key: FAILED_CONFIG
  boot OIDF_ATTESTATION_AUTH_ENABLED=true
  expect attestation "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect attestation "attestation headers at the token endpoint" "503 temporarily_unavailable" "$(attested)"
  expect attestation "ready" "503" "$(ready)"
}

case_attestation_issuer() {   # switched on with a RAR models document that does not parse: FAILED_CONFIG
  boot OIDF_ATTESTATION_ISSUER_ENABLED=true 'OIDF_RAR_MODELS={"types":'
  expect attestation-issuer "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect attestation-issuer "/federation/attestation" "503 temporarily_unavailable" "$(code POST /federation/attestation -d x=y)"
  expect attestation-issuer "ready" "503" "$(ready)"
}

case_hosting() {   # switched on with no authority: FAILED_CONFIG
  boot OIDF_HOSTING_ENABLED=true
  expect hosting "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect hosting "/federation/agents/probe-1" "503 temporarily_unavailable" "$(code GET /federation/agents/probe-1)"
  expect hosting "ready" "503" "$(ready)"
}

case_ssf() {   # a setting that does not parse: FAILED_CONFIG
  boot OIDF_SSF_ENABLED=true OIDF_SSF_DEFAULT_SUBJECTS=SOME
  expect ssf "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect ssf "/.well-known/ssf-configuration" "503 temporarily_unavailable" "$(code GET /.well-known/ssf-configuration)"
  expect ssf "/ssf/poll" "503 temporarily_unavailable" "$(code POST /ssf/poll -H 'Content-Type: application/json' -d '{}')"
  local logout; logout="$(code GET /idp/init_logout.openid | cut -d' ' -f1)"
  expect ssf "the logout (always goes on; not the gate's 503)" "not 503" "$([[ "$logout" != 503 ]] && echo 'not 503' || echo 503)"
  expect ssf "ready" "503" "$(ready)"
}

case_ssf_receiver() {   # switched on with no receiver settings: FAILED_CONFIG
  boot OIDF_SSF_RECEIVER_ENABLED=true
  expect ssf-receiver "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect ssf-receiver "/ssf/receiver/events" "503 temporarily_unavailable" \
    "$(code POST /ssf/receiver/events -H 'Content-Type: application/secevent+jwt' --data a.b.c)"
  expect ssf-receiver "ready" "503" "$(ready)"
}

case_operator_api() {   # switched on with no operator authentication: FAILED_CONFIG
  boot OIDF_OPERATOR_API_ENABLED=true
  expect operator-api "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect operator-api "/federation/admin/entities" "503 temporarily_unavailable" "$(code GET /federation/admin/entities)"
  expect operator-api "ready" "503" "$(ready)"
}

case_fapi() {   # a switch that is not true or false: FAILED_CONFIG, with the rig's client list readable
  boot OIDF_FAPI_ENABLED=maybe
  expect fapi "PingFederate's own token endpoint (a client not listed)" "200 a token" "$(own_token)"
  expect fapi "a listed FAPI client at the token endpoint" "503 temporarily_unavailable" \
    "$(code POST /as/token.oauth2 -d grant_type=client_credentials -d client_id=conformance-fapi2-client1)"
  expect fapi "ready" "503" "$(ready)"
}

case_dependency() {   # FAILED_DEPENDENCY retried to READY with no restart: a file the start reads, there a minute late
  local page=/tmp/fail-soft-matrix-error-page.html
  boot OIDF_FEDERATION_ENABLED=true OIDF_AUTO_REGISTRATION_ENABLED=true "OIDF_FEDERATION_TRUST_ANCHORS=$PF_BASE_URL" \
    "OIDF_FEDERATION_TRUST_CONTROLLER_HOST=$PF_BASE_URL" "OIDF_FEDERATION_SELF_ANCHOR=$PF_BASE_URL" "OIDF_FEDERATION_ERROR_PAGE=$page"
  expect dependency "PingFederate's own token endpoint" "200 a token" "$(own_token)"
  expect dependency "ready while the page is missing (never served: no grace)" "503" "$(ready)"
  docker exec "$PF_RIG_NAME" sh -c "printf '<p>\${error}</p>' > $page"
  local waited=0 now
  while now="$(ready)"; [[ "$now" != 200 && $waited -lt 330 ]]; do sleep 10; waited=$((waited + 10)); done
  expect dependency "ready once the page is there, no restart (${waited}s)" "200" "$now"
  expect dependency "the supervisor's retries in server.log" "retried" "$(docker exec "$PF_RIG_NAME" sh -c \
    "grep -c 'AUTO_REGISTRATION: FAILED_DEPENDENCY -> STARTING' /opt/out/instance/log/server.log" | awk '{print ($1 > 0) ? "retried" : "none"}')"
}

CASES=(baseline federation bootstrap_anchor auto_registration attestation attestation_issuer hosting ssf ssf_receiver operator_api fapi dependency)
if [[ $# -gt 0 ]]; then CASES=("${@//-/_}"); fi
printf '%-19s %-58s %-34s %-44s %s\n' case check expected got result
for c in "${CASES[@]}"; do
  case "$c" in
    baseline) case_baseline ;;
    federation) case_federation ;;
    bootstrap_anchor) case_bootstrap_anchor ;;
    auto_registration) case_auto_registration ;;
    attestation) case_attestation ;;
    attestation_issuer) case_attestation_issuer ;;
    hosting) case_hosting ;;
    ssf) case_ssf ;;
    ssf_receiver) case_ssf_receiver ;;
    operator_api) case_operator_api ;;
    fapi) case_fapi ;;
    dependency) case_dependency ;;
    *) echo "ERROR: no case $c (${CASES[*]})" >&2; exit 2 ;;
  esac
done
if [[ "${KEEP_RIG:-0}" != 1 ]]; then ( cd "$HERE" && docker compose down >/dev/null 2>&1 ); fi
echo "$FAILS row(s) failed"
exit "$FAILS"
