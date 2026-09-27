#!/usr/bin/env bash
# What PingFederate 13.1.3 hands the RAR plugin as the user key in each OAuth flow, and what the plugin makes
# of it - on this rig, with a PDP that says yes and writes down what it was asked.
#
# The evidence for the plan's to-verify item 1 (getUserKey() per flow; U-0016) and, with OLD_PLUGIN_JAR, item 7
# (a stored plaintext secret under the encrypted field; U-0022), recorded in plugins/rar-paz-plugin/README.md.
# Item 2 (JWT-bearer never enriches; U-0017) is not driven here; the refresh that reissues stored details
# without asking the plugin ("Found while designing" item 2) is. For each flow it prints the user key
# PingFederate passed (matched by SHA-256 against the plugin's PII-safe log line, which never carries the key
# itself) and the principal_source the plugin chose, as the stub PDP received it.
#
# What it does:
#   1. boots the rig (up.sh) with the plugin jar lent to it by docker-compose.rar-plugin.yml, on its own
#      slot (PF_RIG_NAME=pfai-rar, ports 45031/45080/45999, authoring 44999/44031), unless SKIP_UP=1
#   2. starts rar-principal/stub-pdp.py on the host (STUB_PORT, default 45500)
#   3. through the running rig's admin API: a processor instance (AuthZEN dialect, pointed at the stub over
#      host.docker.internal), the three built-in authorization detail types bound to it, and one OAuth client
#      that may use them with every grant this drives - a secret-authenticated client, so nothing here signs
#   4. drives client credentials, CIBA (the ciba-sim answers "allow"), refresh, token exchange and the
#      authorization code flow (PAR, the HTML form login, consent bypassed), each carrying
#      authorization_details
#   5. prints the evidence per flow, then removes what it configured and takes the rig down (KEEP_RIG=1 keeps it)
#
# Env:
#   RAR_PLUGIN_JAR   the jar to lend the rig (default: the reactor's plugins/rar-paz-plugin/target build)
#   OLD_PLUGIN_JAR   an older release's jar (gh release download v0.3.0 -p 'pf.plugins.pf-rar-paz-plugin.jar'):
#                    the rig boots on it, an instance is created under it, the archive exported, the container
#                    restarted on RAR_PLUGIN_JAR, the archive imported and the instance saved again - the
#                    upgrade rehearsal, then the flows
#   SKIP_UP=1        the rig is already up on the slot (an earlier run with KEEP_RIG=1)
#   SKIP_AUTHOR=1 / SKIP_BUILD=1   passed through to up.sh
#   KEEP_RIG=1       leave the rig running (the stub is still stopped, the configuration still removed)
#   ONLY_CONFIGURE=1 configure the rig and stop there, leaving the stub and the configuration in place for
#                    driving a flow by hand (SKIP_UP=1 KEEP_RIG=1 ./verify-rar-principal.sh afterwards cleans up)
#   OUT_DIR          where the stub's request log, the summary and PingFederate's server.log land
#                    (default conformance/.rar-principal, git-ignored). On the way down the rehearsal's
#                    exported archive (it holds the rig's pf.jwk and the plaintext secret) is deleted, and
#                    the shared secret in the stub's request log is masked; the evidence is the printed lines.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
export PF_RIG_NAME="${PF_RIG_NAME:-pfai-rar}"
export PF_PORT_HTTPS="${PF_PORT_HTTPS:-45031}" PF_PORT_HTTP="${PF_PORT_HTTP:-45080}" PF_PORT_ADMIN="${PF_PORT_ADMIN:-45999}"
export PF_AUTHOR_ADMIN_PORT="${PF_AUTHOR_ADMIN_PORT:-44999}" PF_AUTHOR_RUNTIME_PORT="${PF_AUTHOR_RUNTIME_PORT:-44031}"
export PF_AUTHOR_ENV="${PF_AUTHOR_ENV:-$HERE/.author.env}"
export RAR_PLUGIN_JAR="${RAR_PLUGIN_JAR:-$REPO/plugins/rar-paz-plugin/target/pf.plugins.pf-rar-paz-plugin.jar}"
export COMPOSE_FILE="docker-compose.yml:docker-compose.rar-plugin.yml"
# The compose project up.sh uses (its rule, repeated: the default rig keeps this directory's project name),
# so the restart in the rehearsal and the teardown address the rig up.sh started and not a namesake.
if [[ "$PF_RIG_NAME" == pf-agentic-identity ]]; then
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-conformance}"
else
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$PF_RIG_NAME}"
fi
STUB_PORT="${STUB_PORT:-45500}"
OUT="${OUT_DIR:-$HERE/.rar-principal}"
PF="https://localhost:$PF_PORT_HTTPS"
ADMIN="https://localhost:$PF_PORT_ADMIN/pf-admin-api/v1"
CLIENT_ID="rar-principal-probe"
INSTANCE_ID="rarPrincipalProbe"
TYPES=(payment_initiation account_information sales_agent)

for tool in docker curl jq python3 openssl; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool is required" >&2; exit 1; }
done
[[ -f "$RAR_PLUGIN_JAR" ]] || { echo "ERROR: no plugin jar at $RAR_PLUGIN_JAR - mvn -pl plugins/rar-paz-plugin -am package first" >&2; exit 1; }
mkdir -p "$OUT"; : > "$OUT/pdp-requests.jsonl"; : > "$OUT/summary.txt"

# ── the rig ──────────────────────────────────────────────────────────────────────────────────────
# With OLD_PLUGIN_JAR, the rig comes up on that jar first (the rehearsal below restarts it on RAR_PLUGIN_JAR).
if [[ "${SKIP_UP:-0}" != 1 ]]; then
  ( cd "$HERE" && RAR_PLUGIN_JAR="${OLD_PLUGIN_JAR:-$RAR_PLUGIN_JAR}" ./up.sh )
fi
PW="$(sed -n 's/^PING_IDENTITY_PASSWORD=//p' "$PF_AUTHOR_ENV")"
[[ -n "$PW" ]] || { echo "ERROR: no PING_IDENTITY_PASSWORD in $PF_AUTHOR_ENV" >&2; exit 1; }

pf() {  # pf <method> <path> [json-body]  -> body; the status is in PF_STATUS, the body also in PF_BODY
  local method="$1" path="$2" body="${3:-}" tmp; tmp="$(mktemp)"
  if [[ -n "$body" ]]; then
    PF_STATUS="$(curl -sk -o "$tmp" -w '%{http_code}' -X "$method" -u "administrator:$PW" -H 'X-XSRF-Header: PingFederate' \
      -H 'Content-Type: application/json' -d "$body" "$ADMIN$path")"
  else
    PF_STATUS="$(curl -sk -o "$tmp" -w '%{http_code}' -X "$method" -u "administrator:$PW" -H 'X-XSRF-Header: PingFederate' "$ADMIN$path")"
  fi
  PF_BODY="$(cat "$tmp")"; rm -f "$tmp"
  printf '%s' "$PF_BODY"
}
need() {  # need <expected-status> <what>  (after a pf call): PingFederate's reason is worth more than the status
  [[ "$PF_STATUS" == "$1" ]] || { echo "ERROR: $2 answered HTTP $PF_STATUS (wanted $1): $(head -c 600 <<<"$PF_BODY")" >&2; exit 1; }
}

# ── helpers ──────────────────────────────────────────────────────────────────────────────────────
DETAIL_SALES='[{"type":"sales_agent","sales_regions":["EMEA"]}]'
DETAIL_PAYMENT='[{"type":"payment_initiation","amount":"42.00","currency":"AUD","creditorName":"Acme"}]'
sha16() { printf '%s' "$1" | openssl dgst -sha256 | sed 's/.*= //' | cut -c1-16; }
token() {  # token <form fields...>  -> the token endpoint's JSON; the status is in TOKEN_STATUS
  local tmp; tmp="$(mktemp)"
  TOKEN_STATUS="$(curl -sk -o "$tmp" -w '%{http_code}' -u "$CLIENT_ID:$CLIENT_SECRET" "$@" "$PF/as/token.oauth2")"
  cat "$tmp"; rm -f "$tmp"
}
jwt_sub() {  # the sub of a JWT, or "?" - the payload is base64url without padding, which base64 -d refuses
  python3 -c 'import base64,json,sys
try:
    p = sys.argv[1].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))).get("sub", "?"))
except Exception: print("?")' "$1"
}
pdp_lines() { wc -l < "$OUT/pdp-requests.jsonl" | tr -d ' '; }
pdp_since() {  # pdp_since <line-count>  -> the stub's requests after that line, one per line
  tail -n +"$(( $1 + 1 ))" "$OUT/pdp-requests.jsonl"
}
# The plugin's INFO lines, read from server.log itself: `docker logs` tails that file and lags it by seconds.
pf_log_lines() { docker exec "$PF_RIG_NAME" grep -c 'RAR governance: type=' /opt/out/instance/log/server.log 2>/dev/null || true; }
pf_log_since() {  # the plugin's INFO lines after the n-th
  { docker exec "$PF_RIG_NAME" grep 'RAR governance: type=' /opt/out/instance/log/server.log 2>/dev/null || true; } \
    | tail -n +"$(( $1 + 1 ))" | sed 's/.*RAR governance: //'
}
USER_HASH="$(sha16 suite-user)"; CLIENT_HASH="$(sha16 "$CLIENT_ID")"
name_key() {  # name_key <sha256:16hex or -> -> what that hash is, if this run knows it
  case "$1" in
    "sha256:$USER_HASH") echo "suite-user" ;;
    "sha256:$CLIENT_HASH") echo "$CLIENT_ID (the client id)" ;;
    "-") echo "(none)" ;;
    *) echo "$1 (not a value this run sent)" ;;
  esac
}
report() {  # report <flow> <pdp-line-count-before> <pf-log-count-before> <what happened at the endpoint>
  local flow="$1" pdp_before="$2" log_before="$3" outcome="$4" asked line
  sleep 2   # the plugin logs before PingFederate answers, but the file is flushed on its own schedule
  echo; echo "── $flow: $outcome"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local userkey principal source
    userkey="$(sed -n 's/.* userKey=\([^ ]*\).*/\1/p' <<<"$line")"
    principal="$(sed -n 's/.* principal=\([^ ]*\).*/\1/p' <<<"$line")"
    source="$(sed -n 's/.* principalSource=\([^ ]*\).*/\1/p' <<<"$line")"
    echo "   PF passed user key: $(name_key "$userkey")   plugin: principal_source=$source principal=$(name_key "$principal")"
    echo "   log line: $line"
  done < <(pf_log_since "$log_before")
  asked="$(pdp_since "$pdp_before" | jq -c '{subject: .body.subject, principal_source: .body.context.principal_source, resource_type: .body.resource.type, secret_header: (.headers["X-Probe-Secret"] // null)}' | sed "s/$SECRET/<the plaintext secret>/g")"
  if [[ -n "$asked" ]]; then
    echo "   PDP was asked: $asked"
  else
    echo "   PDP was not asked"
  fi
  { echo "$flow: $outcome"; pf_log_since "$log_before" | sed 's/^/  /' || true; echo "  pdp: ${asked:-not asked}"; } >> "$OUT/summary.txt" || true
}

# The instance as PingFederate stored it on disk: its field names, and what form "Shared Secret" takes there -
# never the secret itself.
stored_fields() {
  local file
  file="$(docker exec "$PF_RIG_NAME" find /opt/out/instance/server/default/data -name "$INSTANCE_ID.xml" 2>/dev/null | head -1)"
  [[ -n "$file" ]] || { echo "no $INSTANCE_ID.xml under the data directory"; return; }
  docker exec "$PF_RIG_NAME" cat "$file" | python3 -c 'import re, sys
xml = sys.stdin.read(); secret = sys.argv[1]
names = re.findall(r"<urn:Field name=\"([^\"]+)\"", xml)
field = re.search(r"<urn:Field name=\"Shared Secret\"([^>]*)>([^<]*)<", xml)
if field is None:
    form = "absent"
else:
    attrs, value = field.group(1).strip(), field.group(2)
    form = ("the plaintext secret" if value == secret else "empty" if not value
            else "%d characters starting %s" % (len(value), value[:8]))
    form += " (attributes: %s)" % attrs if attrs else ""
print("%d fields%s, Shared Secret %s" % (len(names), " including Deny unless PERMIT" if "Deny unless PERMIT" in names else "", form))' "$SECRET"
}
deobfuscation_errors() { docker exec "$PF_RIG_NAME" grep -c 'problem deobfuscating the value for the field: Shared Secret' /opt/out/instance/log/server.log 2>/dev/null || true; }

configure() {
  unconfigure   # a previous run's leftovers, if any; each DELETE is a 404 otherwise
  DESCRIPTOR="$(pf GET /oauth/authorizationDetailProcessors/descriptors | jq -r '.items[] | select(.className | test("FedRar|AttestationAwareRarProcessor")) | .id' | head -1)"
  [[ -n "$DESCRIPTOR" ]] || { echo "ERROR: the rig lists no RAR plugin descriptor - is the jar mounted? (docker-compose.rar-plugin.yml)" >&2; exit 1; }
  pf POST /oauth/authorizationDetailProcessors "$(jq -cn --arg id "$INSTANCE_ID" --arg d "$DESCRIPTOR" --arg url "http://host.docker.internal:$STUB_PORT/access/v1/evaluation" --arg s "$SECRET" '{
    id: $id, name: "RAR principal probe", pluginDescriptorRef: {id: $d},
    configuration: {fields: [
      {name: "PDP Dialect", value: "authzen"}, {name: "PDP URL", value: $url},
      {name: "Shared Secret Header", value: "X-Probe-Secret"}, {name: "Shared Secret", value: $s},
      {name: "Request timeout (ms)", value: "5000"}], tables: []}}')" >/dev/null; need 201 "creating the processor instance"
  for t in "${TYPES[@]}"; do
    pf POST /oauth/authorizationDetailTypes "$(jq -cn --arg t "$t" --arg id "$INSTANCE_ID" '{id: ("rarProbe_" + $t), type: $t, description: ("RAR probe " + $t), authorizationDetailProcessorRef: {id: $id}, active: true}')" >/dev/null
    need 201 "creating the authorization detail type $t"
  done
  # A token-exchange processor policy, so the token-exchange grant gets as far as the plugin: the subject token
  # is one of this PF's own access tokens, validated by the stock bearer-token processor.
  pf POST /idp/tokenProcessors "$(jq -cn '{id: "rarProbeBearer", name: "RAR probe bearer access token",
    pluginDescriptorRef: {id: "org.sourceid.wstrust.processor.oauth.BearerAccessTokenTokenProcessor"},
    configuration: {fields: [{name: "Access Token Manager", value: "conformanceJwt"}], tables: []},
    attributeContract: {coreAttributes: [{name: "aud"}, {name: "authorization_details"}, {name: "client_id"}, {name: "expires_at"}, {name: "iss"}, {name: "scope"}]}}')" >/dev/null
  need 201 "creating the bearer token processor"
  pf POST /oauth/tokenExchange/processor/policies "$(jq -cn '{id: "rarProbeExchange", name: "RAR probe token exchange", actorTokenRequired: false,
    attributeContract: {coreAttributes: [{name: "subject"}], extendedAttributes: []},
    processorMappings: [{subjectTokenType: "urn:ietf:params:oauth:token-type:access_token", subjectTokenProcessor: {id: "rarProbeBearer"},
      attributeContractFulfillment: {subject: {source: {type: "SUBJECT_TOKEN"}, value: "client_id"}}}]}')" >/dev/null
  need 201 "creating the token exchange processor policy"
  # ...and the access token mapping the exchange issues through, or PingFederate refuses the exchange after
  # the plugin has been asked ("Could not find a Access Token Mapping for the selected Policy Processor").
  pf POST /oauth/accessTokenMappings "$(jq -cn '{context: {type: "TOKEN_EXCHANGE_PROCESSOR_POLICY", contextRef: {id: "rarProbeExchange"}},
    accessTokenManagerRef: {id: "conformanceJwt"},
    attributeContractFulfillment: {sub: {source: {type: "TOKEN_EXCHANGE_PROCESSOR_POLICY"}, value: "subject"}}}')" >/dev/null
  need 201 "creating the token exchange access token mapping"
  pf POST /oauth/clients "$(jq -cn --arg c "$CLIENT_ID" --arg s "$CLIENT_SECRET" '{
    clientId: $c, name: "RAR principal probe", enabled: true,
    grantTypes: ["CLIENT_CREDENTIALS", "AUTHORIZATION_CODE", "REFRESH_TOKEN", "CIBA", "TOKEN_EXCHANGE"],
    redirectUris: ["https://localhost/rar-probe/cb"],
    clientAuth: {type: "SECRET", secret: $s},
    restrictScopes: true, restrictedScopes: ["openid", "profile", "offline_access"],
    defaultAccessTokenManagerRef: {id: "conformanceJwt"},
    bypassApprovalPage: true,
    requireProofKeyForCodeExchange: false, requirePushedAuthorizationRequests: false,
    cibaDeliveryMode: "POLL", cibaPollingInterval: 1, cibaRequireSignedRequests: false, cibaUserCodeSupported: false,
    requestPolicyRef: {id: "conformanceCiba"},
    tokenExchangeProcessorPolicyRef: {id: "rarProbeExchange"},
    authorizationDetailTypes: ["payment_initiation", "account_information", "sales_agent"]}')" >/dev/null
  need 201 "creating the probe client"
  echo "configured: processor $INSTANCE_ID ($DESCRIPTOR), types ${TYPES[*]}, client $CLIENT_ID"
}
unconfigure() {
  local mapping
  pf DELETE "/oauth/clients/$CLIENT_ID" >/dev/null
  for t in "${TYPES[@]}"; do pf DELETE "/oauth/authorizationDetailTypes/rarProbe_$t" >/dev/null; done
  pf DELETE "/oauth/authorizationDetailProcessors/$INSTANCE_ID" >/dev/null
  # The exchange's mapping has an id PingFederate chose, so it is found by the policy it maps - also when an
  # earlier run (KEEP_RIG=1, or one that stopped half way) created it - and goes before the policy it names.
  for mapping in $(pf GET /oauth/accessTokenMappings | jq -r '(.items? // .)[]? | select(.context.contextRef.id? == "rarProbeExchange") | .id'); do
    pf DELETE "/oauth/accessTokenMappings/$mapping" >/dev/null
  done
  pf DELETE /oauth/tokenExchange/processor/policies/rarProbeExchange >/dev/null
  pf DELETE /idp/tokenProcessors/rarProbeBearer >/dev/null
}
wait_for_pf() {
  for _ in $(seq 1 60); do
    if curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$PF/.well-known/openid-configuration" | grep -q 200 \
       && [[ "$(pf GET /version)" == *'"version"'* ]]; then
      return 0
    fi
    sleep 5
  done
  echo "ERROR: PingFederate did not come back on $PF_PORT_HTTPS" >&2; exit 1
}

# ── the stub PDP on the host ─────────────────────────────────────────────────────────────────────
python3 "$HERE/rar-principal/stub-pdp.py" "$STUB_PORT" "$OUT/pdp-requests.jsonl" > "$OUT/stub-pdp.log" 2>&1 &
STUB_PID=$!
cleanup() {
  set +e
  echo; echo "── tearing down ──"
  [[ -n "${ADAPTER_ORIGINAL:-}" ]] && restore_adapter
  unconfigure
  kill "$STUB_PID" 2>/dev/null; wait "$STUB_PID" 2>/dev/null
  rm -f "$OUT/archive-old.zip"
  if [[ -n "${SECRET:-}" && -f "$OUT/pdp-requests.jsonl" ]]; then
    RIG_SECRET="$SECRET" python3 -c 'import os, sys
p = sys.argv[1]; s = os.environ["RIG_SECRET"]
t = open(p, encoding="utf-8").read()
open(p, "w", encoding="utf-8").write(t.replace(s, "<the rig secret>"))' "$OUT/pdp-requests.jsonl"
  fi
  docker exec "$PF_RIG_NAME" cat /opt/out/instance/log/server.log > "$OUT/server.log" 2>/dev/null
  if [[ "${KEEP_RIG:-0}" != 1 ]]; then
    # --rmi all: the rig's image is tagged <PF_RIG_NAME>/pingfederate:local, which --rmi local leaves behind.
    ( cd "$HERE" && docker compose down --rmi all --volumes --remove-orphans ) > "$OUT/compose-down.log" 2>&1
    docker rm -f "${PF_AUTHOR_NAME:-$PF_RIG_NAME-author}" >/dev/null 2>&1
    if docker ps -a --format '{{.Names}}' | grep -qx "$PF_RIG_NAME"; then
      echo "WARNING: container $PF_RIG_NAME is still there - see $OUT/compose-down.log" >&2
    else
      echo "rig $PF_RIG_NAME is down"
    fi
  fi
  echo "evidence: $OUT/summary.txt, $OUT/pdp-requests.jsonl, $OUT/server.log"
}
trap cleanup EXIT
sleep 1
SECRET="rig-$(openssl rand -hex 8)"; CLIENT_SECRET="$(openssl rand -hex 16)"

# ── the upgrade rehearsal (plan to-verify item 7), when an older jar is named ────────────────────
# With OLD_PLUGIN_JAR set, the rig came up with that jar: configure under it (its "Shared Secret" field was
# plain text), make one call so the stub records the secret it sent, export the archive, restart the
# container with the jar under test, import the archive, and read the instance and the secret the plugin
# now sends. Then the flows run against the imported configuration.
if [[ -n "${OLD_PLUGIN_JAR:-}" ]]; then
  echo; echo "── upgrade rehearsal: instance created under $(basename "$OLD_PLUGIN_JAR") ($(unzip -p "$OLD_PLUGIN_JAR" META-INF/MANIFEST.MF | sed -n 's/^Implementation-Version: *//p' | tr -d '\r'))"
  configure
  before="$(pdp_lines)"
  token -d grant_type=client_credentials --data-urlencode "authorization_details=$DETAIL_SALES" >/dev/null
  echo "   before: the old plugin sent secret header $(pdp_since "$before" | jq -c '.headers["X-Probe-Secret"]' | sed "s/$SECRET/<the plaintext secret>/") (HTTP $TOKEN_STATUS at the token endpoint)"
  curl -sk -o "$OUT/archive-old.zip" -u "administrator:$PW" -H 'X-XSRF-Header: PingFederate' "$ADMIN/configArchive/export"
  echo "   exported the archive; the field is stored as: $(unzip -p "$OUT/archive-old.zip" 'authorization-detail-processors/*' | grep -o '<urn:Field name="Shared Secret">[^<]*' | sed 's/.*>//' | sed "s/$SECRET/<the plaintext secret>/")"
  ( cd "$HERE" && docker compose up -d ) > "$OUT/compose-restart.log" 2>&1   # RAR_PLUGIN_JAR now names the jar under test
  wait_for_pf
  curl -sk -o /dev/null -w '   imported the archive under the new jar: HTTP %{http_code}\n' -X POST -u "administrator:$PW" -H 'X-XSRF-Header: PingFederate' \
    -F "file=@$OUT/archive-old.zip" "$ADMIN/configArchive/import?forceImport=true"
  sleep 5
  echo "   the instance reads back with: $(pf GET "/oauth/authorizationDetailProcessors/$INSTANCE_ID" | jq -c '[.configuration.fields[] | select(.name | test("Secret|Deny"))]' | sed "s/$SECRET/<the plaintext secret>/")"
  echo "   on disk after the import: $(stored_fields)"
  echo "   PingFederate's log since the restart: $(deobfuscation_errors) \"problem deobfuscating the value for the field: Shared Secret\" line(s)"
  before="$(pdp_lines)"; errors="$(deobfuscation_errors)"
  token -d grant_type=client_credentials --data-urlencode "authorization_details=$DETAIL_SALES" >/dev/null
  echo "   after: the new plugin sent secret header $(pdp_since "$before" | jq -c '.headers["X-Probe-Secret"] // "nothing (no PDP call)"' | sed "s/$SECRET/<the plaintext secret>/") (HTTP $TOKEN_STATUS at the token endpoint); new deobfuscation lines: $(( $(deobfuscation_errors) - errors ))"
  # The upgrade note's remedy: save the instance again, here through the admin API with what it read back.
  pf PUT "/oauth/authorizationDetailProcessors/$INSTANCE_ID" "$(pf GET "/oauth/authorizationDetailProcessors/$INSTANCE_ID")" >/dev/null
  need 200 "saving the imported instance again"
  sleep 2
  before="$(pdp_lines)"; errors="$(deobfuscation_errors)"
  token -d grant_type=client_credentials --data-urlencode "authorization_details=$DETAIL_SALES" >/dev/null
  echo "   saved again: on disk $(stored_fields); the plugin sent $(pdp_since "$before" | jq -c '.headers["X-Probe-Secret"] // "nothing (no PDP call)"' | sed "s/$SECRET/<the plaintext secret>/") (HTTP $TOKEN_STATUS); new deobfuscation lines: $(( $(deobfuscation_errors) - errors ))"
  { echo "upgrade rehearsal: see the lines above"; } >> "$OUT/summary.txt"
else
  configure
fi

if [[ "${ONLY_CONFIGURE:-0}" == 1 ]]; then
  trap - EXIT
  echo "configured and left in place: stub PDP pid $STUB_PID on $STUB_PORT, client secret in $OUT/client-secret"
  printf '%s\n' "$CLIENT_SECRET" > "$OUT/client-secret"
  exit 0
fi

# ── the flows ────────────────────────────────────────────────────────────────────────────────────
# 1. client credentials: the user key IS the client id; sales_agent reaches the PDP as principal_source=client,
#    payment_initiation is refused before any PDP call (it needs a person).
p="$(pdp_lines)"; l="$(pf_log_lines)"
token -d grant_type=client_credentials --data-urlencode "authorization_details=$DETAIL_SALES" > "$OUT/cc.json"
report "client credentials, sales_agent" "$p" "$l" "token endpoint HTTP $TOKEN_STATUS"
p="$(pdp_lines)"; l="$(pf_log_lines)"
token -d grant_type=client_credentials --data-urlencode "authorization_details=$DETAIL_PAYMENT" > "$OUT/cc-payment.json"
report "client credentials, payment_initiation" "$p" "$l" "token endpoint HTTP $TOKEN_STATUS: $(jq -r '.error_description // .error // .' "$OUT/cc-payment.json" | head -c 160)"

# 2. CIBA: the backchannel request carries the hint; the plugin is asked at bc-auth with the identity hint.
p="$(pdp_lines)"; l="$(pf_log_lines)"
CIBA="$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" -d scope=openid -d login_hint=suite-user --data-urlencode "authorization_details=$DETAIL_PAYMENT" "$PF/as/bc-auth.ciba")"
AUTH_REQ_ID="$(jq -r '.auth_req_id // empty' <<<"$CIBA")"
report "CIBA backchannel request, payment_initiation" "$p" "$l" "bc-auth answered $(jq -c 'del(.auth_req_id)' <<<"$CIBA" | head -c 160)"
REFRESH_TOKEN=""; ACCESS_TOKEN=""
if [[ -n "$AUTH_REQ_ID" ]]; then
  curl -sk -o /dev/null -X POST "$PF/ciba-sim/decision?auth_req_id=$AUTH_REQ_ID&action=allow"
  for _ in $(seq 1 10); do
    sleep 2
    # Not in a command substitution: TOKEN_STATUS must reach this loop, and the first 200 redeems the id.
    token -d grant_type=urn:openid:params:grant-type:ciba -d "auth_req_id=$AUTH_REQ_ID" > "$OUT/ciba-token.json"
    if [[ "$TOKEN_STATUS" == 200 ]]; then break; fi
  done
  REFRESH_TOKEN="$(jq -r '.refresh_token // empty' "$OUT/ciba-token.json")"
  ACCESS_TOKEN="$(jq -r '.access_token // empty' "$OUT/ciba-token.json")"
  echo "   CIBA token poll: HTTP $TOKEN_STATUS, refresh token $([[ -n "$REFRESH_TOKEN" ]] && echo issued || echo 'not issued')"
fi

# 3. refresh: the grant's user is the principal, via refresh - and only a refresh that restates
#    authorization_details reaches the plugin at all (plan "Found" item 2).
if [[ -n "$REFRESH_TOKEN" ]]; then
  p="$(pdp_lines)"; l="$(pf_log_lines)"
  token -d grant_type=refresh_token -d "refresh_token=$REFRESH_TOKEN" --data-urlencode "authorization_details=$DETAIL_PAYMENT" > "$OUT/refresh.json"
  report "refresh with authorization_details, payment_initiation" "$p" "$l" "token endpoint HTTP $TOKEN_STATUS"
  REFRESH_TOKEN="$(jq -r '.refresh_token // empty' "$OUT/refresh.json")"
  [[ -n "$REFRESH_TOKEN" ]] || REFRESH_TOKEN="$(jq -r '.refresh_token // empty' "$OUT/ciba-token.json")"
  p="$(pdp_lines)"; l="$(pf_log_lines)"
  token -d grant_type=refresh_token -d "refresh_token=$REFRESH_TOKEN" > "$OUT/refresh-bare.json"
  report "refresh without authorization_details" "$p" "$l" "token endpoint HTTP $TOKEN_STATUS (the stored details are reissued; the plugin is not asked)"
else
  echo; echo "── refresh: skipped, CIBA issued no refresh token"
fi

# 4. token exchange: PingFederate passes no user key; the plugin has no verified subject-token subject to
#    read (the filter does not publish one yet), so the principal is none. The subject token is the CIBA
#    access token, or failing that the client-credentials one: the plugin is asked before the subject token is
#    validated, so which it is does not change what this shows.
[[ -n "$ACCESS_TOKEN" ]] || ACCESS_TOKEN="$(jq -r '.access_token // empty' "$OUT/cc.json")"
if [[ -n "$ACCESS_TOKEN" ]]; then
  p="$(pdp_lines)"; l="$(pf_log_lines)"
  token -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange -d "subject_token=$ACCESS_TOKEN" \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token --data-urlencode "authorization_details=$DETAIL_SALES" > "$OUT/exchange.json"
  report "token exchange, sales_agent" "$p" "$l" "token endpoint HTTP $TOKEN_STATUS $(jq -c 'del(.access_token)' "$OUT/exchange.json" | head -c 160), token sub=$(jwt_sub "$(jq -r '.access_token // empty' "$OUT/exchange.json")")"
  p="$(pdp_lines)"; l="$(pf_log_lines)"
  token -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange -d "subject_token=$ACCESS_TOKEN" \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token --data-urlencode "authorization_details=$DETAIL_PAYMENT" > "$OUT/exchange-payment.json"
  report "token exchange, payment_initiation" "$p" "$l" "token endpoint HTTP $TOKEN_STATUS: $(jq -r '.error_description // .error // .' "$OUT/exchange-payment.json" | head -c 160)"
else
  echo; echo "── token exchange: skipped, no access token to exchange"
fi

# 5. authorization code, headless: PAR, then the HTML form login with the rig's test user, consent bypassed.
#    PingFederate 13.1.3 asks the plugin once in this flow, at the resume after authentication
#    (OAuthResumableRequestHandlerBase; path /as/<id>/resume/as/authorization.ping), with the authentication
#    result's "subject" attribute as the user key - and the rig's login adapter has no such attribute, so the
#    plugin knows nobody and refuses a payment. Driven twice: as the rig ships, and with "subject" mapped on
#    the adapter by expression, which is what a deployment does to give the plugin a principal here.
code_flow() {  # code_flow <label> <authorization_details json>
  local label="$1" details="$2" p l jar par request_uri action location code password
  p="$(pdp_lines)"; l="$(pf_log_lines)"
  jar="$(mktemp)"
  par="$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" -d response_type=code -d "redirect_uri=https://localhost/rar-probe/cb" -d scope=openid \
    --data-urlencode "authorization_details=$details" "$PF/as/par.oauth2")"
  request_uri="$(jq -r '.request_uri // empty' <<<"$par")"
  code=""; location=""
  if [[ -n "$request_uri" ]]; then
    # The rig's test user, whose password gen-keys.sh generated into the git-ignored secrets.env.
    password="$(sed -n 's/^TF_VAR_test_user_password=//p' "$HERE/secrets.env")"
    curl -sk -c "$jar" -b "$jar" -L -o "$OUT/login.html" "$PF/as/authorization.oauth2?client_id=$CLIENT_ID&request_uri=$request_uri"
    action="$(grep -o 'action="[^"]*"' "$OUT/login.html" | head -1 | sed 's/action="//; s/"$//' | sed 's/&amp;/\&/g')"
    [[ "$action" == http* ]] || action="$PF$action"
    location="$(curl -sk -c "$jar" -b "$jar" -o "$OUT/login-post.html" -w '%{redirect_url}' -d pf.username=suite-user \
      --data-urlencode "pf.pass=$password" -d pf.ok=clicked -d pf.cancel= -d pf.adapterId=conformanceLogin "$action")"
    for _ in 1 2 3; do   # follow PingFederate's own redirects, never the callback
      [[ "$location" == "$PF"* ]] || break
      location="$(curl -sk -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$location")"
    done
    code="$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$location")"
  fi
  rm -f "$jar"
  if [[ -n "$code" ]]; then
    token -d grant_type=authorization_code -d "code=$code" -d "redirect_uri=https://localhost/rar-probe/cb" > "$OUT/code-token.json"
    report "authorization code, $label" "$p" "$l" "callback reached with a code; token endpoint HTTP $TOKEN_STATUS, token sub=$(jwt_sub "$(jq -r '.access_token // empty' "$OUT/code-token.json")")"
  else
    report "authorization code, $label" "$p" "$l" "no code (last location: $(head -c 240 <<<"${location:-none}"); PAR: $(head -c 100 <<<"$par"))"
  fi
}
ADAPTER_ORIGINAL="$(pf GET /idp/adapters/conformanceLogin | jq -c 'del(.attributeContract.extendedAttributes[]? | select(.name == "subject")) | del(.attributeMapping.attributeContractFulfillment.subject)')"
restore_adapter() { pf PUT /idp/adapters/conformanceLogin "$ADAPTER_ORIGINAL" >/dev/null; }
pf PUT /idp/adapters/conformanceLogin "$ADAPTER_ORIGINAL" >/dev/null; need 200 "resetting the login adapter"
sleep 2
code_flow "payment_initiation, login contract without subject (as the rig ships)" "$DETAIL_PAYMENT"
pf PUT /idp/adapters/conformanceLogin "$(jq -c '.attributeContract.extendedAttributes = ((.attributeContract.extendedAttributes // []) + [{name: "subject"}])
  | .attributeMapping.attributeContractFulfillment.subject = {source: {type: "EXPRESSION"}, value: "#this.get(\"username\")"}' <<<"$ADAPTER_ORIGINAL")" >/dev/null
need 200 "mapping subject on the login adapter"
sleep 2
code_flow "payment_initiation, login contract with subject" "$DETAIL_PAYMENT"
restore_adapter
echo; echo "── done: $(date -u +%Y-%m-%dT%H:%M:%SZ) on PingFederate $(pf GET /version | jq -r .version) with $(basename "$RAR_PLUGIN_JAR") ($(unzip -p "$RAR_PLUGIN_JAR" META-INF/MANIFEST.MF | sed -n 's/^Implementation-Version: *//p' | tr -d '\r'))"
