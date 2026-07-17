#!/usr/bin/env bash
#
# Every Grant Management operation, against a real PingFederate, end to end.
#
# Shows the two token shapes that matter for integration:
#   - authorization code    a user is present
#   - client credentials    a TPP with a standing consent and no user   <- Open Banking
#
# and the decisions that make the API worth having: a valid consent that no longer
# grants access, because the subject stopped holding the resource.
#
#   ./walkthrough.sh
#
# Env (all optional; defaults match the demo in deploy/pingfederate):
#   PF        PingFederate runtime          https://localhost:9131
#   GM        Grant Management base         $PF/gm-api
#   CLIENT_ID / CLIENT_SECRET               acme-budgeting / (from .env)
#   USERNAME  / PASSWORD                    alice / 2FederateM0re
set -uo pipefail

PF="${PF:-https://localhost:9131}"
GM="${GM:-$PF/gm-api}"
CLIENT_ID="${CLIENT_ID:-acme-budgeting}"
USERNAME="${USERNAME:-alice}"
PASSWORD="${PASSWORD:-2FederateM0re}"
REDIRECT="${REDIRECT:-http://localhost:8081/callback}"

if [ -z "${CLIENT_SECRET:-}" ]; then
  echo "Set CLIENT_SECRET (see deploy/pingfederate/terraform/terraform.tfvars)." >&2
  exit 1
fi

# The demo PF serves a self-signed cert. -k is for the demo, not for you.
CURL=(curl -sk)
bold() { printf '\n\033[1m%s\033[0m\n' "$1"; }
jqp() { python3 -m json.tool 2>/dev/null || cat; }

claim() { # claim <jwt> <name>
  python3 - "$1" "$2" <<'PY'
import base64, json, sys
p = sys.argv[1].split(".")[1]; p += "=" * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p)).get(sys.argv[2], "") or "")
PY
}

decision() { python3 -c '
import sys, json
d = json.load(sys.stdin)
r = (d.get("context") or {}).get("reasons") or [{}]
print(("PERMIT" if d.get("decision") else "DENY  "), "|", r[0].get("id",""), "|", r[0].get("message",""))
' 2>/dev/null || echo "(no decision)"; }

# ---------------------------------------------------------------------------
bold "1. Alice consents (authorization code). This creates the grant."
# ---------------------------------------------------------------------------
# Scripted browser: authorize -> sign in -> approve -> exchange the code.
# Do NOT ask for `openid` here: the demo PF has no OIDC policy and will 500.
JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT
AUTHZ="$PF/as/authorization.oauth2?client_id=$CLIENT_ID&response_type=code\
&scope=accounts.read%20grant_management_query%20grant_management_revoke%20grant_management_evaluate\
&redirect_uri=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$REDIRECT")&state=demo"

FORM=$("${CURL[@]}" -c "$JAR" "$AUTHZ")
ACTION=$(printf '%s' "$FORM" | grep -oE '<form[^>]*action="[^"]+"' | head -1 | sed 's/.*action="//;s/"//')
APPROVAL=$("${CURL[@]}" -b "$JAR" -c "$JAR" --data-urlencode "pf.username=$USERNAME" \
  --data-urlencode "pf.pass=$PASSWORD" --data-urlencode 'pf.ok=clicked' "$PF$ACTION")

# The approval form's CSRF token must come from THIS render, and each
# authorization_details entry has an opaque handle that must be echoed back —
# omit it and PF issues the grant with no RAR at all, silently.
CSRF=$(printf '%s' "$APPROVAL" | grep -oE 'name="cSRFToken"[^>]*value="[^"]*"' | sed 's/.*value="//;s/"//')
AD=$(printf '%s' "$APPROVAL" | grep -oE 'name="authorization_details"[^>]*value="[^"]*"' | sed 's/.*value="//;s/"//')
ACTION2=$(printf '%s' "$APPROVAL" | grep -oE '<form[^>]*action="[^"]+"' | head -1 | sed 's/.*action="//;s/"//')

ARGS=(--data-urlencode 'check-user-approved-scope=true'
      --data-urlencode 'scope=accounts.read'
      --data-urlencode 'scope=grant_management_query'
      --data-urlencode 'scope=grant_management_revoke'
      --data-urlencode 'scope=grant_management_evaluate'
      --data-urlencode "cSRFToken=$CSRF"
      --data-urlencode 'pf.oauth.authz.consent=allow')
[ -n "$AD" ] && ARGS+=(--data-urlencode "authorization_details=$AD")

LOCATION=$("${CURL[@]}" -b "$JAR" -c "$JAR" -D - -o /dev/null "${ARGS[@]}" "$PF$ACTION2" \
  | grep -i '^location:' | tr -d '\r' | sed 's/^[Ll]ocation: //')
CODE=$(printf '%s' "$LOCATION" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
if [ -z "$CODE" ]; then echo "   FAILED: $LOCATION" >&2; exit 1; fi

TOKENS=$("${CURL[@]}" -X POST "$PF/as/token.oauth2" -d grant_type=authorization_code \
  -d "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT" \
  -d "client_id=$CLIENT_ID" -d "client_secret=$CLIENT_SECRET")
USER_TOKEN=$(printf '%s' "$TOKENS" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))')

GRANT=$(claim "$USER_TOKEN" agid)
echo "   subject:  $(claim "$USER_TOKEN" sub)"
echo "   grant id: $GRANT      <- the 'agid' claim; PF's way of naming your own grant"
echo "   note:     the token response has no 'grant_id' field. PF does not implement spec 5."

# ---------------------------------------------------------------------------
bold "2. Query the grant  (GET, scope: grant_management_query)"
# ---------------------------------------------------------------------------
"${CURL[@]}" -H "Authorization: Bearer $USER_TOKEN" "$GM/grants/$GRANT" | jqp

# ---------------------------------------------------------------------------
bold "3. Evaluate  (POST, scope: grant_management_evaluate)"
# ---------------------------------------------------------------------------
ev() { # ev <account> <action> <label>
  printf '   %-42s ' "$3"
  "${CURL[@]}" -X POST "$GM/grants/$GRANT/evaluate" \
    -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"action\":{\"name\":\"$2\"},\"resource\":{\"type\":\"account\",\"id\":\"$1\"}}" | decision
}
ev 111 read_balance      "111 read_balance   consent+ holds+"
ev 222 read_balance      "222 read_balance   consent+ holds-"
ev 444 read_balance      "444 read_balance   consent+ view"
ev 444 read_transactions "444 read_transact  consent+ right-"
ev 999 read_balance      "999 read_balance   consent-"
echo
echo "   The middle two are the point: the grant is valid and names those accounts."
echo "   Alice closed 222 and is only a view-only signatory on 444. A token"
echo "   introspection cannot see either."

# ---------------------------------------------------------------------------
bold "4. The same, with NO user  (client credentials)  <- Open Banking"
# ---------------------------------------------------------------------------
# A TPP holding a standing consent, asking before it spends a refresh token.
CC=$("${CURL[@]}" -X POST "$PF/as/token.oauth2" -d grant_type=client_credentials \
  --data-urlencode 'scope=grant_management_evaluate' \
  -u "$CLIENT_ID:$CLIENT_SECRET" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))')

if [ -z "$CC" ]; then
  echo "   client_credentials not permitted for $CLIENT_ID (needs the grant type + scope registered)"
else
  HAS_SUB=$(claim "$CC" sub)
  echo "   token subject: '${HAS_SUB:-<none>}'   <- no sub at all, and none is needed:"
  echo "                                            the subject comes off the grant (spec 8.4.1)"
  printf '   %-42s ' "111 read_balance"
  "${CURL[@]}" -X POST "$GM/grants/$GRANT/evaluate" -H "Authorization: Bearer $CC" \
    -H 'Content-Type: application/json' \
    -d '{"action":{"name":"read_balance"},"resource":{"type":"account","id":"111"}}' | decision
fi

# ---------------------------------------------------------------------------
bold "5. Revoke  (DELETE, scope: grant_management_revoke)"
# ---------------------------------------------------------------------------
printf '   DELETE -> HTTP '
"${CURL[@]}" -o /dev/null -w '%{http_code}\n' -X DELETE "$GM/grants/$GRANT" \
  -H "Authorization: Bearer $USER_TOKEN"
printf '   %-42s ' "111 read_balance, after revocation"
"${CURL[@]}" -X POST "$GM/grants/$GRANT/evaluate" -H "Authorization: Bearer $USER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"action":{"name":"read_balance"},"resource":{"type":"account","id":"111"}}' | decision
echo
echo "   Revocation bites on the next evaluation. No token had to expire."

bold "Done."
echo "Reason ids to branch on, and the retry/no-retry split: docs/INTEGRATING.md section 5."
