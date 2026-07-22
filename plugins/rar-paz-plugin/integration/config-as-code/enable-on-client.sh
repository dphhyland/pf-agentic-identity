#!/usr/bin/env sh
# Enable RAR (authorization_details) on an OAuth client so PingFederate routes the
# client's requested detail types through the processor instance, and shows the consent
# page (so the user approves the specific payment, not just a coarse scope).
#
# Patches the client with:
#   - restrictedAuthorizationDetailTypes: the RAR types this client may request
#   - bypassApprovalPage=false            : force the consent/approval page
#
# Usage:
#   ADMIN=https://localhost:9999 PF_USER=administrator PF_PASS=secret \
#   CLIENT_ID=my-webapp RAR_TYPES='["payment_initiation"]' \
#   ./enable-on-client.sh
#
# NOTE: field names on the client resource vary slightly by PF version — verify against
# $ADMIN/pf-admin-api/api-docs (search "authorizationDetail"). This GET-merge-PUT pattern
# avoids clobbering the rest of the client config.
set -eu
ADMIN="${ADMIN:-https://localhost:9999}"
PF_USER="${PF_USER:-administrator}"
: "${PF_PASS:?set PF_PASS}"
: "${CLIENT_ID:?set CLIENT_ID — the OAuth client that will request payment RAR}"
RAR_TYPES="${RAR_TYPES:-[\"payment_initiation\"]}"
AUTH="-u $PF_USER:$PF_PASS -H X-XSRF-Header:PingFederate"

# Fetch, merge the two fields with jq, PUT back.
cur=$(curl -sk $AUTH "$ADMIN/pf-admin-api/v1/oauth/clients/$CLIENT_ID")
echo "$cur" | jq \
  --argjson types "$RAR_TYPES" \
  '.restrictedAuthorizationDetailTypes = $types
   | .authorizationDetailTypesRestricted = true
   | .bypassApprovalPage = false' \
| curl -sk $AUTH -H 'Content-Type: application/json' \
    -X PUT "$ADMIN/pf-admin-api/v1/oauth/clients/$CLIENT_ID" -d @-
echo
