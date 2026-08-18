#!/usr/bin/env bash
# Enumerate the real config-object ids from the LIVE pingfederate-runtime admin API, so the import{}
# blocks in ../imports.tf can be confirmed/completed. Credentialed — you supply the admin password;
# the assistant is blocked from handling it.
#
#   export TF_VAR_pf_admin_password='…'
#   export TF_VAR_pf_admin_host='https://<admin-tcp-proxy-host:port>'   # pingfederate-runtime :9999 proxy
#   ./helpers/list-config-ids.sh
#
# Requires: curl, jq.
set -euo pipefail
HOST="${TF_VAR_pf_admin_host:?set TF_VAR_pf_admin_host}"
PW="${TF_VAR_pf_admin_password:?set TF_VAR_pf_admin_password}"
case "${TF_VAR_pf_admin_host:-}" in
  https://localhost:*|https://127.0.0.1:*|https://localhost|https://127.0.0.1) ;;
  *) echo "TF_VAR_pf_admin_host must be a local tunnel endpoint (https://localhost:PORT); the PF admin" >&2
     echo "console is deliberately not internet-facing. Open a tunnel with 'railway ssh' - see" >&2
     echo "terraform/variables.tf. Got: '${TF_VAR_pf_admin_host:-<unset>}'" >&2
     exit 1 ;;
esac
USER="${TF_VAR_pf_admin_username:?set TF_VAR_pf_admin_username (no default - name the admin account)}"
A=(curl -sk -u "$USER:$PW" -H 'X-XSRF-Header: PingFederate' "$HOST/pf-admin-api/v1")

section() { printf '\n=== %s ===\n' "$1"; }

section "oauth/clients (id = client_id)"
"${A[@]}/oauth/clients" | jq -r '.items[].clientId'

section "oauth/accessTokenManagers (id)"
"${A[@]}/oauth/accessTokenManagers" | jq -r '.items[] | "\(.id)\t\(.name)"'

section "oauth/accessTokenMappings (id = CONTEXT|atmId) — needed for every mapping import"
"${A[@]}/oauth/accessTokenMappings" | jq -r '.items[].id'

section "oauth/tokenExchange/processor/policies (id)"
"${A[@]}/oauth/tokenExchange/processor/policies" | jq -r '.items[] | "\(.id)\t\(.name)"'

section "idp/tokenProcessors (id)"
"${A[@]}/idp/tokenProcessors" | jq -r '.items[] | "\(.id)\t\(.name)"'

section "idp/adapters (id)"
"${A[@]}/idp/adapters" | jq -r '.items[] | "\(.id)\t\(.name)"'

section "passwordCredentialValidators (id)"
"${A[@]}/passwordCredentialValidators" | jq -r '.items[] | "\(.id)\t\(.name)"'

section "oauth/authorizationDetailProcessors (UNMANAGED by TF — stays in data.zip)"
"${A[@]}/oauth/authorizationDetailProcessors" | jq -r '.items[] | "\(.id)\t\(.name)"' || true

echo
echo "Cross-check these against ../imports.tf. Add an import{} + resource per accessTokenMapping id."
