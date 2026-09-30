#!/usr/bin/env bash
# Probe a PingAuthorize governance-engine decision endpoint with the request shape the pf-rar-paz-plugin sends (the
# governance-engine dialect, not the AuthZEN one): confirms the wire contract and the shared-secret header before and
# while a policy is authored.
#
# Keep the BODY below in step with GovernanceEngineRequestBuilder: if that builder gains or renames an attribute, this
# probe stops representing what the plugin actually sends.
#
# Usage:
#   PAZ_PDP_SECRET_FILE=/path/to/secret ./probe-decision.sh [PDP_URL] [HEADER]
#   PAZ_PDP_SECRET=...                  ./probe-decision.sh [PDP_URL] [HEADER]
#
# The secret is the one the plugin's "Shared Secret" field holds: from PAZ_PDP_SECRET, or the file PAZ_PDP_SECRET_FILE
# names. There is no default, and the probe refuses to run without one. PDP_URL defaults to
# https://localhost:8443/governance-engine and HEADER to the plugin's default, CLIENT-TOKEN; a PDP configured with
# JSON_API_HEADER_NAME=CLIENT_TOKEN (underscore) wants that instead. The reference policies' own decision tests are
# paz/decision-tests.py.
#
# The PDP's certificate is verified: give its CA in PAZ_CA_FILE when a public CA did not issue it. Only a PDP on this
# machine (localhost, 127.0.0.1 or [::1]) is called without verification when PAZ_CA_FILE is unset, as the PingAuthorize
# image's self-signed certificate needs; the secret never goes unverified to another host.
set -euo pipefail

PDP_URL="${1:-https://localhost:8443/governance-engine}"
HEADER="${2:-CLIENT-TOKEN}"
if [[ -n "${PAZ_PDP_SECRET:-}" && -n "${PAZ_PDP_SECRET_FILE:-}" ]]; then
  echo "set PAZ_PDP_SECRET or PAZ_PDP_SECRET_FILE, not both" >&2; exit 2
fi
if [[ -n "${PAZ_PDP_SECRET_FILE:-}" ]]; then
  SECRET="$(cat "$PAZ_PDP_SECRET_FILE")"
else
  SECRET="${PAZ_PDP_SECRET:-}"
fi
if [[ -z "$SECRET" ]]; then
  echo "no PDP secret: set PAZ_PDP_SECRET, or PAZ_PDP_SECRET_FILE to a file holding it (the plugin's Shared Secret)" >&2
  exit 2
fi

TLS=()
if [[ -n "${PAZ_CA_FILE:-}" ]]; then
  TLS=(--cacert "$PAZ_CA_FILE")
else
  case "$PDP_URL" in
    https://localhost[:/]*|https://127.0.0.1[:/]*|https://\[::1\][:/]*) TLS=(-k) ;;
    https://*) ;;
    *) echo "PDP_URL must be https:// (got ${PDP_URL})" >&2; exit 2 ;;
  esac
fi

# A sales_agent request for EMEA/create_opportunity, within the attested entitlement.
#
# Mirrors GovernanceEngineRequestBuilder, including the flat req_<field> / att_<field> scalars it derives
# (space-joined; att_ is the union across the attested entitlement), which the reference sales_agent policy reads.
read -r -d '' BODY <<'JSON' || true
{
  "domain": "idpartners.authorization_details.sales_agent",
  "service": "Authorization",
  "action": "authorize",
  "attributes": {
    "idp.sales_agent.sales_regions": "[\"EMEA\"]",
    "idp.sales_agent.actions": "[\"create_opportunity\"]",
    "req_sales_regions": "EMEA",
    "req_actions": "create_opportunity",
    "att_sales_regions": "EMEA",
    "att_actions": "read_accounts create_opportunity submit_quote",
    "UserID": "https://rp.example.com",
    "principal_source": "client",
    "client_id": "https://rp.example.com",
    "attestation.entitlement": "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"actions\":[\"read_accounts\",\"create_opportunity\",\"submit_quote\"]}]",
    "attestation.cnf_thumbprint": "demo-thumb"
  }
}
JSON

OUT="$(mktemp)"; trap 'rm -f "$OUT"' EXIT
echo "POST ${PDP_URL}   (${HEADER}: ****)"
echo "--- request ---"; echo "${BODY}"
echo "--- response ---"
# The secret goes to curl on standard input as a header file, never on its command line.
printf '%s: %s\n' "$HEADER" "$SECRET" | curl -s ${TLS[@]+"${TLS[@]}"} -o "$OUT" -w "HTTP %{http_code}\n" -X POST "${PDP_URL}" \
  -H "Content-Type: application/json" -H @- --data "${BODY}" || { echo "curl failed (is the PDP up on ${PDP_URL}?)"; exit 1; }
cat "$OUT"; echo
echo
echo "A PDP with no matching policy answers decision=NOT_APPLICABLE / authorised=false - that still proves the wire and"
echo "the secret work; author the reference policies (paz/author-policies.py) next."
