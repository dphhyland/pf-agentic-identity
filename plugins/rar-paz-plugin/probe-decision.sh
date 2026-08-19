#!/usr/bin/env bash
# Probe the PingAuthorize governance-engine decision API with the request shape the
# pf-rar-paz-plugin sends (the governance-engine dialect — not the AuthZEN one). Confirms the
# wire contract + shared-secret auth before/while authoring policy.
#
# Keep the BODY below in step with GovernanceEngineRequestBuilder: if that builder gains or
# renames an attribute, this probe stops representing what the plugin actually sends.
#
# Usage:
#   harness: ./probe-decision.sh [PDP_URL] [SECRET] [HEADER]
#   defaults target the local docker-compose PDP (idpartners-authzen-ping-authorize).
set -euo pipefail

PDP_URL="${1:-https://localhost:8443/governance-engine}"
SECRET="${2:-2FederateM0re}"
HEADER="${3:-CLIENT_TOKEN}"   # PDP env JSON_API_HEADER_NAME (underscore)

# A sales_agent request for EMEA/create_opportunity, within the attested entitlement.
#
# Mirrors GovernanceEngineRequestBuilder exactly, including the flat req_<field> / att_<field>
# scalars it derives (space-joined; att_ is the union across the attested entitlement). Those
# are what the containment rule authored by paz/03-align-plugin-scalars.py actually reads —
# omit them and a correct policy returns INDETERMINATE, not PERMIT.
read -r -d '' BODY <<'JSON' || true
{
  "domain": "idpartners.authorization_details.sales_agent",
  "service": "Authorization",
  "action": "authorize",
  "attributes": {
    "UserID": "https://rp.example.com",
    "client_id": "https://rp.example.com",
    "idp.sales_agent.sales_regions": "[\"EMEA\"]",
    "idp.sales_agent.actions": "[\"create_opportunity\"]",
    "req_sales_regions": "EMEA",
    "req_actions": "create_opportunity",
    "att_sales_regions": "EMEA",
    "att_actions": "read_accounts create_opportunity submit_quote",
    "attestation.entitlement": "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"actions\":[\"read_accounts\",\"create_opportunity\",\"submit_quote\"]}]",
    "attestation.cnf_thumbprint": "demo-thumb"
  }
}
JSON

echo "POST ${PDP_URL}   (${HEADER}: ****)"
echo "--- request ---"; echo "${BODY}"
echo "--- response ---"
curl -sk -o /tmp/paz-decision.out -w "HTTP %{http_code}\n" -X POST "${PDP_URL}" \
  -H "Content-Type: application/json" -H "${HEADER}: ${SECRET}" \
  --data "${BODY}" || { echo "curl failed (is the PDP up on ${PDP_URL}?)"; exit 1; }
cat /tmp/paz-decision.out; echo
echo
echo "Tip: a fresh PDP with no matching policy returns decision=NOT_APPLICABLE / authorised=false —"
echo "that still proves the wire + auth work; author the policy in the PAP (https://localhost:7443) next."
