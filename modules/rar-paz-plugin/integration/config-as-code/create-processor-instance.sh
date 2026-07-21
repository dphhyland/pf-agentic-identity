#!/usr/bin/env sh
# Create the "Attestation-aware RAR to PingAuthorize" AuthorizationDetailProcessor
# instance in a RUNNING PingFederate via the admin API.
#
# The processor's config fields are exactly those declared by the plugin's
# getPluginDescriptor() (see AttestationAwareRarProcessor.java). Values below are the
# demo defaults — override via env vars. The processor DECLARES its supported RAR types
# in code (SUPPORTED_TYPES: sales_agent, payment_initiation, account_information), so no
# separate "register type" call is needed; you only enable them per-client (see
# enable-on-client.sh).
#
# Usage:
#   ADMIN=https://localhost:9999 PF_USER=administrator PF_PASS=secret \
#   PDP_URL=https://pingauthorize:1443/governance-engine PDP_SECRET=shhh \
#   ./create-processor-instance.sh
#
# NOTE: the admin-API path for authorization-detail processors can differ by PF version.
# Verify against your server's OpenAPI at  $ADMIN/pf-admin-api/api-docs  if you get a 404.
set -eu
ADMIN="${ADMIN:-https://localhost:9999}"
PF_USER="${PF_USER:-administrator}"
: "${PF_PASS:?set PF_PASS to the PF admin password}"
PDP_URL="${PDP_URL:?set PDP_URL — the PingAuthorize governance-engine decision endpoint}"
PDP_SECRET="${PDP_SECRET:-}"
INSTANCE_ID="${INSTANCE_ID:-rarPazProc}"
DOMAIN_PREFIX="${DOMAIN_PREFIX:-idpartners.authorization_details}"
ATTR_PREFIX="${ATTR_PREFIX:-idp}"
SECRET_HEADER="${SECRET_HEADER:-CLIENT-TOKEN}"
INSECURE_TLS="${INSECURE_TLS:-false}"

curl -sk -u "$PF_USER:$PF_PASS" -H 'X-XSRF-Header: PingFederate' -H 'Content-Type: application/json' \
  -X POST "$ADMIN/pf-admin-api/v1/oauth/authorizationDetailProcessors" -d @- <<JSON
{
  "id": "$INSTANCE_ID",
  "name": "Attestation-aware RAR to PingAuthorize",
  "pluginDescriptorRef": { "id": "com.pingidentity.ps.oidf.rar.AttestationAwareRarProcessor" },
  "configuration": {
    "fields": [
      { "name": "PDP URL",                        "value": "$PDP_URL" },
      { "name": "PDP Domain Prefix",              "value": "$DOMAIN_PREFIX" },
      { "name": "PDP Service",                    "value": "Authorization" },
      { "name": "PDP Action",                     "value": "authorize" },
      { "name": "Attribute Prefix",               "value": "$ATTR_PREFIX" },
      { "name": "Prefix Attributes with Type",    "value": "true" },
      { "name": "Shared Secret Header",           "value": "$SECRET_HEADER" },
      { "name": "Deny unless PERMIT",             "value": "true" },
      { "name": "Fail open on engine error",      "value": "false" },
      { "name": "Skip TLS verification (dev only)","value": "$INSECURE_TLS" },
      { "name": "Request timeout (ms)",           "value": "10000" }
    ],
    "sensitiveFields": [
      { "name": "Shared Secret", "value": "$PDP_SECRET" }
    ]
  }
}
JSON
echo   # POST returns the created instance JSON (or a validation error to fix)
