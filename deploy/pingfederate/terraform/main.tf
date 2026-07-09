# PingFederate config-as-code for the OIDF federation plane (this repo's demo AS).
#
# DECLARATIVE SOURCE for the token-endpoint issuance criterion that enforces OpenID Federation:
# a client_credentials access-token mapping only issues when the presented private_key_jwt carries
# a valid Client Attestation OR a valid Trust Chain to the configured anchor. This is what makes the
# §12.1 automatic-registration + attestation flow gate correctly.
#
# The Railway PF is ephemeral (boots config from ../data.zip), so Terraform is the AUTHORING tool and
# the realised config is exported back into ../data.zip (the deploy artifact). See README.md.
#
# ISOLATION: this module targets pingfederate-runtime and, together with prune-agentic.tf, produces a
# data.zip that carries the OIDF plane ONLY — it removes the agentic urn:agent:* clients + the RFC 8693
# token-exchange plane that currently ride along from the shared idp-paz-authzen-adapter/demo/pingfederate
# data.zip. The exported archive becomes THIS repo's own deploy artifact.

provider "pingfederate" {
  https_host                          = var.pf_admin_host
  admin_api_path                      = "/pf-admin-api/v1"
  username                            = var.pf_admin_username
  password                            = var.pf_admin_password
  insecure_trust_all_tls              = true # demo PF serves a self-signed cert
  x_bypass_external_validation_header = true # don't run PF's connection-validation probes on apply
}

# --- Adopt the existing client_credentials access-token mapping(s) that carry the OIDF criterion ---
#
# There is one mapping per (CLIENT_CREDENTIALS context, access-token-manager). Get the real ids from
#   GET /oauth/accessTokenMappings        (id looks like "CLIENT_CREDENTIALS|<atmId>")
# then, on the FIRST run, capture their exact current bodies before editing:
#   terraform plan -generate-config-out=generated.tf
# Fold the generated body into oidf_cc_mapping below (keep the issuance_criteria authored here), and
# re-plan until the only diff is your intended change. Duplicate this resource + import block per ATM.

import {
  to = pingfederate_oauth_access_token_mapping.oidf_cc_mapping
  id = "CLIENT_CREDENTIALS|REPLACE_WITH_ATM_ID" # <-- confirm via GET /oauth/accessTokenMappings
}

resource "pingfederate_oauth_access_token_mapping" "oidf_cc_mapping" {
  context = {
    type = "CLIENT_CREDENTIALS"
  }
  # access_token_manager_ref.id must match the ATM referenced in the import id above.
  access_token_manager_ref = {
    id = "REPLACE_WITH_ATM_ID" # <-- confirm via GET /oauth/accessTokenMappings / generate-config-out
  }

  # Attribute contract fulfilment is captured verbatim from generate-config-out — do not hand-invent it.
  # (placeholder; replaced on first reconcile)
  attribute_contract_fulfillment = {}

  # THE OIDF GATE (the reason this is config-as-code): issue only if the request presents a valid
  # client attestation OR a trust chain that resolves to the anchor. Mirrors the OGNL that was
  # hand-set in data.zip's oauth-authz-server-settings.xml.
  issuance_criteria = {
    expression_criteria = [
      {
        error_result = "trust_validation_failed"
        expression   = "@${var.attestation_utils_class}@validateClientAttestation(#this) || @${var.federation_utils_class}@validateTrustChain(#this, false, '${var.trust_anchor}')"
      }
    ]
  }
}
