# The OIDF federation gate — the reason this module is config-as-code.
#
# A client_credentials access-token mapping only issues when the presented private_key_jwt carries a
# valid Client Attestation OR a valid Trust Chain to the configured anchor. This mirrors the OGNL that
# was hand-set in data.zip's oauth-authz-server-settings.xml, now authored declaratively.
#
# RECONCILE (first run, credentialed — see README §2): the attribute_contract_fulfillment below is a
# placeholder. Capture the live body by temporarily commenting out this resource, running
#   terraform plan -generate-config-out=generated.tf
# (which then generates it from the import{} block), folding generated attribute_contract_fulfillment
# back in here, and KEEPING the issuance_criteria authored below. Re-plan until the only diff is the gate.

import {
  to = pingfederate_oauth_access_token_mapping.oidf_cc_mapping
  # id = "CLIENT_CREDENTIALS|<atmId>". The attestation demo (rp.example.com) issues client_credentials
  # via attestATM, so this is almost certainly the mapping — CONFIRM via GET /oauth/accessTokenMappings
  # (helpers/list-config-ids.sh) before the first apply.
  id = "CLIENT_CREDENTIALS|attestATM"
}

resource "pingfederate_oauth_access_token_mapping" "oidf_cc_mapping" {
  context = {
    type = "CLIENT_CREDENTIALS"
  }
  access_token_manager_ref = {
    id = "attestATM" # must match the ATM in the import id above (confirm via generate-config-out)
  }

  # Captured verbatim from generate-config-out on first reconcile — do not hand-invent.
  attribute_contract_fulfillment = {}

  # THE OIDF GATE: issue only if the request presents a valid client attestation OR a trust chain that
  # resolves to the anchor.
  issuance_criteria = {
    expression_criteria = [
      {
        error_result = "trust_validation_failed"
        expression   = "@${var.attestation_utils_class}@validateClientAttestation(#this) || @${var.federation_utils_class}@validateTrustChain(#this, false, '${var.trust_anchor}')"
      }
    ]
  }
}
