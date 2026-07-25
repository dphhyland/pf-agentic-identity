# Issue JWT access tokens (not opaque references) for the attestation demo clients, and fill their
# claims from the verified attestation context.
#
# PF ships two ATMs here: `attestATM` (Reference plugin — opaque `k7rj…` handles) and `attestJwtATM`
# (JWT bearer). The demo clients are pinned to the JWT one below so the token can be decoded and read.
#
# The OGNL expressions pull claims out of the presented Client Attestation, so the issued token names the
# workload (its SPIFFE ID and which platform attested it), not just the client. A resource server holding
# this token can see which attested workload the call came from.

locals {
  # Reads a claim out of the presented Client Attestation. PF fulfils the attribute contract BEFORE it
  # runs issuance criteria, so the context validateClientAttestation publishes is not available yet —
  # this helper reads the attestation payload directly. Verification is still enforced by the
  # validateClientAttestation issuance criterion below, so no token is issued unless it verifies.
  claim = "@${var.attestation_utils_class}@attestationClaim(#this, \"%s\")"
}

import {
  to = pingfederate_oauth_access_token_mapping.attest_jwt_cc_mapping
  id = "client_credentials|attestJwtATM"
}

resource "pingfederate_oauth_access_token_mapping" "attest_jwt_cc_mapping" {
  context                  = { type = "CLIENT_CREDENTIALS" }
  access_token_manager_ref = { id = "attestJwtATM" }

  attribute_contract_fulfillment = {
    # The client the ATTESTER resolved this workload to (the attestation's sub).
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
    # The attested workload — its SPIFFE ID — falling back to the client id if the attestation
    # carried no workload claim.
    "sub" = {
      source = { type = "EXPRESSION" }
      value  = "${format(local.claim, "spiffe_id")} == \"\" ? #this.get(\"context.ClientId\").getValue() : ${format(local.claim, "spiffe_id")}"
    }
    # RFC 8693-style actor claim: the client acting, and which platform attested it.
    "act" = {
      source = { type = "EXPRESSION" }
      value  = "\"{\\\"sub\\\":\\\"\" + #this.get(\"context.ClientId\").getValue() + \"\\\",\\\"attested_by\\\":\\\"\" + ${format(local.claim, "attested_by")} + \"\\\"}\""
    }
  }

  issuance_criteria = {
    expression_criteria = [
      {
        error_result = "attestation_validation_failed"
        expression   = var.attest_gate_expression
      }
    ]
  }
}
