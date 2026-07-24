# The client_credentials|attestATM issuance gate (adopted from the data.zip archive). Managing it here
# lets the demo (a) keep the gate under config-as-code like the main workspace does, and (b) swap the
# expression for diagnostics via var.attest_gate_expression without hand-editing the console.

variable "attest_gate_expression" {
  description = "OGNL issuance criterion for the attestATM client_credentials mapping"
  type        = string
  default     = "@com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils@validateClientAttestation(#this)"
}

import {
  to = pingfederate_oauth_access_token_mapping.attest_cc_mapping
  id = "client_credentials|attestATM"
}

resource "pingfederate_oauth_access_token_mapping" "attest_cc_mapping" {
  context = {
    type = "CLIENT_CREDENTIALS"
  }
  access_token_manager_ref = {
    id = "attestATM"
  }

  # Adopted verbatim from the archive on first import; only the gate is authored.
  attribute_contract_fulfillment = {
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
    "sub" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
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
