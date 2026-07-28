# Cross-cloud RFC 8693 token exchange (P2 of the federation demo).
#
# The exchange plane (policy `userToAgentTE`, the TE-context mapping onto attestJwtATM, and the
# `subjectJwtProc` JWT token processor) shipped in this PF's data.zip from the earlier agentic demo.
# This file ADOPTS those two objects and makes the delegation chain real:
#
#   - the policy exposes the subject token's `act` claim under a second contract name `prior_act`,
#     because PF 13.x rejects OGNL that references an attribute named `act` on an access-token
#     mapping (ognl_expression_invalid_attribute) — the legacy `act` attribute stays for the old
#     northwind mappings;
#   - the mapping's `act` claim becomes a real RFC 8693 delegation chain built by OGNL:
#     {"sub": <the exchanging client>, "act": <the subject token's chain, when present>}
#     — replacing the northwind-era hardcoded TEXT literal, which could never grow with new hops.
#
# `act` is emitted as a JSON *string* claim (consumers json-decode it), consistent with the
# client_credentials mapping in jwt-access-token.tf.

import {
  to = pingfederate_oauth_token_exchange_processor_policy.user_to_agent
  id = "userToAgentTE"
}

resource "pingfederate_oauth_token_exchange_processor_policy" "user_to_agent" {
  policy_id            = "userToAgentTE"
  name                 = "User-to-Agent Token Exchange"
  actor_token_required = false

  attribute_contract = {
    # core attribute `subject` is provider-managed (read-only).
    # `act` predates this file (northwind mappings); `prior_act` is the same claim under a name
    # OGNL is allowed to reference.
    extended_attributes = [{ name = "act" }, { name = "prior_act" }]
  }

  processor_mappings = [
    {
      subject_token_type      = "urn:ietf:params:oauth:token-type:access_token"
      subject_token_processor = { id = "subjectJwtProc" }
      attribute_contract_fulfillment = {
        "subject"   = { source = { type = "SUBJECT_TOKEN" }, value = "sub" }
        "act"       = { source = { type = "SUBJECT_TOKEN" }, value = "act" }
        "prior_act" = { source = { type = "SUBJECT_TOKEN" }, value = "act" }
      }
    }
  ]
}

import {
  to = pingfederate_oauth_access_token_mapping.attest_jwt_te_mapping
  id = "urn:ietf:params:oauth:grant-type:token-exchange|userToAgentTE|attestJwtATM"
}

resource "pingfederate_oauth_access_token_mapping" "attest_jwt_te_mapping" {
  context                  = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY", context_ref = { id = "userToAgentTE" } }
  access_token_manager_ref = { id = "attestJwtATM" }

  attribute_contract_fulfillment = {
    # The delegation subject: whoever the ORIGINAL token was issued for, carried through unchanged.
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject"
    }
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
    # RFC 8693 delegation: the exchanging client becomes the current actor; the subject token's
    # existing chain (if any) nests inside. Grows by one level per hop. Built by a module helper
    # because PF's mapping OGNL cannot reference token-exchange policy contract attributes (only
    # context.* — verified empirically: every policy-attribute spelling fails
    # ognl_expression_invalid_attribute). The helper reads the subject_token request parameter;
    # the token's validity is still enforced by the token-exchange processor.
    "act" = {
      source = { type = "EXPRESSION" }
      value  = "@${var.attestation_utils_class}@delegationActChain(#this)"
    }
  }

  depends_on = [pingfederate_oauth_token_exchange_processor_policy.user_to_agent]
}
