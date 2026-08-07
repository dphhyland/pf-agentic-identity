# Issue JWT access tokens (not opaque references) for the attestation demo clients, and fill their
# claims from the verified attestation context.
#
# PF ships two ATMs here: `attestATM` (Reference plugin — opaque `k7rj…` handles) and `attestJwtATM`
# (JWT bearer). The demo clients are pinned to the JWT one below so the token can be decoded and read.
#
# The OGNL expressions pull claims out of the presented Client Attestation, so the issued token names the
# client and (Phase 2.7) the attested instance's agent_id, without leaking cluster/workload topology into
# the token's primary sub claim — see the "sub" fulfillment entry below for the privacy fix this replaced.

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
    # Phase 2.7 privacy fix: this used to fall back through the attestation's spiffe_id claim (e.g.
    # "spiffe://gke-cluster.svc.id.goog/ns/demo/sa/payment-agent"), putting internal cluster/namespace/
    # service-account topology straight into the token's primary identity claim, readable by any holder.
    # sub is now always the client_id; agent_id below is the privacy-preserving way to name the specific
    # instance without exposing where it runs.
    "sub" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
    # The attester-minted per-instance identifier (Phase 2.1/2.2/2.6) — pseudonymous, opaque outside the
    # AgentRegistry, and the intended replacement for exposing the raw SPIFFE ID in the token. Empty string
    # (attestationClaim's own "not present" sentinel) omits the claim rather than emitting "".
    #
    # PREREQUISITE (operator step, not done by this file): attestJwtATM's attribute contract must declare
    # an "agent_id" extended attribute before this fulfillment entry can apply — that contract is captured
    # from the live server via `terraform plan -generate-config-out` into adopted-issuer.tf, per that
    # file's own "__generated__ … not hand-written" convention, not edited here. Add the extended attribute
    # via the PF admin console (or API) first, then regenerate adopted-issuer.tf.
    "agent_id" = {
      source = { type = "EXPRESSION" }
      value  = format(local.claim, "agent_id")
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
