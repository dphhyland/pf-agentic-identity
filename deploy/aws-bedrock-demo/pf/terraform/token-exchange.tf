# Cross-cloud RFC 8693 token exchange — the EKS PF side (P2 of the federation demo).
#
# This PF is the SECOND hop: agent C presents a token issued by the GKE PF (the anchor) as
# subject_token, authenticating with its own attestation. Validating that foreign token needs a JWT
# token processor pointed at the GKE PF's public JWKS — the same keys the federation anchor vouches
# for in its subordinate statement about the GKE PF (P1), so the JWKS URL here is exactly what a
# chain-resolving deployment would discover through /federation/fetch.
#
# The exchange plane (policy `userToAgentTE`, `subjectJwtProc`, the TE mapping onto attestJwtATM)
# shipped in this PF's data.zip; this file adopts it, mirroring the GKE side
# (deploy/gke-spiffe-demo/pf/terraform/token-exchange.tf — see there for the OGNL/act rationale).

variable "gke_pf_issuer" {
  description = "The GKE PF's public issuer / federation entity id (the anchor)"
  type        = string
  default     = "http://35.223.142.97"
}

# Validates subject tokens ISSUED BY THE GKE PF (cross-cloud hop). Presented with
# subject_token_type urn:ietf:params:oauth:token-type:jwt (the local access_token type stays on
# subjectJwtProc). The issued tokens carry no `iss` claim today, so the Issuer field is
# documentation until the ATMs stamp one; the signature check against the GKE JWKS is what gates.
# Adopted: present in the baked archive once this PF has been baked at least once.
import {
  to = pingfederate_idp_token_processor.gke_subject_proc
  id = "gkeSubjectProc"
}

resource "pingfederate_idp_token_processor" "gke_subject_proc" {
  processor_id = "gkeSubjectProc"
  name         = "Subject JWT Processor (GKE PF tokens)"

  plugin_descriptor_ref = { id = "org.sourceid.wstrust.processor.jwt.JWTTokenProcessor" }

  configuration = {
    fields = [
      { name = "Expiry Tolerance", value = "0" },
      { name = "Issuer", value = var.gke_pf_issuer },
      { name = "JWKS Endpoint URI", value = "${var.gke_pf_issuer}/pf/JWKS" },
      { name = "Preserve JWT Claim Types", value = "false" },
    ]
  }

  attribute_contract = {
    core_attributes = [{ name = "sub" }]
    extended_attributes = [
      { name = "acr" },
      { name = "act" },
      { name = "scope" },
    ]
  }
}

import {
  to = pingfederate_oauth_token_exchange_processor_policy.user_to_agent
  id = "userToAgentTE"
}

resource "pingfederate_oauth_token_exchange_processor_policy" "user_to_agent" {
  policy_id            = "userToAgentTE"
  name                 = "User-to-Agent Token Exchange"
  actor_token_required = false

  attribute_contract = {
    # core attribute `subject` is provider-managed (read-only); `prior_act` mirrors the GKE side.
    extended_attributes = [{ name = "act" }, { name = "prior_act" }]
  }

  # NB: list order matches what PF returns (foreign/jwt first) — the provider compares the list
  # positionally and flags a phantom "inconsistent result" if the order differs.
  processor_mappings = [
    {
      # Foreign tokens issued by the GKE PF — the cross-cloud hop.
      subject_token_type      = "urn:ietf:params:oauth:token-type:jwt"
      subject_token_processor = { id = pingfederate_idp_token_processor.gke_subject_proc.processor_id }
      attribute_contract_fulfillment = {
        "subject"   = { source = { type = "SUBJECT_TOKEN" }, value = "sub" }
        "act"       = { source = { type = "SUBJECT_TOKEN" }, value = "act" }
        "prior_act" = { source = { type = "SUBJECT_TOKEN" }, value = "act" }
      }
    },
    {
      # Local tokens (issued by THIS PF).
      subject_token_type      = "urn:ietf:params:oauth:token-type:access_token"
      subject_token_processor = { id = "subjectJwtProc" }
      attribute_contract_fulfillment = {
        "subject"   = { source = { type = "SUBJECT_TOKEN" }, value = "sub" }
        "act"       = { source = { type = "SUBJECT_TOKEN" }, value = "act" }
        "prior_act" = { source = { type = "SUBJECT_TOKEN" }, value = "act" }
      }
    },
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
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject"
    }
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
    # RFC 8693 delegation chain via the module helper — see the GKE twin for why plain OGNL cannot
    # reference policy contract attributes here.
    "act" = {
      source = { type = "EXPRESSION" }
      value  = "@com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils@delegationActChain(#this)"
    }
  }

  depends_on = [pingfederate_oauth_token_exchange_processor_policy.user_to_agent]
}
