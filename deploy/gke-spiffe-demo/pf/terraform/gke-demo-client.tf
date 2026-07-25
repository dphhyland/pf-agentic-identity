# Phase 1 client: demo-attest-gke — a SPIRE-on-GKE workload's JWT-SVID is the evidence.
#
# Differences from the Railway demo clients (deploy/pingfederate/terraform/attestation-demo-clients.tf):
#   - trust domain gke.banking.demo, pinned via attestation_trust_domain (a REAL SPIRE domain, so the
#     "SPIRE replaced the browser-simulated SVID" story is visible in every decoded JWT);
#   - the bundle is SPIRE's JWT-authority JWKS (var.spire_bundle_jwks — pasted after helm install);
#   - the binding uses SPIRE's k8s registration shape: /ns/<namespace>/sa/<serviceaccount>.
# The signer stays the pre-trusted mock-attester-1 inline JWK so the minted attestation ALSO verifies
# at the token endpoint with zero image changes (oidf-mock-attesters.json already trusts it).

locals {
  demo_attester_issuer = "https://attester.example.com"

  # Same demo-only inline attester key as the Railway clients (public half is baked into
  # oidf-mock-attesters.json in the PF image).
  demo_inline_signing_jwk = jsonencode({
    kty = "EC", kid = "mock-attester-1", crv = "P-256",
    x   = "c2pTtxD_E2ZGIMam9QGsiDvlY57axE9Q9LKSnidQUag",
    y   = "ZI_wiUp0BUd_Gmi9412cAet7vBMhi4fkwclL_ujlTSI",
    d   = "9TAjv9_QP_mzZOn0NIWeERR_gtXjcqqj8KDp-XX-C84"
  })

  gke_spire_instances = jsonencode([{
    spiffe_id   = "spiffe://gke.banking.demo/ns/demo/sa/payment-agent"
    entitlement = [{ type = "sales_agent", actions = ["read_accounts", "create_opportunity", "submit_quote"], sales_regions = ["EMEA"] }]
    metadata    = { region = "EMEA", environment = "gke", attestor = "spire" }
  }])
}

# The attest_jwt_client_auth bridge public JWKS. The ClientAttestationAuthFilter in pf-runtime.war
# verifies the workload's OAuth-Client-Attestation headers, then authenticates to PF as this client with
# a private_key_jwt client_assertion signed by the bridge PRIVATE key (OIDF_BRIDGE_PRIVATE_JWK in the PF
# deployment). PF trusts that assertion because its public half is registered here. There is no client
# secret: the workload's only credential is the attestation.
variable "bridge_public_jwks" {
  description = "Public JWKS (JSON) of the attest_jwt_client_auth bridge key; private half is in the PF deployment env"
  type        = string
}

resource "pingfederate_oauth_client" "demo_attest_gke" {
  client_id                        = "demo-attest-gke"
  name                             = "Demo attester — SPIRE on GKE"
  grant_types                      = ["CLIENT_CREDENTIALS"]
  client_auth                      = { type = "PRIVATE_KEY_JWT" }
  jwks_settings                    = { jwks = var.bridge_public_jwks }
  restrict_scopes                  = false
  bypass_approval_page             = true
  persistent_grant_expiration_type = "SERVER_DEFAULT"

  # Issue JWT access tokens (decodable) rather than opaque reference tokens.
  default_access_token_manager_ref         = { id = "attestJwtATM" }
  restrict_to_default_access_token_manager = true

  extended_parameters = {
    attestation_issuer        = { values = [local.demo_attester_issuer] }
    attestation_spiffe_bundle = { values = [var.spire_bundle_jwks] }
    attestation_trust_domain  = { values = ["gke.banking.demo"] }
    attestation_instances     = { values = [local.gke_spire_instances] }
    attestation_issued_ttl    = { values = ["300"] }
    attestation_required      = { values = ["true"] }
    attestation_signing_jwk   = { values = [local.demo_inline_signing_jwk] }
  }

  depends_on = [pingfederate_extended_properties.props]
}
