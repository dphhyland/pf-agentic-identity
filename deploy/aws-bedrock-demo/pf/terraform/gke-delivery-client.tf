# Agent C (the GKE delivery agent) must ALSO exist as a client here: C attests at its own local
# attester in GCP, but presents that attestation to THIS PF's token endpoint for the second exchange
# hop. The ClientAttestationAuthFilter resolves the client from the attestation's `sub` and then
# authenticates it to PF with the bridge private_key_jwt — so the client record has to be present on
# the AS being called, not only on the one that issued the attestation.
#
# The attestation_* properties mirror the GKE definition (same attester, same evidence contract) so
# the issuance gate evaluates identically on both sides of the federation.

locals {
  # The attester's signing key, as registered on this PF's other attestation clients.
  delivery_attester_signing_jwk = "{\"crv\":\"P-256\",\"d\":\"9TAjv9_QP_mzZOn0NIWeERR_gtXjcqqj8KDp-XX-C84\",\"kid\":\"mock-attester-1\",\"kty\":\"EC\",\"x\":\"c2pTtxD_E2ZGIMam9QGsiDvlY57axE9Q9LKSnidQUag\",\"y\":\"ZI_wiUp0BUd_Gmi9412cAet7vBMhi4fkwclL_ujlTSI\"}"
  gke_cluster_issuer            = "https://container.googleapis.com/v1/projects/pf-spiffe-demo-4412/locations/us-east1-b/clusters/spiffe-demo-e"
  attester_issuer               = "https://attester.example.com"
}

# Adopted: this client arrives via the baked config archive on any server built from the image.
# recover-config.sh strips this block so a from-zero rebuild creates it instead.
import {
  to = pingfederate_oauth_client.demo_attest_gke_delivery
  id = "demo-attest-gke-delivery"
}

resource "pingfederate_oauth_client" "demo_attest_gke_delivery" {
  client_id                        = "demo-attest-gke-delivery"
  name                             = "Demo attester — GKE delivery agent (chain agent C)"
  grant_types                      = ["CLIENT_CREDENTIALS", "TOKEN_EXCHANGE"]
  client_auth                      = { type = "PRIVATE_KEY_JWT" }
  jwks_settings                    = { jwks = var.bridge_public_jwks }
  restrict_scopes                  = false
  bypass_approval_page             = true
  persistent_grant_expiration_type = "SERVER_DEFAULT"

  default_access_token_manager_ref         = { id = "attestJwtATM" }
  restrict_to_default_access_token_manager = true

  extended_parameters = {
    attestation_issuer          = { values = [local.attester_issuer] }
    attestation_evidence        = { values = ["gke-sa-token"] }
    attestation_trust_domain    = { values = ["pf-spiffe-demo-4412.svc.id.goog"] }
    attestation_bundle_url      = { values = ["${local.gke_cluster_issuer}/jwks"] }
    attestation_evidence_issuer = { values = [local.gke_cluster_issuer] }
    attestation_instances = { values = [jsonencode([{
      spiffe_id   = "spiffe://pf-spiffe-demo-4412.svc.id.goog/ns/demo/sa/delivery-agent"
      entitlement = [{ type = "sales_agent", actions = ["read_accounts", "submit_quote"], sales_regions = ["EMEA"] }]
      metadata    = { region = "EMEA", environment = "gke", attestor = "gke-workload-identity", role = "delivery" }
    }])] }
    attestation_issued_ttl  = { values = ["300"] }
    attestation_required    = { values = ["true"] }
    attestation_signing_jwk = { values = [local.delivery_attester_signing_jwk] }
  }
}
