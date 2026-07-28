# Agent C of the cross-cloud chain — a SECOND GKE workload with its own Kubernetes service account,
# so it resolves to its own client and appears as a distinct actor in the delegation chain.
#
# Without this, agents A and C share `demo-attest-gke-native` and the issued act chain reads
# {gke-native, {agentcore, {gke-native}}} — the two GCP hops are indistinguishable in an audit.
# Binding a separate SA (demo/delivery-agent) makes the chain {delivery, {agentcore, {payment}}}:
# three distinct identities, which is the point of carrying an actor chain at all.
#
# Its entitlement ceiling is deliberately NARROWER than the payment agent's: C may only settle and
# read, so a downstream resource can enforce "the last actor cannot do what the originator could".

resource "pingfederate_oauth_client" "demo_attest_gke_delivery" {
  count = var.gcp_project_id == "" ? 0 : 1

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
    attestation_issuer          = { values = [local.demo_attester_issuer] }
    attestation_evidence        = { values = ["gke-sa-token"] }
    attestation_trust_domain    = { values = ["${var.gcp_project_id}.svc.id.goog"] }
    attestation_bundle_url      = { values = [var.gke_jwks_uri] }
    attestation_evidence_issuer = { values = [var.gke_cluster_issuer] }
    attestation_instances = { values = [jsonencode([{
      spiffe_id   = "spiffe://${var.gcp_project_id}.svc.id.goog/ns/demo/sa/delivery-agent"
      entitlement = [{ type = "sales_agent", actions = ["read_accounts", "submit_quote"], sales_regions = ["EMEA"] }]
      metadata    = { region = "EMEA", environment = "gke", attestor = "gke-workload-identity", role = "delivery" }
    }])] }
    attestation_issued_ttl  = { values = ["300"] }
    attestation_required    = { values = ["true"] }
    attestation_signing_jwk = { values = [local.demo_inline_signing_jwk] }
  }

  depends_on = [pingfederate_extended_properties.props]
}
