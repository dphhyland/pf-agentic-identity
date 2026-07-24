# Phase 2 client: demo-attest-gke-native — Google-native identity, no SPIRE.
#
# Evidence is the pod's PROJECTED service-account token (a serviceAccountToken volume with
# audience = attestation_issuer), validated against the GKE cluster's public OIDC JWKS fetched by URL.
# The verified `sub` (system:serviceaccount:demo:payment-agent) is mapped onto Google's canonical GKE
# SPIFFE ID — spiffe://<project>.svc.id.goog/ns/demo/sa/payment-agent — so the binding below uses the
# exact identifiers Google documents for workload identity.
#
# Created only when the Phase-2 variables are set (count guard), so Phase 1 applies cleanly first.

resource "pingfederate_oauth_client" "demo_attest_gke_native" {
  count = var.gcp_project_id == "" ? 0 : 1

  client_id                        = "demo-attest-gke-native"
  name                             = "Demo attester — GKE native identity"
  grant_types                      = ["CLIENT_CREDENTIALS"]
  client_auth                      = { type = "SECRET", secret = var.demo_attest_client_secret }
  restrict_scopes                  = false
  bypass_approval_page             = true
  persistent_grant_expiration_type = "SERVER_DEFAULT"

  extended_parameters = {
    attestation_issuer          = { values = [local.demo_attester_issuer] }
    attestation_evidence        = { values = ["gke-sa-token"] }
    attestation_trust_domain    = { values = ["${var.gcp_project_id}.svc.id.goog"] }
    attestation_bundle_url      = { values = [var.gke_jwks_uri] }
    attestation_evidence_issuer = { values = [var.gke_cluster_issuer] }
    attestation_instances = { values = [jsonencode([{
      spiffe_id   = "spiffe://${var.gcp_project_id}.svc.id.goog/ns/demo/sa/payment-agent"
      entitlement = [{ type = "sales_agent", actions = ["read_accounts", "create_opportunity", "submit_quote"], sales_regions = ["EMEA"] }]
      metadata    = { region = "EMEA", environment = "gke", attestor = "gke-workload-identity" }
    }])] }
    attestation_issued_ttl  = { values = ["300"] }
    attestation_required    = { values = ["true"] }
    attestation_signing_jwk = { values = [local.demo_inline_signing_jwk] }
  }

  depends_on = [pingfederate_extended_properties.props]
}
