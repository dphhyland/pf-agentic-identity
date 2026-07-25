# Phase 3 client: demo-attest-agent-engine — a Vertex AI Agent Engine (Gemini Enterprise Agent
# Platform) agent, attested by the Google-signed ID token of its runtime service account.
#
# The agent's managed X.509 Agent Identity stays inside Google's fabric, but its service account can
# mint audience-scoped ID tokens (IAM Credentials generateIdToken on itself). Evidence is validated
# against Google's public JWKS and the `email` claim maps to spiffe://<trust_domain>/sa/<email> —
# the trust domain is a deployment convention here (Google defines no canonical SPIFFE mapping for
# bare service accounts). Works identically from Cloud Run / GCE.

resource "pingfederate_oauth_client" "demo_attest_agent_engine" {
  count = var.gcp_project_id == "" ? 0 : 1

  client_id                        = "demo-attest-agent-engine"
  name                             = "Demo attester — Agent Engine (GCP SA ID token)"
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
    attestation_issuer          = { values = [local.demo_attester_issuer] }
    attestation_evidence        = { values = ["gcp-id-token"] }
    attestation_trust_domain    = { values = ["${var.gcp_project_id}.gcp.banking.demo"] }
    attestation_bundle_url      = { values = ["https://www.googleapis.com/oauth2/v3/certs"] }
    attestation_evidence_issuer = { values = ["https://accounts.google.com"] }
    attestation_instances = { values = [jsonencode([{
      spiffe_id   = "spiffe://${var.gcp_project_id}.gcp.banking.demo/sa/agent-engine-demo@${var.gcp_project_id}.iam.gserviceaccount.com"
      entitlement = [{ type = "sales_agent", actions = ["read_accounts", "create_opportunity", "submit_quote"], sales_regions = ["EMEA"] }]
      metadata    = { region = "EMEA", environment = "agent-engine", attestor = "gcp-service-account" }
    }])] }
    attestation_issued_ttl  = { values = ["300"] }
    attestation_required    = { values = ["true"] }
    attestation_signing_jwk = { values = [local.demo_inline_signing_jwk] }
  }

  depends_on = [pingfederate_extended_properties.props]
}
