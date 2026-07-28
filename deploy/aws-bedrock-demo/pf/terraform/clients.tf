# The two AWS attestation clients. Both authenticate with attest_jwt_client_auth (the two attestation
# headers become the credential via ClientAttestationAuthFilter, backed by the shared bridge key), so
# client_auth is PRIVATE_KEY_JWT with the bridge public JWKS — identical to the GKE demo clients.
#
# The shared PF config (the attestJwtATM access-token manager, the client_credentials access-token mapping
# that stamps sub/act from the attestation, extended-property registration, server settings) is the same as
# deploy/gke-spiffe-demo/pf/terraform — copy those files in alongside these two, minus the GCP count guards.

locals {
  attester_issuer = "https://attester.example.com"
}

# 1. EKS workload — IRSA projected service-account token (eks-sa-token).
#    Evidence: the pod's projected SA token (audience = attester), signed by the EKS cluster OIDC issuer,
#    validated against the cluster's public JWKS at <issuer>/keys. sub system:serviceaccount:demo:payment-agent
#    maps to spiffe://<eks_trust_domain>/ns/demo/sa/payment-agent.
resource "pingfederate_oauth_client" "demo_attest_eks" {
  client_id                        = "demo-attest-eks"
  name                             = "Demo attester - EKS IRSA workload"
  grant_types                      = ["CLIENT_CREDENTIALS"]
  client_auth                      = { type = "PRIVATE_KEY_JWT" }
  jwks_settings                    = { jwks = var.bridge_public_jwks }
  restrict_scopes                  = false
  bypass_approval_page             = true
  persistent_grant_expiration_type = "SERVER_DEFAULT"

  default_access_token_manager_ref         = { id = "attestJwtATM" }
  restrict_to_default_access_token_manager = true

  extended_parameters = {
    attestation_issuer          = { values = [local.attester_issuer] }
    attestation_evidence        = { values = ["eks-sa-token"] }
    attestation_trust_domain    = { values = [var.eks_trust_domain] }
    attestation_bundle_url      = { values = [var.eks_jwks_url] }        # <cluster OIDC issuer>/keys
    attestation_evidence_issuer = { values = [var.eks_cluster_issuer] }
    attestation_instances = { values = [jsonencode([{
      spiffe_id   = "spiffe://${var.eks_trust_domain}/ns/demo/sa/payment-agent"
      entitlement = [{ type = "sales_agent", actions = ["read_accounts", "create_opportunity", "submit_quote"], sales_regions = ["EMEA"] }]
      metadata    = { region = "EMEA", environment = "eks", attestor = "eks-irsa" }
    }])] }
    attestation_issued_ttl  = { values = ["300"] }
    attestation_required    = { values = ["true"] }
    attestation_signing_jwk = { values = [var.attester_signing_jwk] }
  }

  depends_on = [pingfederate_extended_properties.props]
}

# 2. Bedrock AgentCore agent - sts:GetWebIdentityToken (aws-sts-web-identity).
#    Evidence: an AWS-signed OIDC JWT for the agent's IAM execution role, audience = attester, validated
#    against the account issuer's public JWKS. sub arn:aws:iam::<account>:role/<AgentExecutionRole> maps to
#    spiffe://<aws_trust_domain>/aws/<account>/role/<AgentExecutionRole>.
resource "pingfederate_oauth_client" "demo_attest_agentcore" {
  client_id                        = "demo-attest-agentcore"
  name                             = "Demo attester - Bedrock AgentCore agent"
  grant_types                      = ["CLIENT_CREDENTIALS"]
  client_auth                      = { type = "PRIVATE_KEY_JWT" }
  jwks_settings                    = { jwks = var.bridge_public_jwks }
  restrict_scopes                  = false
  bypass_approval_page             = true
  persistent_grant_expiration_type = "SERVER_DEFAULT"

  default_access_token_manager_ref         = { id = "attestJwtATM" }
  restrict_to_default_access_token_manager = true

  extended_parameters = {
    attestation_issuer          = { values = [local.attester_issuer] }
    attestation_evidence        = { values = ["aws-sts-web-identity"] }
    attestation_trust_domain    = { values = [var.aws_trust_domain] }
    attestation_bundle_url      = { values = [var.aws_sts_jwks_url] }    # <account issuer>/.well-known/jwks.json
    attestation_evidence_issuer = { values = [var.aws_sts_issuer] }
    attestation_instances = { values = [jsonencode([{
      spiffe_id   = "spiffe://${var.aws_trust_domain}/aws/${var.aws_account_id}/role/${var.agent_execution_role}"
      entitlement = [{ type = "sales_agent", actions = ["read_accounts", "create_opportunity", "submit_quote"], sales_regions = ["EMEA"] }]
      metadata    = { region = "EMEA", environment = "agentcore", attestor = "aws-outbound-identity-federation" }
    }])] }
    attestation_issued_ttl  = { values = ["300"] }
    attestation_required    = { values = ["true"] }
    attestation_signing_jwk = { values = [var.attester_signing_jwk] }
  }

  depends_on = [pingfederate_extended_properties.props]
}
