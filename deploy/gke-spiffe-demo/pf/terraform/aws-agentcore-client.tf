# AWS Bedrock AgentCore client on the shared attester (one attester, many clouds).
#
# Evidence is an AWS-signed OIDC token from sts:GetWebIdentityToken (AWS Outbound Identity Federation),
# validated against the account issuer's public JWKS by AwsStsWebIdentityValidator. The token's sub is the
# agent's IAM role ARN; it maps to spiffe://<aws_trust_domain>/aws/<account>/role/agentcore-attest-demo.
#
# Demo-specific values for account 971422710168 (region ap-southeast-2). The account issuer comes from
# `aws iam enable-outbound-web-identity-federation`.

resource "pingfederate_oauth_client" "demo_attest_agentcore" {
  client_id                        = "demo-attest-agentcore"
  name                             = "Demo attester - Bedrock AgentCore agent"
  # TOKEN_EXCHANGE: agent B exchanges agent A's token here (the cross-cloud hop), attestation as client auth.
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
    attestation_evidence        = { values = ["aws-sts-web-identity"] }
    attestation_trust_domain    = { values = ["971422710168.aws.demo"] }
    attestation_bundle_url      = { values = ["https://a188ffe2-94b1-49e6-a35a-a937a3f68d5b.tokens.sts.global.api.aws/.well-known/jwks.json"] }
    attestation_evidence_issuer = { values = ["https://a188ffe2-94b1-49e6-a35a-a937a3f68d5b.tokens.sts.global.api.aws"] }
    attestation_instances = { values = [jsonencode([{
      spiffe_id   = "spiffe://971422710168.aws.demo/aws/971422710168/role/agentcore-attest-demo"
      entitlement = [{ type = "sales_agent", actions = ["read_accounts", "create_opportunity", "submit_quote"], sales_regions = ["EMEA"] }]
      metadata    = { region = "EMEA", environment = "agentcore", attestor = "aws-outbound-identity-federation" }
    }])] }
    attestation_issued_ttl  = { values = ["300"] }
    attestation_required    = { values = ["true"] }
    attestation_signing_jwk = { values = [local.demo_inline_signing_jwk] }
  }

  depends_on = [pingfederate_extended_properties.props]
}
