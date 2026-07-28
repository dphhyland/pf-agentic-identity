# Admin-API connection (via kubectl port-forward to PF on EKS). Secrets from env, never committed.

variable "pf_admin_host" {
  description = "PingFederate admin API base (the port-forward)"
  type        = string
  default     = "https://localhost:9999"
}

variable "pf_admin_username" {
  type    = string
  default = "administrator"
}

variable "pf_admin_password" {
  description = "PingFederate admin password (TF_VAR_pf_admin_password; same as the data.zip archive's)"
  type        = string
  sensitive   = true
}

# The bridge public JWKS (from the pf-bridge-key secret) registered on every attestation client so the
# ClientAttestationAuthFilter's private_key_jwt assertion validates. Same key as the GKE demo.
variable "bridge_public_jwks" {
  description = "Bridge public JWKS as inline JSON (TF_VAR_bridge_public_jwks)"
  type        = string
  default     = ""
}

# The attester's own signing key (mints the Client Attestation). Inline JWK. Not committed.
variable "attester_signing_jwk" {
  description = "Attester signing JWK as inline JSON (TF_VAR_attester_signing_jwk)"
  type        = string
  sensitive   = true
  default     = ""
}

# ── EKS IRSA path (eks-sa-token) ───────────────────────────────────────────────────────────────────
variable "eks_trust_domain" {
  description = "SPIFFE trust domain for EKS workloads (deployment convention, e.g. eks.demo.aws)"
  type        = string
  default     = "eks.demo.aws"
}

variable "eks_cluster_issuer" {
  description = "The EKS cluster OIDC issuer URL (aws eks describe-cluster --query cluster.identity.oidc.issuer)"
  type        = string
  default     = ""
}
variable "eks_jwks_url" {
  description = "The EKS cluster OIDC JWKS URL — the issuer URL with /keys appended (NOT /.well-known/jwks.json)"
  type        = string
  default     = ""
}

# ── AWS Outbound Identity Federation path (aws-sts-web-identity), incl. Bedrock AgentCore ───────────
variable "aws_account_id" {
  description = "The AWS account id (12 digits)"
  type        = string
  default     = ""
}
variable "aws_trust_domain" {
  description = "SPIFFE trust domain for AWS role identities (deployment convention, e.g. <account>.aws.demo)"
  type        = string
  default     = ""
}
variable "aws_sts_issuer" {
  description = "The account issuer from `aws iam enable-outbound-web-identity-federation` (https://<uuid>.tokens.sts.global.api.aws)"
  type        = string
  default     = ""
}
variable "aws_sts_jwks_url" {
  description = "The account issuer JWKS URL (<issuer>/.well-known/jwks.json)"
  type        = string
  default     = ""
}
variable "agent_execution_role" {
  description = "The Bedrock AgentCore agent's IAM execution role name (the sub in its web-identity token)"
  type        = string
  default     = ""
}
