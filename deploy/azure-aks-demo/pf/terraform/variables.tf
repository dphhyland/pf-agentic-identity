# Admin-API connection (via kubectl port-forward to PF on AKS, or the anchor PF's tunnel). Secrets from
# env, never committed. Same shape as ../../aws-bedrock-demo/pf/terraform/variables.tf.

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
# ClientAttestationAuthFilter's private_key_jwt assertion validates. Same key as the GKE/AWS demos.
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

# ── AKS Workload Identity Federation path (aks-sa-token) ────────────────────────────────────────────
variable "aks_trust_domain" {
  description = "SPIFFE trust domain for AKS workloads (deployment convention, e.g. aks.demo.azure)"
  type        = string
  default     = "aks.demo.azure"
}

variable "aks_cluster_issuer" {
  description = "The AKS cluster OIDC issuer URL (az aks show --query oidcIssuerProfile.issuerUrl)"
  type        = string
  default     = ""
}
variable "aks_jwks_url" {
  description = "The AKS cluster OIDC JWKS URL — the issuer URL with openid/v1/jwks appended"
  type        = string
  default     = ""
}

# ── Azure managed-identity path (azure-mi-token), for Container Apps / VM / Functions compute ──────
variable "azure_tenant_id" {
  description = "The Entra tenant id (the issuer/JWKS namespace for azure-mi-token evidence)"
  type        = string
  default     = ""
}
variable "azure_mi_trust_domain" {
  description = "SPIFFE trust domain for Azure managed identities (deployment convention, e.g. <tenant>.azure.demo)"
  type        = string
  default     = ""
}
variable "agent_execution_identity_oid" {
  description = "The gateway workload's managed-identity object id (the oid in its IMDS-obtained token) — the identity that hosts deploy/azure-aks-demo/agent-runtime/gateway.py when deployed to Container Apps rather than AKS"
  type        = string
  default     = ""
}

# ── Asserted-context (Entra Agent ID directory) opt-in ───────────────────────────────────────────────
# The directory data itself (OIDF_ENTRA_AGENT_DIRECTORY) is an ATTESTER-side environment variable, not a
# per-client PF property — see ../../README.md and servlets/attestation-issuer's
# EntraDirectoryAssertedContextResolver. This variable only controls whether the gateway CLIENT below opts
# in by naming the resolver; it does not carry the directory contents.
variable "enable_entra_asserted_context" {
  description = "Whether demo_attest_azure_gateway opts into the entra-directory AssertedContextResolver"
  type        = bool
  default     = true
}
