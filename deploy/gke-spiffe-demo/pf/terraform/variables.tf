# Admin-API connection (via kubectl port-forward). Secrets from env — NEVER commit them.

variable "pf_admin_host" {
  description = "PingFederate admin API base (the port-forward)"
  type        = string
  default     = "https://localhost:9999"
}

variable "pf_admin_username" {
  description = "PingFederate admin username"
  type        = string
  default     = "administrator"
}

variable "pf_admin_password" {
  description = "PingFederate admin password (TF_VAR_pf_admin_password; same as the data.zip archive's)"
  type        = string
  sensitive   = true
}

# ── Phase 1 (SPIRE) ──────────────────────────────────────────────────────────────────────────────

variable "spire_bundle_jwks" {
  description = <<-EOT
    The SPIRE trust domain's JWT-authority JWKS, pasted after SPIRE is up:
      kubectl exec -n spire-mgmt spire-server-0 -c spire-server -- \
        /opt/spire/bin/spire-server bundle show -format spiffe \
        | jq -c '{keys: [.keys[] | select(.use == "jwt-svid")]}'
    Leave the placeholder for the first apply (client created but not yet usable), then re-apply.
  EOT
  type        = string
  default     = "{\"keys\":[]}" # placeholder — issuance fails until the real bundle is pasted
}

# ── Phase 2 (Google-native) ──────────────────────────────────────────────────────────────────────

variable "gcp_project_id" {
  description = "The demo GCP project (trust domain = <project>.svc.id.goog)"
  type        = string
  default     = ""
}

variable "gke_cluster_issuer" {
  description = <<-EOT
    The GKE cluster's OIDC issuer URL, e.g.
      https://container.googleapis.com/v1/projects/<project>/locations/us-central1-a/clusters/spiffe-demo
  EOT
  type        = string
  default     = ""
}

variable "gke_jwks_uri" {
  description = "The cluster issuer's jwks_uri (curl <issuer>/.well-known/openid-configuration | jq -r .jwks_uri)"
  type        = string
  default     = ""
}

# The OGNL hook class from the merged module jar, used by the attestation gate and by the JWT
# access-token attribute mapping (attestationClaim).
variable "attestation_utils_class" {
  description = "FQCN of ClientAttestationUtils (OGNL hook)"
  type        = string
  default     = "com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils"
}
