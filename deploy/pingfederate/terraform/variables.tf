# Admin-API connection. Secrets come from env (TF_VAR_pf_admin_password) — NEVER commit them.
# pingfederate-runtime's admin console (:9999) is now publicly reachable via its TCP proxy, so no
# ssh tunnel is needed — point pf_admin_host straight at it.

variable "pf_admin_host" {
  description = "PingFederate admin API base, e.g. the pingfederate-runtime admin TCP proxy"
  type        = string
  default     = "https://hayabusa.proxy.rlwy.net:39267"
}

variable "pf_admin_username" {
  description = "PingFederate admin username"
  type        = string
  default     = "administrator"
}

variable "pf_admin_password" {
  description = "PingFederate admin password (set via TF_VAR_pf_admin_password; never commit)"
  type        = string
  sensitive   = true
}

# Which pingfederate-runtime environment this apply targets. Selects the PF base URL (server-settings.tf)
# and names the exported artifact (helpers/export-data-zip.sh -> ../data.<environment>.zip). Set via
# TF_VAR_environment; the admin host/password above must point at the SAME environment's PF.
variable "environment" {
  description = "Target environment: staging | production"
  type        = string
  default     = "staging"
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be \"staging\" or \"production\"."
  }
}

# PF server-settings base URL — the runtime's PUBLIC origin. PF derives its OAuth issuer, its discovery /
# token-endpoint URLs, the private_key_jwt audiences it accepts, and (via OAuthIssuerUtils) the OIDF
# module's entity-statement `iss` from THIS value. The Phase-2 export that shipped before this resource
# existed carried the old EKS rig's ELB hostname here — hence the stale issuer/aud in every environment.
# Leave null to take the per-environment default below; override only for a rig this map doesn't know.
variable "pf_base_url" {
  description = "Override for the PF server-settings base URL (defaults per environment)"
  type        = string
  default     = null
}

locals {
  pf_base_urls = {
    staging    = "https://pingfederate-runtime-staging.up.railway.app"
    production = "https://pingfederate-runtime-production.up.railway.app"
  }
  pf_base_url = coalesce(var.pf_base_url, local.pf_base_urls[var.environment])
}

# The OpenID Federation trust anchor the runtime hook validates chains against. This is the ONLY
# federation-topology value baked into the issuance criterion; keep it in sync with the demo's
# CFG.trust_controller and the pf-demo-ui env.
variable "trust_anchor" {
  description = "OIDF trust anchor / controller base URL the trust-chain validator resolves against"
  type        = string
  default     = "https://lighthouse-staging-e017.up.railway.app"
}

# The OGNL hook classes from the pf-oidf-modules jar that the token-endpoint issuance criterion calls.
# (Static @Class@method() references — confirm against the live mapping body via generate-config-out.)
variable "attestation_utils_class" {
  type    = string
  default = "com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils"
}
variable "federation_utils_class" {
  type    = string
  default = "com.pingidentity.ps.oidf.servlet.clientregistration.utils.OIDFederationUtils"
}
