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
