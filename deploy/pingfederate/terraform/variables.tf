# Admin-API connection. Secrets come from env (TF_VAR_pf_admin_password) — NEVER commit them.
#
# The admin console is NOT publicly reachable and must not become so again: it was exposed through a
# Railway TCP proxy whose hostname was the default of this very variable, so anyone with the repo had
# the address of an internet-facing PF admin API. Both admin proxies were deleted on 2026-08-20.
#
# Reach it privately instead, from the machine running terraform:
#     railway ssh config -p <project> -s pingfederate-runtime -e staging --alias pf-staging-admin
#     ssh -N -L 19999:127.0.0.1:9999 pf-staging-admin        # 29999 for production - distinct ports
#     export TF_VAR_pf_admin_host=https://localhost:19999
# (If the SSH gateway will not forward, the equivalent without -L is:
#     socat TCP-LISTEN:19999,bind=127.0.0.1,reuseaddr,fork \
#       EXEC:"railway ssh -p <project> -s pingfederate-runtime -e staging -- nc 127.0.0.1 9999")
#
# No defaults: an admin endpoint and account are per-environment and must be stated deliberately,
# and a wrong-environment apply is far more expensive than a missing-variable error.

variable "pf_admin_host" {
  description = "PingFederate admin API base — a LOCAL tunnel endpoint, e.g. https://localhost:19999. Never a public address."
  type        = string

  validation {
    # Not security (terraform runs on your machine), but a fat-finger guard: this variable used to
    # default to a public proxy, and re-pointing it at one would silently undo the exposure fix.
    condition     = can(regex("^https://(localhost|127\\.0\\.0\\.1)(:[0-9]+)?$", var.pf_admin_host))
    error_message = "pf_admin_host must be a local tunnel endpoint (https://localhost:PORT). Open one with `railway ssh` — see the comment above; the admin console is deliberately not internet-facing."
  }
}

variable "pf_admin_username" {
  description = "PingFederate admin username (set TF_VAR_pf_admin_username; no default — name the account you are using)"
  type        = string
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
