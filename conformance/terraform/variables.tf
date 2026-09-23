# ── admin API (the local authoring container only) ──────────────────────────────────────────────

variable "pf_admin_host" {
  description = "Admin API of the LOCAL authoring PingFederate, e.g. https://localhost:19999"
  type        = string

  validation {
    condition     = can(regex("^https://(localhost|127\\.0\\.0\\.1)(:[0-9]+)?$", var.pf_admin_host))
    error_message = "pf_admin_host must be a local endpoint. The rig's admin API is not exposed; author locally and ship the archive."
  }
}

variable "pf_admin_username" {
  description = "Admin username on the authoring PingFederate"
  type        = string
  default     = "administrator"
}

variable "pf_admin_password" {
  description = "Admin password on the authoring PingFederate (TF_VAR_pf_admin_password; never commit)"
  type        = string
  sensitive   = true
}

# ── the origin PF advertises ────────────────────────────────────────────────────────────────────

# PF derives its issuer, every endpoint in discovery and the audiences it accepts on a client
# assertion from this. The default is the PF ../up.sh runs on this machine. For a PF on a public
# address (a rig behind a TLS-passthrough proxy, say) set TF_VAR_pf_base_url to that origin BEFORE
# applying: it is baked into the archive, and a suite fails its first check if the issuer in discovery
# is not byte-for-byte the URL it fetched discovery from.
variable "pf_base_url" {
  description = "The origin PF advertises: https://host[:port], no trailing slash"
  type        = string
  default     = "https://localhost:9031"

  validation {
    condition     = can(regex("^https://[^/]+$", var.pf_base_url))
    error_message = "pf_base_url is an https origin with no path and no trailing slash."
  }
}

# ── the suites that will test it ────────────────────────────────────────────────────────────────

# Each suite redirects the browser back to <base>/test/a/<alias>/callback, and PF only redirects to a
# URI registered on the client. The hosted suite is where a certification run happens; the local one
# is for iterating without a login, and reaches the rig outbound like any other client.
variable "suite_base_urls" {
  description = "Origins of the conformance suites allowed as redirect targets"
  type        = list(string)
  default = [
    "https://www.certification.openid.net",
    "https://localhost.emobix.co.uk:9643",
  ]
}

variable "suite_alias" {
  description = "The alias in the suite configuration; part of every redirect URI"
  type        = string
  default     = "pf-agentic-identity"
}

# ── generated secrets (../secrets.env, written by ../gen-keys.sh) ───────────────────────────────

variable "test_user_password" {
  description = "Password of the one test user the suite signs in as"
  type        = string
  sensitive   = true
}

variable "ssf_emitter_client_secret" {
  description = "Secret of the client suite/trigger-caep-events.py raises CAEP events with (holds ssf.provision)"
  type        = string
  sensitive   = true
}

variable "ssf_introspection_client_secret" {
  description = "Secret of the client the SSF servlet introspects receiver tokens with (OIDF_SSF_INTROSPECTION_CLIENT_SECRET)"
  type        = string
  sensitive   = true
}
