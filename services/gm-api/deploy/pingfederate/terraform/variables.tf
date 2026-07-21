# Admin-API connection. Secrets come from the environment (TF_VAR_*), never from here.

variable "pf_admin_host" {
  description = "PingFederate admin API base URL"
  type        = string
  default     = "https://localhost:9199"
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

# The provider gates which fields it will send by product version, so this must
# match the running server (GET /pf-admin-api/v1/version).
variable "pf_version" {
  description = "PingFederate product version"
  type        = string
  default     = "13.0"
}

# The issuer PF stamps into tokens.
#
# The container publishes its runtime on host port 9131, but PF's own base URL -- and
# therefore the iss claim -- is whatever is configured here. The GM API's TOKEN_ISSUER
# must match this exactly, while its JWKS_URL uses the host port it can actually reach.
# The two being different is normal for a port-mapped container, and is why the GM API
# keeps them as separate settings.
variable "pf_issuer" {
  description = "Issuer claim value stamped into access tokens"
  type        = string
  default     = "https://localhost:9031"
}

variable "gm_audience" {
  description = "Audience claim value for tokens destined for the Grant Management API"
  type        = string
  default     = "https://gm-api.demo/grants"
}

variable "gm_api_client_secret" {
  description = "Secret for the gm-api client (set via TF_VAR_gm_api_client_secret)"
  type        = string
  sensitive   = true
}

variable "tpp_client_secret" {
  description = "Secret for the acme-budgeting client (set via TF_VAR_tpp_client_secret)"
  type        = string
  sensitive   = true
}

variable "gm_service_username" {
  description = "Username the GM API uses for PF's OAuth Administrative Web Service"
  type        = string
  default     = "gm-api-service"
}

variable "gm_service_password" {
  description = "Password for the GM API service account (set via TF_VAR_gm_service_password)"
  type        = string
  sensitive   = true
}

# The demo cast. Their entitlements are in policy/entitlements.yaml, which the PDP
# reads -- PingFederate holds only their identity and their grants.
variable "demo_users" {
  description = "Usernames to create for the demo"
  type        = list(string)
  default     = ["alice", "bob", "carol"]
}

variable "demo_user_password" {
  description = "Shared password for the demo users (set via TF_VAR_demo_user_password)"
  type        = string
  sensitive   = true
}
