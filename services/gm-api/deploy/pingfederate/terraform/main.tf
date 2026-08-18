# PingFederate config-as-code for the Grant Evaluation API demo.
#
# This is the declarative source for the PF side of the demo: the JWT access token
# manager, the scopes, the clients, and -- the one setting the Grant Management API
# will not work without -- atmIdForOAuthGrantManagement.
#
# Apply against a running PF:
#
#   export TF_VAR_pf_admin_password=2FederateM0re
#   terraform init && terraform validate && terraform apply
#
# Never make these changes through the admin console: they would be unversioned and
# lost the next time the container is recreated.

provider "pingfederate" {
  https_host                          = var.pf_admin_host
  admin_api_path                      = "/pf-admin-api/v1"
  username                            = var.pf_admin_username
  password                            = var.pf_admin_password
  product_version                     = var.pf_version
  insecure_trust_all_tls              = var.pf_insecure_tls # the demo PF serves a self-signed cert
  x_bypass_external_validation_header = true # don't run PF's connection-validation probes on apply
}

# The local docker rig serves a self-signed admin cert; anything else should not be trusted blindly.
variable "pf_insecure_tls" {
  description = "Trust any TLS cert on the PF admin API. Only for the local docker rig this module documents."
  type        = bool
  default     = false
}
