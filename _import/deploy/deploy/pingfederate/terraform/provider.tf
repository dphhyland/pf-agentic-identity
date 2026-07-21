# PingFederate admin-API provider for pingfederate-runtime (prod, Railway project e02a8e2f).
#
# The provider talks to the admin API; `terraform apply` writes config to a RUNNING PF, and the
# realised config is exported back into ../data.zip (the deploy artifact — PF is ephemeral, no volume).
# Secrets come from the environment (TF_VAR_pf_admin_password); never commit them.
provider "pingfederate" {
  https_host                          = var.pf_admin_host
  admin_api_path                      = "/pf-admin-api/v1"
  username                            = var.pf_admin_username
  password                            = var.pf_admin_password
  insecure_trust_all_tls              = true # demo PF serves a self-signed cert
  x_bypass_external_validation_header = true # don't run PF's connection-validation probes on apply
}
