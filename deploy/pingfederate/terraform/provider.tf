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
  # PF serves a self-signed cert on the admin listener. Over the `railway ssh` tunnel the transport is
  # already authenticated and encrypted end-to-end by SSH, and the far end is 127.0.0.1 inside the
  # container - so this is trusting a certificate we reach through a channel we already trust, not
  # trusting the internet. It was NOT that before: the same flag was pointed at a public proxy, where
  # it meant the admin password was sent to whoever answered.
  insecure_trust_all_tls              = true
  x_bypass_external_validation_header = true # don't run PF's connection-validation probes on apply
}
