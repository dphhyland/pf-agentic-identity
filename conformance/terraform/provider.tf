# PingFederate is authored against a LOCAL stock PF and shipped as a config archive.
#
# This provider never points at a running deployment: a deployed PF exposes its runtime and not its
# admin API. It points at a stock PF 13.0.3 container on this machine (../author.sh), the realised
# config is exported as data.zip (../export.sh), and every PF built from this repo boots from that.
provider "pingfederate" {
  https_host     = var.pf_admin_host
  admin_api_path = "/pf-admin-api/v1"
  username       = var.pf_admin_username
  password       = var.pf_admin_password
  # The server is 13.0.3; the provider only uses this to decide which fields it may send.
  product_version = "13.0"
  # Self-signed, and on 127.0.0.1: variables.tf refuses any other host.
  insecure_trust_all_tls              = true
  x_bypass_external_validation_header = true
}
