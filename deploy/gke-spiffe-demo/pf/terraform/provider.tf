# PingFederate admin-API provider for the in-cluster demo PF.
#
# The admin API is reached through a port-forward from the laptop:
#   kubectl -n pf port-forward svc/pingfederate 9999:9999
# so pf_admin_host defaults to https://localhost:9999. `terraform apply` writes config to the RUNNING
# pod; afterwards export data.zip (helpers in ../../../pingfederate/terraform/helpers) and bake it into
# the image so restarts keep the config. Secrets come from the environment (TF_VAR_pf_admin_password).
provider "pingfederate" {
  https_host                          = var.pf_admin_host
  admin_api_path                      = "/pf-admin-api/v1"
  username                            = var.pf_admin_username
  password                            = var.pf_admin_password
  insecure_trust_all_tls              = true # demo PF serves a self-signed admin cert
  x_bypass_external_validation_header = true
}
