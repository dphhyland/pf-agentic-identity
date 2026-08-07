# PingFederate admin-API provider for the Azure demo PF, reached through a port-forward or the anchor
# PF's tunnel — same pattern as ../../gke-spiffe-demo/pf/terraform and ../../aws-bedrock-demo/pf/terraform.
# `terraform apply` writes to the RUNNING pod/container; afterwards export data.zip and bake it into the
# image so a restart keeps the config. Secrets come from the environment (TF_VAR_pf_admin_password).
provider "pingfederate" {
  https_host                          = var.pf_admin_host
  admin_api_path                      = "/pf-admin-api/v1"
  username                            = var.pf_admin_username
  password                            = var.pf_admin_password
  insecure_trust_all_tls              = true # demo PF serves a self-signed admin cert
  x_bypass_external_validation_header = true
}
