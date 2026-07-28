# PingFederate admin-API provider for the EKS demo PF, reached through a port-forward:
#   kubectl --context <eks-context> -n pf port-forward svc/pingfederate <port>:9999
# NB: pick a local port that is actually free — Docker Desktop squats on localhost:9999.
# `terraform apply` writes to the RUNNING pod; afterwards export data.zip and bake it into the image
# so pod replacement keeps the config. Secrets come from the environment (TF_VAR_pf_admin_password).
provider "pingfederate" {
  https_host                          = var.pf_admin_host
  admin_api_path                      = "/pf-admin-api/v1"
  username                            = var.pf_admin_username
  password                            = var.pf_admin_password
  insecure_trust_all_tls              = true # demo PF serves a self-signed admin cert
  x_bypass_external_validation_header = true
}
