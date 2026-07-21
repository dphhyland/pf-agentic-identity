#!/usr/bin/env bash
# Export the running PF's config archive into ../data.zip — the deploy artifact. Run AFTER
# `terraform apply`, so data.zip reflects the Terraform-authored config. Credentialed (your password).
#
#   export TF_VAR_pf_admin_password='…'
#   export TF_VAR_pf_admin_host='https://<admin-tcp-proxy-host:port>'
#   ./helpers/export-data-zip.sh
#
# Then commit BOTH the .tf changes and the regenerated ../data.zip, and redeploy the image
# (deploy/pingfederate — the Dockerfile bakes ../data.zip via the drop-in-deployer).
set -euo pipefail
HOST="${TF_VAR_pf_admin_host:?set TF_VAR_pf_admin_host}"
PW="${TF_VAR_pf_admin_password:?set TF_VAR_pf_admin_password}"
USER="${TF_VAR_pf_admin_username:-administrator}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/../data.zip"

curl -sk -u "$USER:$PW" -H 'X-XSRF-Header: PingFederate' \
  -o "$OUT" "$HOST/pf-admin-api/v1/configArchive/export"

if command -v unzip >/dev/null && unzip -tq "$OUT" >/dev/null 2>&1; then
  echo "exported $(wc -c < "$OUT") bytes -> $OUT ($(unzip -l "$OUT" | tail -1 | awk '{print $2}') files)"
else
  echo "WARNING: exported $OUT is not a valid zip — check the admin host/credentials"; exit 1
fi
