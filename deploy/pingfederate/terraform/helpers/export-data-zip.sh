#!/usr/bin/env bash
# Export the running PF's config archive into the per-environment deploy artifact
# ../data.<environment>.zip. NEVER COMMIT THE RESULT. A PF configArchive is a plain zip that contains
# pf.jwk (the master key), pingfederate-system-keys.xml, both keystores, the admin password hash and
# master-key-reversible client secrets — PF obfuscates individual VALUES with the master key and then
# ships the key alongside them, so "encrypted, therefore safe to commit" (what this header used to
# claim) is false. Everything data*.zip is git-ignored and CI fails if one is ever tracked.
# Also refreshes ../data.zip so a local `railway up` from deploy/pingfederate bakes the same thing.
# Run AFTER `terraform apply`, so the archive reflects the Terraform-authored config — including the
# server-settings base URL for THIS environment. Credentialed (your password).
#
#   export TF_VAR_pf_admin_password='…'
#   export TF_VAR_pf_admin_host='https://<admin-tcp-proxy-host:port>'   # the SAME env's PF admin
#   export TF_VAR_environment=staging          # or production (default: staging)
#   ./helpers/export-data-zip.sh
#
# Then commit the .tf changes + ../data.<environment>.zip, and redeploy the image.
set -euo pipefail
HOST="${TF_VAR_pf_admin_host:?set TF_VAR_pf_admin_host}"
PW="${TF_VAR_pf_admin_password:?set TF_VAR_pf_admin_password}"
USER="${TF_VAR_pf_admin_username:-administrator}"
ENVIRONMENT="${TF_VAR_environment:-staging}"
case "$ENVIRONMENT" in staging|production) ;; *) echo "TF_VAR_environment must be staging|production (got '$ENVIRONMENT')"; exit 2;; esac
DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$DIR/data.$ENVIRONMENT.zip"

curl -sk -u "$USER:$PW" -H 'X-XSRF-Header: PingFederate' \
  -o "$OUT" "$HOST/pf-admin-api/v1/configArchive/export"

if command -v unzip >/dev/null && unzip -tq "$OUT" >/dev/null 2>&1; then
  echo "exported $(wc -c < "$OUT") bytes -> $OUT ($(unzip -l "$OUT" | tail -1 | awk '{print $2}') files)"
else
  echo "WARNING: exported $OUT is not a valid zip — check the admin host/credentials"; rm -f "$OUT"; exit 1
fi
cp "$OUT" "$DIR/data.zip"
echo "copied -> $DIR/data.zip (git-ignored local build input)"

# Sanity: the base URL PF will advertise from this archive. Anything *.elb.amazonaws.com here means the
# server-settings apply didn't land (wrong host? plan not applied?) — don't ship it.
if command -v unzip >/dev/null; then
  BASE="$(unzip -p "$OUT" sourceid-saml2-local-metadata.xml 2>/dev/null | grep -o 'BaseURL="[^"]*"' | head -1)"
  echo "server-settings ${BASE:-BaseURL not found}"
  case "$BASE" in *elb.amazonaws.com*) echo "ERROR: archive still carries the stale ELB base URL"; exit 1;; esac
fi
