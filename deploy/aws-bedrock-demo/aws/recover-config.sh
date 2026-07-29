#!/usr/bin/env bash
# Rebuild a PingFederate's config from the Terraform in the current directory, on a server where
# NOTHING pre-exists — the from-zero recovery path described in ../RECOVERY.md.
#
# Why this script exists rather than "just run terraform apply": most resources carry an `import {}`
# block, because they were adopted from a running server. Terraform's import fails outright against a
# non-existent object — it does not fall back to creating one. So a from-zero apply aborts on the
# first missing object. This copies the config to a scratch directory, strips the import blocks, and
# applies there, leaving your real terraform directory and state untouched.
#
# Run it FROM the terraform directory you want to rebuild:
#   cd deploy/gke-spiffe-demo/pf/terraform && /path/to/recover-config.sh [--apply]
#
# Without --apply it plans only. Required environment is the same as a normal apply
# (TF_VAR_pf_admin_host, TF_VAR_pf_admin_password, PINGFEDERATE_PROVIDER_PRODUCT_VERSION, plus the
# per-cloud TF_VARs); the script tells you what is missing.
set -euo pipefail

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1
SRC="$(pwd)"
[ -n "$(ls *.tf 2>/dev/null)" ] || { echo "no .tf files here - run from a terraform directory" >&2; exit 1; }

: "${TF_VAR_pf_admin_host:?set TF_VAR_pf_admin_host, e.g. https://localhost:29991}"
: "${TF_VAR_pf_admin_password:?set TF_VAR_pf_admin_password}"
# The provider refuses to start without this, with an error that does not mention Terraform vars.
export PINGFEDERATE_PROVIDER_PRODUCT_VERSION="${PINGFEDERATE_PROVIDER_PRODUCT_VERSION:-13.0}"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cp "$SRC"/*.tf "$WORK/"
[ -f "$SRC/.terraform.lock.hcl" ] && cp "$SRC/.terraform.lock.hcl" "$WORK/"
cd "$WORK"

python3 - <<'PYEOF'
import glob, re
removed = 0
for f in glob.glob('*.tf'):
    s = open(f).read()
    s2, n = re.subn(r'import \{[^}]*\}\n*', '', s)
    if n:
        open(f, 'w').write(s2); removed += n
print(f"==> stripped {removed} import blocks (from-zero: nothing to adopt)")
PYEOF

echo "==> terraform init"
terraform init -input=false >/dev/null

echo "==> plan (empty state: everything should be a create)"
terraform plan -input=false -no-color -out=recover.plan > plan.txt 2>&1 || {
  grep -E "Error|error" plan.txt | head -20; exit 1; }
grep -E "will be created|Plan:" plan.txt | sed 's/^ *//'

if grep -qE "will be (updated|destroyed)" plan.txt; then
  echo
  echo "!! The plan is not purely creations. That means this PF already holds some of these objects," >&2
  echo "   so this is not a from-zero rebuild. Use the normal apply (with imports) instead." >&2
  exit 1
fi

if [ "$APPLY" != "1" ]; then
  cat <<'NOTE'

Plan only. Re-run with --apply to create these objects.

Two things to expect on apply:
  - PRIVATE_KEY_JWT clients throw a benign "Provider produced inconsistent result after apply".
    The admin API call SUCCEEDED; it is a provider read-back quirk on the sensitive block. Verify
    with GET /oauth/clients/<id> and move on.
  - attest_cc_mapping will FAIL: it references an access-token manager named attestATM that no
    Terraform resource manages. See the open gap in ../RECOVERY.md. Either create that ATM first
    or remove the mapping.
NOTE
  exit 0
fi

echo "==> apply"
set +e
terraform apply -input=false -no-color recover.plan > apply.txt 2>&1
STATUS=$?
set -e
grep -E "Creation complete|Apply complete" apply.txt | sed 's/^ *//' | head -20
if [ "$STATUS" != "0" ]; then
  echo
  echo "--- errors (check these against ../RECOVERY.md before assuming failure) ---"
  grep -A4 "^Error:" apply.txt | head -40
  echo
  echo "Benign: 'inconsistent result after apply' on PRIVATE_KEY_JWT clients - the change landed."
  echo "Real:   anything referencing attestATM - see the open gap in ../RECOVERY.md."
fi

cat <<'NOTE'

==> Next: export the archive and bake it, or the next pod replacement reverts everything.

  curl -sk -u administrator:$TF_VAR_pf_admin_password -H 'X-XSRF-Header: PingFederate' \
    -o data.zip "$TF_VAR_pf_admin_host/pf-admin-api/v1/configArchive/export"
  cp data.zip <repo>/deploy/pingfederate/data.zip
  # then rebuild + push the PF image and roll the deployment
NOTE
