#!/usr/bin/env bash
# terraform fmt and validate over every tracked configuration, from the repository root: what build.yml's lint
# job runs, so a checkout gives the same answer.
#
# validate needs every file() a configuration reads to exist. conformance/terraform reads docs/extended-
# properties.json, which is tracked, and the suite clients' public JWKS under conformance/keys/, which gen-keys.sh
# generates and nothing commits. So validate runs on a copy of the configuration in a temporary directory, beside
# empty key sets standing in for the generated ones: the provider's schema, the attribute names and the variable
# references are what validate checks, and no key takes part. The copy carries the committed .terraform.lock.hcl
# and init is told to leave it as it is, so a provider the lock file does not record fails here instead of being
# fetched. To move the provider: change versions.tf, then in conformance/terraform
#   terraform init -backend=false -upgrade && terraform providers lock -platform=linux_amd64 -platform=linux_arm64 -platform=darwin_amd64 -platform=darwin_arm64
# and commit the lock file, which then records the build for Linux and macOS on either architecture, as
# conformance/README.md says.
set -euo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

git ls-files -z -- '*.tf' | xargs -0 -n1 dirname | sort -u | while IFS= read -r dir; do
  terraform fmt -check -diff -recursive "$dir"
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/conformance/terraform" "$TMP/conformance/keys" "$TMP/docs"
cp conformance/terraform/*.tf conformance/terraform/.terraform.lock.hcl "$TMP/conformance/terraform/"
cp docs/extended-properties.json "$TMP/docs/"
for name in fapi2-client1 fapi2-client2 ssf-receiver ciba-client1 ciba-client2; do
  echo '{"keys":[]}' > "$TMP/conformance/keys/$name.public.jwks.json"
done
terraform -chdir="$TMP/conformance/terraform" init -backend=false -input=false -lockfile=readonly >/dev/null
terraform -chdir="$TMP/conformance/terraform" validate
