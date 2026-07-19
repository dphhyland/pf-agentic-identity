# PingFederate config-as-code (Terraform) — pingfederate-runtime (prod)

**The PF configuration is declarative Terraform in this repo, applied via the
`pingidentity/pingfederate` provider — never hand-poked through the admin console or REST API.** The
runtime PF is ephemeral (Railway, no volume): it boots its config from `../data.zip`. So the flow is

> **author `.tf` → `terraform apply` (to a running PF) → export `configArchive` → overwrite `../data.zip`
> → commit `.tf` + `data.zip` → redeploy the image.**

`.tf` is the human-readable **source of truth**; `data.zip` is the built **artifact** the Dockerfile
bakes (via the drop-in-deployer). The image build + `railway up` rollout stay Docker/CI — Terraform owns
the *configuration*, not the licensed image.

## What's modelled

This module adopts the **current live prod config** (enumerated from the running instance 2026-07-14):

| Terraform resource | live objects |
|---|---|
| `pingfederate_oauth_client` | `rp.example.com`, `northwind-webapp`, `urn:agent:northwind-{account,concierge,payments}:v1` |
| `pingfederate_oauth_access_token_manager` | `attestATM`, `attestJwtATM`, `attestJwtAcct`, `attestJwtPmts`, `userJwtATM` |
| `pingfederate_idp_token_processor` | `subjectJwtProc`, `subjectTokenProc` |
| `pingfederate_oauth_token_exchange_processor_policy` | `userToAgentTE` |
| `pingfederate_password_credential_validator` | `userpcv` |
| `pingfederate_idp_adapter` | `htmlform` |
| `pingfederate_oauth_access_token_mapping` | the OIDF client_credentials gate (authored) + the rest (enumerate) |

**Not managed here** (provider gap): the `rarPazProc` authorization-detail processor — the provider has
no `authorization_detail_processor` resource, so it stays an unmanaged carve-out inside `data.zip`.
**Excluded**: the runtime-registered dynamic client `…/e/prodtok-…` (OIDF §12.1 auto-registration —
regenerates; must not be pinned).

Files: `provider.tf`, `variables.tf`, `versions.tf`, `imports.tf` (adoption import blocks),
`access-token-mappings.tf` (the OIDF gate), `helpers/` (credentialed id-list + archive export).

## Prerequisites

```sh
export TF_VAR_pf_admin_password='…'   # PF admin pwd (Railway env var; NEVER commit)
export TF_VAR_pf_admin_host='https://<pingfederate-runtime admin :9999 TCP-proxy host:port>'
```
Terraform ≥ 1.5 (for `import {}`). The assistant is blocked from handling the admin password, so every
step that touches PF (2–5) is **yours**; steps 0-arg and 1 need no PF beyond what's noted.

## Step 0 — enumerate the real ids (confirm imports are complete)

```sh
./helpers/list-config-ids.sh    # lists clients / ATMs / mappings / policies / processors / adapters
```
Cross-check against `imports.tf`. Add an `import{}` per `accessTokenMapping` id it prints.

## Step 1 — init (no PF needed)

```sh
terraform init
```

## Step 2 — generate the exact live bodies (adopt, don't recreate)

```sh
terraform plan -generate-config-out=generated.tf
```
Terraform writes every imported object's current body into `generated.tf`. Review it. For the OIDF
mapping, fold the generated `attribute_contract_fulfillment` into `access-token-mappings.tf` and **keep
the authored `issuance_criteria`** (temporarily comment the `oidf_cc_mapping` resource so it generates,
then restore). Re-plan until the only diff is intended.

## Step 3 — apply

```sh
terraform apply
```

## Step 4 — export the artifact

```sh
./helpers/export-data-zip.sh    # GET configArchive/export -> ../data.zip
```

## Step 5 — commit + redeploy

```sh
git add deploy/pingfederate/terraform/*.tf deploy/pingfederate/terraform/generated.tf deploy/pingfederate/data.zip
# then rebuild+redeploy the image (data.zip is baked via the drop-in-deployer):
( cd deploy/pingfederate && railway up --detach -s pingfederate-runtime -e production )
```

## Keep in sync

`trust_anchor` (variables.tf) MUST match the demo's `CFG.trust_controller` and pf-demo-ui's env — it's
the one federation-topology value baked into the gate criterion.

## Why config-as-code

A hand-poked change is unversioned and lost on the next ephemeral redeploy. With this module, a bad
config change is `git revert` + re-apply + re-export, not an incident — and prod's config is
reproducible from source instead of living only in a binary archive authored elsewhere.
