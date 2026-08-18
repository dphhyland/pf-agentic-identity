# PingFederate config-as-code (Terraform) — pingfederate-runtime (staging + production)

**The PF configuration is declarative Terraform in this repo, applied via the
`pingidentity/pingfederate` provider — never hand-poked through the admin console or REST API.** The
runtime PF is ephemeral (Railway, no volume): it boots its config from `../data.zip`. So the flow is

> **author `.tf` → `terraform apply` (to a running PF) → export `configArchive` → write
> `../data.<env>.zip` → commit `.tf` + `data.<env>.zip` → redeploy the image.**

`.tf` is the human-readable **source of truth**; `data.<env>.zip` (`data.staging.zip` /
`data.production.zip`) is the built **artifact** — `deploy-pingfederate.yml` copies the right one to
`data.zip` and the Dockerfile bakes it (via the drop-in-deployer). The image build + `railway up` rollout
stay Docker/CI — Terraform owns the *configuration*, not the licensed image.

**One module, two environments.** `var.environment` (`TF_VAR_environment=staging|production`) selects
the environment-specific values — today that is the PF **base URL** (`server-settings.tf`) — and names
the exported artifact. Everything else in the module is identical across environments by design.

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
| `pingfederate_server_settings` | the server **base URL** (per environment — see below) |

**Not managed here** (provider gap): the `rarPazProc` authorization-detail processor — the provider has
no `authorization_detail_processor` resource, so it stays an unmanaged carve-out inside `data.zip`.
**Excluded**: the runtime-registered dynamic client `…/e/prodtok-…` (OIDF §12.1 auto-registration —
regenerates; must not be pinned).

Files: `provider.tf`, `variables.tf`, `versions.tf`, `imports.tf` (adoption import blocks),
`access-token-mappings.tf` (the OIDF gate), `server-settings.tf` (the per-env base URL),
`attestation-demo-clients.tf` (the two hosted-attester demo clients, `demo-attest-inline` /
`demo-attest-vault`) + `extended-properties.tf` (the extended-property names they need — a
last-writer-wins singleton, adopt before applying), `helpers/` (credentialed id-list + archive export).

### The base URL (why `server-settings.tf` exists)

PF derives its OAuth `issuer`, the discovery/token-endpoint URLs, the audiences it accepts on a
`private_key_jwt` client assertion, **and** the OIDF module's entity-statement `iss`/`sub` at
`/.well-known/openid-federation` from **Server Settings → Federation Info → Base URL**. The first Phase-2
export was taken from the old EKS rig, so the archive carried that rig's ELB hostname
(`http://ae546b15c1b884e858e24d0c021d7e20-548341687.ap-southeast-2.elb.amazonaws.com`) — every environment
booted from it then advertised the ELB as issuer, rejected assertions with the real runtime as `aud`, and
the demo UI had to send the ELB as `PF_TOKEN_AUD` to get a token at all.

`server-settings.tf` pins the base URL per environment (`local.pf_base_urls` in `variables.tf`):

| environment | base URL |
|---|---|
| staging | `https://pingfederate-runtime-staging.up.railway.app` |
| production | `https://pingfederate-runtime-production.up.railway.app` |

Both are the services' Railway HTTP domains (port 9080). Change them there, never in the console.

## Prerequisites

```sh
export TF_VAR_environment=staging     # or production — picks the base URL + names data.<env>.zip
export TF_VAR_pf_admin_password='…'   # THAT environment's PF admin pwd (Railway env var; NEVER commit)
export TF_VAR_pf_admin_host='https://<that environment's pingfederate-runtime admin :9999 TCP-proxy host:port>'
```
`pf_admin_host` has NO default and must be a local tunnel endpoint (terraform rejects anything else —
the old default was a public admin proxy, now deleted). Open one per environment:

```sh
railway ssh config -p e02a8e2f-ff38-4043-836f-25d9e1c0f26b -s pingfederate-runtime -e staging --alias pf-staging-admin
ssh -N -L 19999:127.0.0.1:9999 pf-staging-admin      # production: 29999, -e production
export TF_VAR_pf_admin_host='https://localhost:19999'
```

For production
set it explicitly. Applying a staging `environment` against production's admin (or vice versa) writes the
wrong base URL into the wrong PF — check all three vars agree before Step 3.
Terraform ≥ 1.5 (for `import {}`). The assistant is blocked from handling the admin password, so every
step that touches PF (2–5) is **yours**; steps 0-arg, 1 and 6 need no PF admin credential.

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

**Base URL:** `pingfederate_server_settings.this` is authored (not generated), so the plan for it must be
a single in-place `~ update` of `federation_info.base_url` (ELB → this environment's runtime URL) and
`saml_2_entity_id` (`""` → same). A `+ create` means the import block didn't take; a `-/+ replace` means
stop and look. **Also grep `generated.tf` for the ELB** — the archive carries it in more than server
settings: `attestJwtATM` (*Issuer Claim Value*, twice) and `subjectJwtProc` (*Issuer*) were exported with
the ELB as their literal issuer, and the other JWT ATMs still name a retired host
(`pingfederate-production-cb0a.up.railway.app`). Replace those literals with `local.pf_base_url` when you
fold the generated bodies in, so the token `iss` and the base URL move together per environment.

## Step 3 — apply

```sh
terraform apply
```

## Step 3b — confirm the running PF now advertises the right issuer

`apply` writes to the RUNNING PF, so this is visible immediately (no redeploy needed):

```sh
curl -s https://pingfederate-runtime-staging.up.railway.app/.well-known/openid-configuration | jq -r .issuer
# expect: https://pingfederate-runtime-staging.up.railway.app   (production: …-production.up.railway.app)
curl -s https://pingfederate-runtime-staging.up.railway.app/.well-known/openid-federation | cut -d. -f2 | tr '_-' '/+' | jq -Rr '@base64d | fromjson | .iss'
# expect: the same URL — the entity statement iss follows PF's OAuth issuer
```

## Step 4 — export the artifact

```sh
./helpers/export-data-zip.sh    # GET configArchive/export -> ../data.<environment>.zip (+ refreshes ../data.zip)
```
The helper refuses an archive whose base URL is still the ELB.

## Step 5 — commit + redeploy

```sh
git add deploy/pingfederate/terraform/*.tf deploy/pingfederate/data.staging.zip   # or data.production.zip
# (generated.tf is gitignored — fold what you keep into the per-type .tf files first; ../data.zip is gitignored too)
# then rebuild+redeploy the image — CI (Actions → Deploy PingFederate → environment), or locally
# (--no-gitignore is what the workflow passes: without it railway up drops the gitignored modules/,
#  data.zip and overlay/ from the upload and the Docker build fails on its COPYs):
mvn -q -DskipTests package && deploy/pingfederate/build/stage-modules.sh
( cd deploy/pingfederate && railway up --detach --no-gitignore -s pingfederate-runtime -e staging )   # or production
```
Until the redeploy lands, the live PF already has the applied config (Step 3b) — but the NEXT restart of the
ephemeral service would boot the old archive, so don't leave Step 5 undone.

## Step 6 — restore the demo UI's `PF_TOKEN_AUD`

`pf-demo-ui` (Railway project `e02a8e2f-ff38-4043-836f-25d9e1c0f26b`) sends `PF_TOKEN_AUD` as the `aud` of
its `private_key_jwt`. Staging is currently pinned to the ELB **as a workaround for the stale base URL**;
once Step 3b shows the runtime URL as issuer, PF accepts the runtime token endpoint as `aud` and the
workaround must go — otherwise the assertion's `aud` no longer matches PF's issuer and token calls fail:

```sh
railway variables -p e02a8e2f-ff38-4043-836f-25d9e1c0f26b -e staging -s pf-demo-ui \
  --set "PF_TOKEN_AUD=https://pingfederate-runtime-staging.up.railway.app/as/token.oauth2"
```
(Same for production with `-e production` and the `…-production.up.railway.app` token endpoint. Use the
`https` origin — it must match the base URL PF now advertises; PF also accepts the bare issuer as `aud`.)

## Keep in sync

`trust_anchor` (variables.tf) MUST match the demo's `CFG.trust_controller` and pf-demo-ui's env — it's
the one federation-topology value baked into the gate criterion.

## Why config-as-code

A hand-poked change is unversioned and lost on the next ephemeral redeploy. With this module, a bad
config change is `git revert` + re-apply + re-export, not an incident — and prod's config is
reproducible from source instead of living only in a binary archive authored elsewhere.
