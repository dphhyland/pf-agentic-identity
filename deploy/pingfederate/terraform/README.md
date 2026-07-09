# OIDF PingFederate — config-as-code + isolation from the agentic deploy

Makes `pingfederate-runtime` (the demo AS in Railway project `e02a8e2f`) **config-as-code** and
**isolated**: its PF config becomes declarative Terraform + an OIDF-only `data.zip`, dropping the
agentic `urn:agent:*` clients and the RFC 8693 token-exchange plane that currently ride along from the
*shared* `idp-paz-authzen-adapter/demo/pingfederate/data.zip`.

Why the bleed exists today: both this PF and the agentic-banking PF build from the **same** deploy
context, so that context's `data.zip` (3 agent clients + token-exchange, authored by
`idp-paz-authzen-adapter/demo/pingfederate/terraform`) is baked into both. This module gives the OIDF PF
its **own** source + artifact.

## Status

- **Phase 1 — DONE (this module):** the declarative source for the OIDF token-endpoint issuance
  criterion (`main.tf`), provider + vars.
- **Phase 2 — YOU run it:** `terraform apply` + `configArchive export` need the PF admin **password**
  (`TF_VAR_pf_admin_password`). The assistant is blocked from handling that secret, so the credentialed
  steps below are yours. Everything is scripted; you just supply the password.

## Prerequisites

```sh
export TF_VAR_pf_admin_password='…'                              # PF admin pwd (Railway env, never commit)
export TF_VAR_pf_admin_host='https://hayabusa.proxy.rlwy.net:39267'   # pingfederate-runtime admin proxy (default)
```
Terraform ≥ 1.5. The admin console is already publicly proxied (`:39267`), so **no ssh tunnel needed**.

## Step 1 — validate against the provider schema (no PF needed)

```sh
terraform init
TF_VAR_pf_admin_password=dummy terraform validate   # catches wrong field names before touching PF
```

## Step 2 — reconcile the mapping bodies against the live PF (first run only)

The `import {}` + placeholder ids in `main.tf` adopt the existing hand-built mapping so Terraform
**modifies** it (never recreates). Capture the exact current bodies, then fold them in:

```sh
# list the real client_credentials mappings + their ATM ids
curl -sk -u administrator:$TF_VAR_pf_admin_password -H 'X-XSRF-Header: PingFederate' \
  $TF_VAR_pf_admin_host/pf-admin-api/v1/oauth/accessTokenMappings | jq '.items[].id'

terraform plan -generate-config-out=generated.tf   # writes exact bodies
```
Replace every `REPLACE_WITH_ATM_ID` in `main.tf` with the real id, fold `generated.tf`'s
`attribute_contract_fulfillment` into `oidf_cc_mapping`, and **keep the authored `issuance_criteria`**.
Duplicate the resource+import per client_credentials mapping that must carry the OIDF gate. Re-plan
until the only diff is the issuance criterion.

## Step 3 — apply the OIDF criterion

```sh
terraform apply
```

## Step 4 — prune the agentic bleed (isolation)

Remove the config that belongs to the agentic demo, so the exported archive is OIDF-only. Delete via
the admin API (ids from the list endpoints):

```sh
A="curl -sk -u administrator:$TF_VAR_pf_admin_password -H X-XSRF-Header:PingFederate $TF_VAR_pf_admin_host/pf-admin-api/v1"
# the 3 agent clients
for c in 'urn:agent:northwind-concierge:v1' 'urn:agent:northwind-payments:v1' 'urn:agent:northwind-account:v1'; do
  $A/oauth/clients/$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$c") -X DELETE -o /dev/null -w "%{http_code} $c\n"; done
# the token-exchange processor policy + subject-JWT processor + agentic ATMs (confirm ids first):
#   $A/oauth/tokenExchange/processor/policies   → DELETE the user_to_agent policy
#   $A/idp/tokenProcessors                      → DELETE subjectJwtProc
#   $A/oauth/accessTokenManagers                → DELETE attestJwtATM / attestJwtAcct / attestJwtPmts / events
```
> Leave the OIDF plane intact: the OIDF ATM(s), the client_credentials mapping with the criterion, the
> attestation/federation runtime settings, and any pre-registered OIDF clients.

## Step 5 — export the OIDF-only artifact

```sh
$A/configArchive/export -o ../data.zip     # overwrite THIS module's sibling data.zip; commit .tf + data.zip
```

## Step 6 — give the OIDF PF its own deploy context

The isolated `data.zip` needs its own image so it no longer shares the agentic build context:

- Copy a Dockerfile here modelled on `idp-paz-authzen-adapter/demo/pingfederate/Dockerfile`, **minus the
  RAR/agentic plugin** (`pf.plugins.pf-rar-paz-plugin.jar` + `template/oauth.approval.page…`). Keep:
  `oidf.war`, `pf-oidf-modules.jar`, `jose4j`, the `overlay/` master key, the license, and **this**
  `data.zip`.
- Repoint the service to build from here:
  ```sh
  ( cd deploy/pingfederate && railway up --detach -p e02a8e2f-ff38-4043-836f-25d9e1c0f26b -s pingfederate-runtime -e staging )
  ```

## Step 7 — verify

```sh
node harness/ui/... e2e   # or the demo ⚡ flow: enrol → resolve (chain 3) → token 200
```
Then open the admin console (`https://hayabusa.proxy.rlwy.net:39267/pingfederate/app`) → OAuth → Clients:
the `urn:agent:*` clients are **gone**; only OIDF clients remain. Federation + auto-registration unaffected.

## Keep in sync

`trust_anchor` here MUST match the demo's `CFG.trust_controller` and pf-demo-ui's env
(`lighthouse-staging-e017…`). It's the one federation-topology value inside the criterion.
