# Deploy runbook — hosted-attester minting in the live demo

Gets the **"Attestation minting — the hosted attester"** demo section working end-to-end against the
**existing** staging `pingfederate-runtime` (the same PF the demo already drives). No new services.

What has to happen, and why:
- The `/federation/attestation` **servlet** is code in `pf-oidf-modules.jar` → needs **one redeploy** of
  `pingfederate-runtime` (the jar is merged into `pf-runtime.war` at image build).
- The two **demo clients** (`demo-attest-inline`, `demo-attest-vault`) are config → provisioned via
  Terraform and baked into `data.zip`.
- The **OpenBao** toggle needs vault env vars on the PF service + the transit key's public JWK trusted.
- The **UI** (`pf-demo-ui`) deploys by **push** (`deploy-demo.yml`, path `harness/ui/**`).

> **Fast path (inline toggle only):** do Steps 0, 3, 4, 5, 6 and skip Step 2 (OpenBao). The inline signer
> needs no vault. Add Step 2 later for the OpenBao toggle.

Railway: project `e02a8e2f-ff38-4043-836f-25d9e1c0f26b`, env `staging`, services `pingfederate-runtime`
(id `413fdf8a-…`) and `openbao` (id `78ad0f83-…`). Branch `sd-jwt-rar-paz` → staging.

---

## Prereqs (out-of-band secrets — never commit)

- Railway CLI logged in (or `RAILWAY_TOKEN` = a staging project token).
- `TF_VAR_pf_admin_password` — the `pingfederate-runtime` admin password (baked in `data.zip`; team secret store).
- `PINGFEDERATE_PROVIDER_PRODUCT_VERSION=13.0` (provider 1.8.1 requires it).
- `deploy/pingfederate/overlay/` staged — the **master-key** secret (git-ignored; from the shared demo context).
- Confirm the **current** staging proxies (history drifts): admin `hayabusa.proxy.rlwy.net:39267`,
  runtime — check with `railway domain -s pingfederate-runtime` / `list_tcp_proxies`. The demo's
  `PF_BASE` (a `pf-demo-ui` service var) must point at the runtime proxy **root** (no `/oidf`).

---

## Step 0 — build the module jar

```sh
cd ~/Source/pf-oidf-modules
cp -R com/* src/main/java/com/        # mirror tracked source into the build tree
mvn -o -q package -DskipTests -Dassembly.skipAssembly=true -Dpmd.skip=true -Dcheckstyle.skip=true
ls target/pf-oidf-modules-0.0.1-SNAPSHOT.jar   # this carries the new AttestationIssuanceServlet
```

## Step 1 — sanity-check the issuance logic locally (optional, no PF)

```sh
MODULE_JAR="$PWD/target/pf-oidf-modules-0.0.1-SNAPSHOT.jar" bash harness/run.sh issuance-selfverify
# expect: ALL 3 CHECKS PASSED
```

## Step 2 — OpenBao (vault toggle only) ⚠️ secret

The transit key `attestation-es256` (type `ecdsa-p256`) already exists on the `openbao` service.

**2a. Point the PF runtime at the vault** (reference var — no raw token in the repo):

```sh
railway variables \
  --set "OIDF_OPENBAO_URL=http://openbao.railway.internal:8200" \
  --set 'OIDF_OPENBAO_TOKEN=${{openbao.BAO_ROOT_TOKEN}}' \
  -s pingfederate-runtime -e staging --skip-deploys
```

**2b. Trust the transit key at the token endpoint** (only needed for the "use at token endpoint" loop —
the mint itself does not need it). Read the transit public key and add it to the mock-attesters trust:

```sh
railway ssh -s openbao -e staging
  # inside: export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$BAO_ROOT_TOKEN"
  bao read -format=json transit/keys/attestation-es256 | \
    jq -r '.data.keys[(.data.latest_version|tostring)].public_key'   # PEM
  exit
```

Convert that PEM to an EC JWK + RFC 7638 `kid` (matches `OpenBaoTransitSigner`) and add it under the demo
issuer in `deploy/pingfederate/oidf-mock-attesters.json`, alongside the existing `mock-attester-1` key:

```jsonc
// oidf-mock-attesters.json  →  https://attester.example.com : { "keys": [ mock-attester-1, <transit-key> ] }
```

Helper to produce the JWK from the PEM:

```sh
python3 - <<'PY'
import sys, base64, json, hashlib
from cryptography.hazmat.primitives.serialization import load_pem_public_key
pem = sys.stdin.read().encode()
k = load_pem_public_key(pem); n = k.public_numbers()
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32,'big')).rstrip(b'=').decode()
x, y = b(n.x), b(n.y)
kid = base64.urlsafe_b64encode(hashlib.sha256(json.dumps({"crv":"P-256","kty":"EC","x":x,"y":y},separators=(',',':')).encode()).digest()).rstrip(b'=').decode()
print(json.dumps({"kty":"EC","kid":kid,"crv":"P-256","x":x,"y":y,"use":"sig","alg":"ES256"}, indent=2))
PY
```

## Step 3 — provision the two demo clients (Terraform) ⚠️ admin password

Config-as-code flow: apply to the running PF, then export `data.zip` (the deploy artifact). See
`terraform/README.md` for the full Phase-2 export; the mint-specific parts:

```sh
cd deploy/pingfederate/terraform
export TF_VAR_pf_admin_password='<staging admin password>'   # out-of-band; never commit
export PINGFEDERATE_PROVIDER_PRODUCT_VERSION=13.0
export TF_VAR_pf_admin_host='https://hayabusa.proxy.rlwy.net:39267'   # confirm current

terraform init -input=false

# Reconcile the extended-properties SINGLETON so nothing already declared is dropped:
#   1. add:  import { to = pingfederate_extended_properties.props  id = "extended_properties" }  (confirm id)
#   2. terraform plan -generate-config-out=generated.tf      # writes the CURRENT items
#   3. merge those items into extended-properties.tf, keeping the attestation_* additions
terraform plan            # expect: + demo_attest_inline, + demo_attest_vault, ~ extended_properties (add names only)
terraform apply           # the ONLY acceptable verbs are create (the 2 clients) + update (properties)

# Export the realised config into the baked artifact:
curl -sk -u "administrator:$TF_VAR_pf_admin_password" -H 'X-XSRF-Header: PingFederate' \
  -o ../data.zip "$TF_VAR_pf_admin_host/pf-admin-api/v1/configArchive/export"
cd ../../..
git add deploy/pingfederate/terraform/*.tf deploy/pingfederate/data.zip   # commit .tf + artifact
```

> A plan that shows **destroy+create** on any existing object means a wrong import id — stop and fix.

## Step 4 — redeploy `pingfederate-runtime` (adds the servlet + the new data.zip)

Stage the build context (see `README.md` "Stage the build context"), then:

```sh
cp target/pf-oidf-modules-0.0.1-SNAPSHOT.jar deploy/pingfederate/pf-oidf-modules.jar
# also present in deploy/pingfederate/: jose4j-0.9.6.jar, oidf-mock-attesters.json, overlay/ (secret), data.zip
( cd deploy/pingfederate && railway up --detach -p e02a8e2f-ff38-4043-836f-25d9e1c0f26b -s pingfederate-runtime -e staging )
```

## Step 5 — verify the servlet is live

```sh
RUNTIME=https://<runtime-proxy-host:port>     # the PF runtime root (same origin as PF_BASE, minus /oidf)
curl -sk -X POST "$RUNTIME/federation/attestation" -H 'Content-Type: application/json' -d '{}'
# expect: HTTP 400  {"error":"invalid_request","error_description":"missing client_id"}  ← servlet is live
```

## Step 6 — deploy the demo UI

```sh
git push origin sd-jwt-rar-paz     # deploy-demo.yml auto-deploys harness/ui/** to pf-demo-ui (staging)
```

Open the demo → **Deploy** tab → **"Mint an attestation from a SPIFFE SVID — the hosted attester"** → Run.
- **inline JWK**: mints a Client Attestation signed by `mock-attester-1` (kid shown in the header).
- **OpenBao transit**: mints one signed inside the vault (kid = the transit key thumbprint; "key never left
  the vault" badge). Needs Step 2.
- **Use it at the token endpoint →**: presents the minted attestation + a fresh PoP; issues a token once the
  attester key is trusted (Step 2b / federation).

---

## Gotchas

- **aud/scheme trap** (behind the TCP proxy): the PoP `aud` must match PF's *configured* base
  (`https://localhost:9031`), not the public proxy URL — the demo already derives this from `token_aud`.
  Same reason the SVID/proof `aud` here is the attester *issuer*, not a URL.
- **Ephemeral PF** — no volume. Console edits are lost on redeploy; `data.zip` is the only source of truth.
  Challenge/replay state resets on redeploy unless `OIDF_REDIS_URL` is set (it is, on staging).
- **DevOps licensing** is re-fetched at container start (~7-day eval) — a redeploy/restart refreshes it; a
  401 "no suitable verification key" right after a restart just means mint a fresh token.
- **`PF_BASE`** on `pf-demo-ui` must be the runtime **root** (module endpoints have no `/oidf` prefix).
- The two demo clients share `iss=https://attester.example.com`; to verify BOTH signers at the token
  endpoint, that issuer maps to BOTH keys (mock-attester-1 + the transit key) in `oidf-mock-attesters.json`.
