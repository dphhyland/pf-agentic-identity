# Demos — where each one lives and how to bring it up

Since the 2026-08-08 split this repo is the **platform** (libs / servlets / plugins / services) plus
the **Railway service definitions** under `deploy/`. The demos themselves live in sibling repos and
consume this one through a **sibling checkout** — clone everything under one parent so the relative
paths in their scripts resolve:

```
Source/
  pf-agentic-identity/                    # this repo — the product + deploy/
  pf-agentic-identity-domain-authority/   # cross-platform rigs + phone-simulator (private)
  pf-oidf-modules/                        # demo UI + harness + deploy-demo.yml
  idp-pingfed-ssf-servelet/               # SSF transmitter/receiver compose demo
  grant-evaluation-api/                   # AS-agnostic Go Grant Evaluation reference
```

Every deployable definition stays **here** — no other repo may deploy `pingfederate-runtime`,
`lighthouse`, `fedhost` or `device-enrolment` (the standing-hazard rule in
[PROVENANCE.md](PROVENANCE.md)). Where a demo below is currently broken, author-local, or torn down,
it says so; nothing here is papered over.

| Demo | Shows | Lives in | State (2026-08-15) |
|---|---|---|---|
| [Staging environment](#1-staging-environment-this-repo) | the AS + federation, live | this repo, `deploy/` | up; PF issuer fix in flight |
| [Demo UI / harness](#2-demo-ui--harness) | attestation client-auth, step by step, in a browser | pf-oidf-modules | UI live; Java harness needs package translation |
| [Cross-platform rigs](#3-cross-platform-rigs) | GKE / EKS / Azure workloads → one federation → cross-cloud `act` chain | domain-authority | torn down; explainer live |
| [Device enrolment + phone simulator](#4-device-enrolment--phone-simulator) | App Attest + passkey + Secure Enclave enrolment, the CAEP loop | this repo + domain-authority | compose broken since the split |
| [SSF transmitter/receiver](#5-ssf-transmitterreceiver-demo) | CAEP/RISC SETs on real PF + Identity Object Model store | idp-pingfed-ssf-servelet | public deploy live; still built from the old jar |
| [RAR → PingAuthorize](#6-rar--pingauthorize) | RFC 9396 consent governed by a PDP, `requested ⊆ attested` | `plugins/rar-paz-plugin` | author-local compose |
| [Grant Evaluation API](#7-grant-evaluation-api) | "is this grant still enough, right now?" — servlet + Go reference | `services/gm-api` + grant-evaluation-api | Go demo live; PF servlet needs a local PF |

---

## 1. Staging environment (this repo)

**What it shows.** The platform running: `lighthouse` (go-oidfed trust anchor / resolver),
`fedhost` (static federation entity host — the `as-emea` / `as-partner` / `as-external` /
`as-unknown` entities the demo UI resolves against), and `pingfederate-runtime` (PF 13.0.3 with the
reactor's modular jars merged into `pf-runtime.war` at root context). Railway project
`e02a8e2f-ff38-4043-836f-25d9e1c0f26b`, environment `staging`.

| Service | Host | Defined by |
|---|---|---|
| lighthouse | `https://lighthouse-staging-e017.up.railway.app` | `deploy/lighthouse/` |
| fedhost | `https://fedhost-staging.up.railway.app` (entities under `/e/<name>/.well-known/openid-federation`) | `deploy/fedhost/` |
| pingfederate-runtime | `https://pingfederate-runtime-staging.up.railway.app` (Railway HTTPS edge → PF's HTTP listener 9080); admin console/API only via the service's TCP proxy — address and credentials in the Railway service variables, not here | `deploy/pingfederate/` |

**How a change deploys.** Push to `main` touching `deploy/lighthouse/**` or `deploy/fedhost/**`
runs the matching workflow's staging job (applies `vars.staging.env`, `railway up`). Production is a
`workflow_dispatch` with `environment=production`. PF is `workflow_dispatch`-only and gated on the
per-env `data.<env>.zip` archives (see [deploy/README.md](../deploy/README.md)); today it is deployed
by hand from a staged context:

```sh
# from the repo root — needs overlay/pf.jwk + overlay/pingfederate-system-keys.xml (secret) and
# data.zip (the terraform Phase-2 export) already in deploy/pingfederate/, all git-ignored
mvn -q -DskipTests package && deploy/pingfederate/build/stage-modules.sh
( cd deploy/pingfederate && railway up --detach --no-gitignore \
    -p e02a8e2f-ff38-4043-836f-25d9e1c0f26b -s pingfederate-runtime -e staging )
```

`--no-gitignore` is what `deploy-pingfederate.yml` passes — without it `railway up` drops the
git-ignored `modules/`, `data.zip` and `overlay/` from the upload and the Docker build fails on its
`COPY`s (`deploy/pingfederate/README.md` shows the command without the flag; `.railwayignore`
governs what is excluded once the flag is on).

**The mock-attester DEV mode.** `deploy/pingfederate/oidf-mock-attesters.json` is baked into the
image and activated by `oidf.mock.attesters=…` in `run.properties`. It maps attester issuers
(`urn:agent:northwind-*`, the demo's `https://attester.example.com` with `kid=mock-attester-1`) to
public JWKs, so an attestation signed by one of those keys is trusted **statically** — no federation
chain resolution for the attester. It is how the demo UI, the agent workload and the cross-platform
rigs mint attestations without standing up a real Client Attester; production trust goes through
the trust chain (`FederationAttesterKeyResolver`) instead. Adding a new demo attester means adding
its public JWK there and redeploying.

**PF config is Terraform.** `deploy/pingfederate/terraform/` — author `.tf` → `terraform apply`
against the running PF → `helpers/export-data-zip.sh` → commit `data.<env>.zip` → redeploy. The
runbook is [its README](../deploy/pingfederate/terraform/README.md); `TF_VAR_environment` picks the
environment and the PF base URL (`server-settings.tf`).

**Verify:**

```sh
curl -s https://lighthouse-staging-e017.up.railway.app/.well-known/openid-federation | cut -d. -f2 | tr '_-' '/+' | jq -R '@base64d | fromjson | .iss'
curl -s https://pingfederate-runtime-staging.up.railway.app/.well-known/openid-configuration | jq -r .issuer
curl -s https://pingfederate-runtime-staging.up.railway.app/.well-known/openid-federation | cut -d. -f2 | tr '_-' '/+' | jq -R '@base64d | fromjson | .iss'
```

**Known at time of writing:** the staging PF still advertises the old EKS rig's ELB hostname as its
OAuth issuer (the first Phase-2 archive was exported from that rig) — the `server-settings.tf`
per-environment base URL exists to fix exactly this and is being applied; until it lands, clients
must send that ELB as the `private_key_jwt` `aud` (`PF_TOKEN_AUD` on the demo UI).

---

## 2. Demo UI / harness

**What it shows.** [pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules) `harness/ui/` — a
browser UI (stdlib Python proxy + WebCrypto in the page; no private key touches the server) that
drives a live PF through the whole attestation client-auth flow: keys → challenge → Client
Attestation + PoP/DPoP → token endpoint, plus federation resolution against lighthouse/fedhost,
§12.1/§12.2 registration, the hosted-attester minting tab, and remote invocation of a SPIFFE-attested
`agent-workload`. Deployed as `pf-demo-ui`: `https://pf-demo-ui-staging.up.railway.app` /
`https://pf-demo-ui-production.up.railway.app` (both live).

**Deploys from that repo**, not this one — `deploy-demo.yml`, path-filtered to `harness/ui/**`, with
its **own** mapping: push to `sd-jwt-rar-paz` → staging, push to `main` → production. Do not read
that mapping across to this repo (here `main` is staging).

**Run it locally** against staging (Python 3, no pip installs):

```sh
cd ../pf-oidf-modules
PF_BASE=https://pingfederate-runtime-staging.up.railway.app python3 harness/ui/server.py
# open http://localhost:8800
```

`PF_BASE` is the PF **root** — the modules are merged into `pf-runtime.war`, so there is no `/oidf`
prefix (the script's default `https://localhost:19031/oidf` is the old loose-war local layout).
`LIGHTHOUSE` / `FEDHOST` default to the staging hosts; `PF_TOKEN_AUD` must equal what PF advertises
as issuer + `/as/token.oauth2` (see the note in §1); the two demo clients (`demo-attest-inline`,
`demo-attest-vault`) come from `deploy/pingfederate/terraform/attestation-demo-clients.tf` here.

**Wire-level probes** in `harness/` still work against any deployment (from `../pf-oidf-modules`;
verified against staging today):

```sh
harness/probe-challenge.sh https://pingfederate-runtime-staging.up.railway.app   # challenge-endpoint contract test
```

**Broken, honestly:** the in-process Java harnesses (`harness/run.sh selfverify | issuance-selfverify
| ssf-selfverify`) compile `harness/*.java` against a single module jar and import
`com.pingidentity.ps.oidf.common.*` — a package this repo unwound on 2026-08-15 (`.jose` /
`.clientattestation` / `.federation` / `.pf` / `.issuer`). They will not compile against current
monorepo artifacts until the harness sources are translated; that repo's own `com/` tree is the
non-canonical pre-monorepo copy. `harness/agent-workload/` (the SPIFFE-attested Python workload,
Railway service `agent-workload`) is unaffected — it vendors `client_attestation_sdk` from
`client-attestation-sdk-polyglot`, gitignored, before build.

---

## 3. Cross-platform rigs

**What it shows.** **pf-agentic-identity-domain-authority** (private, sibling checkout - referenced by name): a workload on GKE and one on EKS each authenticate to a PingFederate using the identity
token its own cloud already issues — no client secret — by exchanging that evidence at the
attestation-issuer servlet for a portable Client Attestation; the two PFs are joined by an OpenID
Federation trust chain (GKE = anchor, EKS = leaf), so either cloud's attestation is presentable to
either AS; then four agents chain RFC 8693 token exchanges across the clouds and the resource sees
`sub` = the originating workload and `act` nested three deep.

| Dir | Leg |
|---|---|
| `gke-spiffe-demo/` | GCP — GKE workload identity / SPIRE into PF, the federation anchor. Public explainer: `https://gke-spiffe-demo-production.up.railway.app` (live) |
| `aws-bedrock-demo/` | AWS — EKS IRSA + a real Bedrock AgentCore Runtime agent (`sts:GetWebIdentityToken`), the federation leaf. Read its `RECOVERY.md` once |
| `azure-aks-demo/` | Azure — AKS workload identity + managed identity + the `AssertedContextResolver` (Entra Agent ID). Written to mirror AWS; **never run against a real subscription** (`DEMO-STATE.md`) |
| `cross-cloud-chain/` | the chain — `deploy.sh`, `curl -s -X POST http://<agent-a-ip>/run \| jq` |
| `phone-simulator/` | see §4 |

**State:** everything cloud-side was **torn down on 2026-08-02** (no GCP project, no EKS cluster, no
AgentCore runtime; the old GKE demo IP no longer answers). `REBUILD.md` there stands the whole rig
back up from nothing — budget half a day, mostly cluster creation. Its order: GCP project + cluster
→ bridge key + attester key → PF into GKE → terraform (from zero) → set GKE PF as anchor → export +
bake → the same for EKS as leaf → verify the chain → `cross-cloud-chain/deploy.sh`.

**Prerequisites** (`REBUILD.md`): `gcloud`, `aws`, `eksctl`, `kubectl`, `docker`, `terraform`, `mvn`
3.9+; a GCP billing account and an AWS admin profile; a `boto3` venv; and **this repo as a sibling
checkout** — the PF image build context is `../pf-agentic-identity/deploy/pingfederate` and the
module jars come from this reactor:

```sh
# from the domain-authority repo root
( cd ../pf-agentic-identity && mvn -q -DskipTests package )      # every module jar
gke-spiffe-demo/pf/build-module-jar.sh                            # PF_AGENTIC_IDENTITY overrides the sibling path
```

**Drift to know about before rebuilding:** `build-module-jar.sh` merges the reactor jars into a single
`pf-oidf-modules.jar` and drops it in `deploy/pingfederate/` — the shape this repo's Dockerfile
consumed until 2026-08-15. The Dockerfile now `COPY`s `modules/` (staged by
`deploy/pingfederate/build/stage-modules.sh`), so the image step in those runbooks needs
`stage-modules.sh` instead of `build-module-jar.sh`; the runbooks also still say `../pingfederate`
(the pre-split worktree layout) where they mean `../pf-agentic-identity/deploy/pingfederate`. Both are
open follow-ups in that repo.

---

## 4. Device enrolment + phone simulator

**What it shows.** `services/device-enrolment` — the agent platform backend for on-device agents:
challenge → App Attest (bound to a Secure Enclave key via `clientDataHash`) → PingOne passkey
authentication → enrolment → mint a Client Attestation whose subject is the opaque instance id →
re-mint on the hot path → the server-side user-verification time-box → a CAEP
`device-compliance-change` suspending the instance mid-session. `phone-simulator` (domain-authority
repo) plays the phone: `DemoServerMain` is `Main`'s wiring with one substitution — a bundled
synthetic App Attest root, because nothing but a physical iPhone can chain to Apple's real one — and
`PhoneSimulatorCli` builds synthetic attestations against it. Target service: `device-enrolment`
(`https://device-enrolment-staging.up.railway.app`), config in `deploy/device-enrolment/`, **not yet
provisioned on Railway** — the URL 404s; no service exists in any project. No workflow either way:
when it is created, it deploys by hand (`railway up`; the Dockerfile builds the reactor from the repo
root, so the upload root is the repo root).

**The documented path, and why it does not work today.**
`deploy/device-enrolment/docker-compose.yml` brings up Postgres (schema applied from the vendored
Identity Object Model migrations in `libs/device-instance/src/test/resources/idm/` — the registry is
`IomInstanceRegistry` now, an entry store in the same directory `proofing-directory` uses, not a
private schema of its own) plus `Dockerfile.demo` on host port `8180`, wired to the real PingOne
tenant. `Dockerfile.demo` does `COPY demo demo` and `mvn -pl demo/phone-simulator` — **that path left
this repo on 2026-08-08**, so `docker compose up --build` fails at the build stage. It ran end to end
on 2026-08-01 (the compose commit messages record it); it has not run since the split. The same
compose command is what `phone-simulator/README.md` in the domain-authority repo still tells you to
run.

**Closest working path today** (two gates, both real):

1. **Postgres with the schema.** The compose `postgres` service publishes no host port, so either add
   a `ports: ["5432:5432"]` line locally or run it directly (from this repo's root):
   ```sh
   docker run -d --name enrolment-pg -p 5432:5432 -e POSTGRES_USER=enrolment -e POSTGRES_PASSWORD=enrolment -e POSTGRES_DB=enrolment \
     -v "$PWD/libs/device-instance/src/test/resources/idm:/docker-entrypoint-initdb.d:ro" postgres:16-alpine
   ```
   The three files there apply in filename order (`0000-base-schema`, `002-backfill-may-attrs`,
   `006-add-agent-instance-registry`) — refresh them from `~/Source/idp-scim-service/migrations` if
   they drift.
2. **Build the simulator** (domain-authority repo) against locally installed monorepo artifacts:
   ```sh
   ( cd ../pf-agentic-identity && mvn -q -DskipTests -pl services/device-enrolment,libs/app-attest -am install )
   ( cd ../pf-agentic-identity-domain-authority/phone-simulator && mvn -q -DskipTests package )
   ```
   **Gate:** `DemoServerMain` / `PhoneSimulatorCli` import `com.pingidentity.ps.oidf.common.*`
   (`JwsSigner`, `LocalJwkSigner`, `InMemoryAttestationChallengeService`, `Jwks`), which this repo
   moved to `…oidf.jose` / `…oidf.clientattestation` on 2026-08-15. Against a fresh `mvn install`
   from this repo the simulator **does not compile** until those five imports are translated (a
   backport-direction fix in the domain-authority repo). Against a pre-unwind `~/.m2` it still builds.
3. **Run `DemoServerMain`** with the environment `docker-compose.yml` sets (`ENROLMENT_ISSUER=http://localhost:8180`,
   `PORT=8180`, `IDM_DATABASE_URL=jdbc:postgresql://localhost:5432/enrolment?user=enrolment&password=enrolment`,
   `APPLE_ALLOW_DEVELOPMENT=true`, `REQUIRE_COMPLIANT_DEVICE=false`, `UV_MAX_AGE_SECONDS=300`,
   the RFC 7515 example `ENROLMENT_SIGNING_JWK`, and the three `PINGONE_*` values), then the CLI —
   these two commands are verbatim from `phone-simulator/README.md`, run from that repo's root:
   ```sh
   # fail-closed run, zero setup: refused at user_authentication_failed because the evidence is fake
   java -cp "phone-simulator/target/phone-simulator-0.1.0.jar:phone-simulator/target/dependency/*" \
     com.pingidentity.ps.oidf.demo.phonesim.PhoneSimulatorCli --base-url http://localhost:8180 --demo-evidence
   # green path: needs a real PingOne ID token (client fad0652e has only the app's custom-scheme redirect)
   java -cp "phone-simulator/target/phone-simulator-0.1.0.jar:phone-simulator/target/dependency/*" \
     com.pingidentity.ps.oidf.demo.phonesim.PhoneSimulatorCli --base-url http://localhost:8180 --id-token <the ID token>
   # add --suspend-device <device id from the registry> to see the CAEP loop refuse the next re-mint
   ```

Until the two gates are closed, treat this demo as **not runnable from a clean checkout**. What *is*
exercised on every build: `EnrolmentHttpEndToEndTest` in `services/device-enrolment` drives the real
HTTP surface (challenge, App Attest with the enclave-key commitment, enrolment, re-mint, time-box
refusal and recovery) with the `app-attest` test-jar's synthetic chain — `mvn -pl
services/device-enrolment -am test`.

---

## 5. SSF transmitter/receiver demo

**What it shows.** [idp-pingfed-ssf-servelet](https://github.com/dphhyland/idp-pingfed-ssf-servelet):
a docker-compose stack of PF 13.0.3 with the SSF module merged into `pf-runtime.war`, the ID Partners
**Identity Object Model** store (Postgres 16, `idm.entry` JSONB; `storeDialect=ldm`) as the
transmitter's persistence, and a single-page demo UI behind a credential-injecting proxy. An 11-stage
probe: transmitter metadata → `ssf.manage` bearer → stream CRUD → SCIM-driven subjects → verification
SET polled/acked → PF logout emits `caep.session-revoked` (`LogoutEventFilter` over
`/idp/init_logout.openid`) → SCIM disable emits `risc.account-disabled` → state survives a PF restart →
**loopback push (RFC 8935)**: PF's transmitter delivers to PF's own receiver, which verifies the SET and
runs the grant-revocation action. Public deployment (Railway project `ssf-demo`, live): UI
`https://ssf-demo-ui-production.up.railway.app`, transmitter
`https://pingfederate-ssf-production.up.railway.app/.well-known/ssf-configuration`.

**Bring it up** (from that repo's README; Ping DevOps credentials for licensing):

```sh
cd ../idp-pingfed-ssf-servelet
cp .env.example .env         # PING_IDENTITY_DEVOPS_USER / _KEY — never commit
# pf/*.jar is gitignored — see the note below on where the jar must come from
docker compose up -d --build
./scripts/bootstrap-pf.sh    # one-time: licence agreement, admin, ATM, mapping, ssf.manage scope, receiver client
./scripts/probe-demo.sh      # the 11-stage walk
# UI http://localhost:18080 · admin https://localhost:19999/pingfederate/app (administrator / 2FederateM0re)
# store: docker compose exec ldm-store psql -U ldm -d ldm
```

**Where the module jar must come from — an open backport.** That README says to build
`pf-oidf-modules.jar` in the pf-oidf-modules repo and copy it to `pf/`; its `pf/Dockerfile` `COPY`s a
single `pf-oidf-modules.jar` and its own (older, single-jar) `assemble-pf-runtime-war.sh`. **The
canonical SSF source is this repo** (`servlets/ssf`, plus `oidf-jose` / `pf-integration` it depends
on) — pf-oidf-modules is backport-only. The demo has not been repointed: this repo's
`deploy/pingfederate/build/assemble-pf-runtime-war.sh` already accepts a directory of jars (the
`modules/` shape from `stage-modules.sh`), so the fix is to `COPY modules/` there and call the
directory form — tracked as a drift-rule-2 backport, not yet done. Until then the compose builds from
whatever `pf/pf-oidf-modules.jar` is lying around (the local copy is dated 2026-07-21, pre-unwind).

---

## 6. RAR → PingAuthorize

**What it shows.** `plugins/rar-paz-plugin` — a PF `AuthorizationDetailProcessor` that forwards each
RFC 9396 `authorization_details` entry, together with the client attestation's vouched subject /
entitlement / workload, to a PingAuthorize governance-engine decision; denies unless `PERMIT`; applies
returned statements; and attributes the decision to the principal (`UserID`) with the agent as `actor`.
The policy proves `requested ⊆ attested`: `EMEA` / `APAC` within the entitlement → PERMIT, `AMER` →
DENY. Verified live end to end at authoring time.

**Two halves.** The **PDP** (`paz/`) and the **PF wiring** (`integration/`).

```sh
# PDP — PingAuthorize PDP :8443 + PAP :7443, then import the policy branch and author the rules
cd plugins/rar-paz-plugin/paz
docker compose -f paz-compose.yml up -d
SNAP=/Users/davidhyland/Source/idpartners-authzen-ping-authorize/ping-authorize/pap/policies/AuthZEN.snapshot
curl -sk -H "x-user-id: admin" -H "Content-Type: application/json" --data-binary @"$SNAP" \
     "https://localhost:7443/api/snapshot/AuthZEN/import"
python3 01-author-permit.py && python3 02-author-containment.py && python3 03-align-plugin-scalars.py
../probe-decision.sh          # PERMIT/DENY against the plugin's real request shape
```

**Author-local, said plainly:** `paz-compose.yml` mounts absolute paths under
`/Users/davidhyland/Source/idpartners-authzen-ping-authorize/` (server profile, PAP options, console
war, certs, the PingAuthorize licence) and the snapshot import points at the same checkout. Anyone
else needs that private checkout at that path or must edit every volume line. The authoring scripts
also hard-code IDs captured on the first run (branch `58a67ffb…`, rule `805ab29f…`); a fresh PAP means
re-importing and updating them. Every secret in it is Ping's public demo default (`2FederateM0re`).

```sh
# PF side — the jar, then config-as-code against a running PF's admin API
mvn -pl plugins/rar-paz-plugin -am package          # → target/pf.plugins.pf-rar-paz-plugin.jar (shaded jackson, PF-INF marker)
export ADMIN=https://localhost:9999 PF_USER=administrator PF_PASS=…
PDP_URL=https://<pingauthorize-host>:1443/governance-engine PDP_SECRET=… \
  plugins/rar-paz-plugin/integration/config-as-code/create-processor-instance.sh     # instance "rarPazProc"
CLIENT_ID=<your-webapp-client> RAR_TYPES='["payment_initiation"]' \
  plugins/rar-paz-plugin/integration/config-as-code/enable-on-client.sh              # GET-merge-PUT; forces the approval page
```

Bake the jar with `integration/Dockerfile.fragment` (it also seds the TLS-hostname JVM flag into
`run.sh` and installs the consent template). Note the OIDF-only image in `deploy/pingfederate/` does
**not** include this plugin by design; the `rarPazProc` processor instance that rides in the archive
is an unmanaged carve-out (the provider has no resource for it) and is inert without the jar.

---

## 7. Grant Evaluation API

**What it shows.** A client asks whether an existing grant still permits an action, right now,
without a new authorization flow — and the answer is *what the client was granted ∩ what the subject
holds*, decided by an AuthZEN PDP. Alice consented to accounts 111, 222, 444; she closed 222 and is
view-only on 444; the grant is valid and the answer is still no. Two implementations, one protocol:

- **`services/gm-api`** — the API **inside PingFederate** (`gm-api.war`): reads grants in-process via
  `AccessGrantManagerAccessor`, verifies tokens against PF's own keys, `/mcp` add-on for agents.
- **grant-evaluation-api** — the AS-agnostic **Go** reference with a pluggable grant source
  (PingFederate grant store, or any RFC 7662 introspection endpoint) and the demo PDP.

**Zero-install:** the Go demo is live at `https://demo-production-0792.up.railway.app`:

```sh
curl -X POST https://demo-production-0792.up.railway.app/api/grants/grant-alice-accounts/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"action":{"name":"read_balance"},"resource":{"type":"account","id":"222"}}'
# → "You no longer have access to this account."
```

**Locally in 30 seconds, no PF** (from `../grant-evaluation-api`):

```sh
go run ./cmd/pdp  -addr :9090 -expose-entitlements &
go run ./cmd/demo -addr :8081 -pdp http://localhost:9090     # open http://localhost:8081
```

**The PF servlet, end to end** (`services/gm-api/deploy/pingfederate/README.md`): a DevOps PF on
non-standard ports, its config as Terraform, `gm-api.war` dropped into `server/default/deploy`, the
demo PDP from the Go repo, and the authorization-code flow that creates the persistent grant:

```sh
docker run -d --name gm-pingfederate -p 9131:9031 -p 9199:9999 \
  -e PING_IDENTITY_ACCEPT_EULA=YES -e PING_IDENTITY_DEVOPS_USER="$PING_IDENTITY_DEVOPS_USER" -e PING_IDENTITY_DEVOPS_KEY="$PING_IDENTITY_DEVOPS_KEY" \
  -e SERVER_PROFILE_URL=https://github.com/pingidentity/pingidentity-server-profiles.git -e SERVER_PROFILE_PATH=getting-started/pingfederate \
  pingidentity/pingfederate:13.0.3-latest
( cd services/gm-api/deploy/pingfederate/terraform && export TF_VAR_pf_admin_password='2FederateM0re' \
    TF_VAR_gm_api_client_secret="$(openssl rand -hex 24)" TF_VAR_tpp_client_secret="$(openssl rand -hex 24)" \
    TF_VAR_gm_service_password="$(openssl rand -hex 20)" && terraform init && terraform validate && terraform apply )
mvn -pl services/gm-api/servlet package                       # needs the local.pingfederate:* jars — build.yml shows the install lines
docker cp services/gm-api/servlet/target/gm-api.war gm-pingfederate:/opt/out/instance/server/default/deploy/ && docker restart gm-pingfederate
( cd ../grant-evaluation-api && go run ./cmd/pdp -addr :9099 -expose-entitlements & )   # PF reaches it at host.docker.internal:9099
( cd ../grant-evaluation-api && python3 scripts/authcode.py <path-to-tpp-secret> )      # alice consents; prints TOKEN + AGID
curl -sk -X POST "https://localhost:9131/gm-api/grants/$AGID/evaluate" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"action":{"name":"read_balance"},"resource":{"type":"account","id":"222"}}'
```

**Two honest notes.** The Go reference is a **local sibling checkout only** at time of writing — it
has not been pushed to GitHub, so the module READMEs name it without a link; the older links inside
`services/gm-api/docs/` and `services/gm-api/deploy/` still carry a URL that does not resolve until
it is published. And on a stock PF the RAR
consent rides as a grant attribute constant rather than a user choice, until the RAR processor of §6
is wired in — `services/gm-api/deploy/pingfederate/README.md` spells out the remaining steps.
