# GKE SPIFFE → Client Attestation → PingFederate demo

> **Explainer (public):** https://gke-spiffe-demo-production.up.railway.app

A workload running in Google Cloud proves its identity with SPIFFE evidence, exchanges it at the
**attestation-issuer servlet** (`/federation/attestation`, inside PF's war) for a **Client Attestation**
(draft-ietf-oauth-attestation-based-client-auth), and authenticates to PF's token endpoint with the
`OAuth-Client-Attestation` / `OAuth-Client-Attestation-PoP` headers. Two phases:

| Phase | Evidence | Attests the workload | Servlet changes |
|---|---|---|---|
| **1** | SPIRE JWT-SVID (`spiffe-jwt`) | SPIRE on GKE, trust domain `gke.banking.demo` | none |
| **2** | GKE-projected SA token (`gke-sa-token`) | **Google itself** — cluster OIDC JWKS, canonical `spiffe://PROJECT.svc.id.goog/ns/…/sa/…` IDs | the evidence adapter (already merged) |

Everything runs inside **one GKE cluster** (PF included) — nothing is publicly exposed; the admin API is
reached by `kubectl port-forward`, and all token-endpoint calls run in-cluster so the PoP-`aud` proxy trap
never appears. Workloads bootstrap from the attester discovery document
**`/.well-known/client-attester?client_id=…`** (endpoints, `evidence_audience`, evidence type, challenge
policy) — the only agent config is a base URL and a `client_id`.

## Phase 0 — GCP bootstrap

```bash
cd deploy/gke-spiffe-demo
PROJECT_ID=pf-spiffe-demo-$RANDOM BILLING_ACCOUNT=XXXXXX-XXXXXX-XXXXXX ./gcp/bootstrap.sh
```

Creates the project (billing link needs your account), enables GKE + Artifact Registry, and creates a
**1-node zonal Standard cluster** (`e2-standard-4`, `--workload-pool` on for Phase 2). Standard, not
Autopilot: the spiffe-csi driver needs privileges Autopilot restricts, and one zonal cluster's management
fee is inside the GKE free tier.

## Phase 1a — PF into the cluster

The PF image is the existing `deploy/pingfederate/Dockerfile` (attestation issuer + verifier merged into
`pf-runtime.war`, mock-attester trust baked, HTTP on 9080). Its build context needs git-ignored
artifacts; on this machine they live in the original adapter repo
(`~/Source/idp-paz-authzen-adapter/demo/pingfederate/`), and the module jar is merged from the
monorepo build (which is what carries the new discovery servlet + GKE evidence adapter):

```bash
mvn -q -DskipTests package                          # at the repo root — builds every module jar
./pf/build-module-jar.sh                            # → ../pingfederate/pf-oidf-modules.jar (merged)

ADAPTER=~/Source/idp-paz-authzen-adapter/demo/pingfederate
cp "$ADAPTER"/data.zip "$ADAPTER"/oidf-mock-attesters.json ../pingfederate/
# The adapter's mock-attesters file trusts only the urn:agent:* issuers — ADD the demo attester
# (its public key is the mock-attester-1 JWK in pf/terraform/gke-demo-client.tf), else the token
# endpoint fails with "No statically-trusted attester keys registered for issuer":
python3 - <<'EOF'
import json
f = "../pingfederate/oidf-mock-attesters.json"
d = json.load(open(f))
d["https://attester.example.com"] = {"keys": [{
    "kty": "EC", "kid": "mock-attester-1", "crv": "P-256",
    "x": "c2pTtxD_E2ZGIMam9QGsiDvlY57axE9Q9LKSnidQUag",
    "y": "ZI_wiUp0BUd_Gmi9412cAet7vBMhi4fkwclL_ujlTSI",
    "use": "sig", "alg": "ES256"}]}
json.dump(d, open(f, "w"), indent=1)
EOF
mkdir -p ../pingfederate/overlay/config-store
cp "$ADAPTER"/overlay/pf.jwk "$ADAPTER"/overlay/pingfederate-system-keys.xml ../pingfederate/overlay/
cp "$ADAPTER"/overlay/config-store/org.sourceid.saml20.domain.mgmt.impl.DataDeployer.xml \
   ../pingfederate/overlay/config-store/

REGION=us-central1
REGISTRY=${REGION}-docker.pkg.dev/${PROJECT_ID}/demo
( cd ../pingfederate && docker buildx build --platform linux/amd64 -t ${REGISTRY}/pf:phase1 --push . )

kubectl apply -f pf/namespace.yaml
cp pf/secret.example.yaml pf/secret.yaml   # fill in DevOps creds; git-ignored
kubectl apply -f pf/secret.yaml
sed "s|IMAGE|${REGISTRY}/pf:phase1|" pf/deployment.yaml | kubectl apply -f -
kubectl apply -f pf/service.yaml
kubectl -n pf rollout status deploy/pingfederate --timeout=600s   # slow: license fetch + data.zip import
```

Smoke: `kubectl run curl -n demo --rm -it --image=curlimages/curl --restart=Never -- \
  curl -s http://pingfederate.pf:9080/.well-known/client-attester | jq .`

## Phase 1b — client config (Terraform)

```bash
kubectl -n pf port-forward svc/pingfederate 9999:9999 &
cd pf/terraform
export TF_VAR_pf_admin_password=…    # the data.zip archive's admin password
terraform init
terraform plan -generate-config-out=generated.tf   # adopt the live /extendedProperties list; reconcile
terraform apply                                    # creates demo-attest-gke (bundle still placeholder)
```

## Phase 1c — SPIRE

```bash
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/
helm upgrade --install spire-crds spiffe/spire-crds -n spire-mgmt --create-namespace
helm upgrade --install spire spiffe/spire -n spire-mgmt -f ../../spire/values.yaml
kubectl apply -f ../../spire/clusterspiffeid.yaml

# The SPIRE JWT-authority JWKS → the client's trust bundle:
export TF_VAR_spire_bundle_jwks=$(kubectl exec -n spire-mgmt spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server bundle show -format spiffe \
  | jq -c '{keys: [.keys[] | select(.use == "jwt-svid")]}')
terraform apply    # re-apply with the real bundle
```

(If jose4j balks at `use:"jwt-svid"`, strip it: `jq -c '{keys: [.keys[] | select(.use=="jwt-svid") | del(.use)]}'`.)
SPIRE **rotates** JWT authorities — a long-lived cluster eventually needs this bundle re-pasted.

## Phase 1d — the agent

```bash
( cd ../../agent && docker buildx build --platform linux/amd64 -t ${REGISTRY}/agent:demo --push . )
sed "s|IMAGE|${REGISTRY}/agent:demo|" ../../agent/deployment-phase1.yaml | kubectl apply -f -
kubectl -n demo rollout status deploy/payment-agent

# Run the whole chain (discovery → SVID → mint → token):
kubectl -n demo port-forward deploy/payment-agent 8080:8080 &
curl -s -X POST localhost:8080/invoke | jq '{evidence_mode, mint_status, pf_status}'
```

`/invoke` returns every artifact (SVID, attestation, PoP, PF response) — decode them at jwt.io for the
demo narrative. `runbook-curl.md` walks the same five steps as raw curl.

### Phase 1 verification

- **Positive:** `pf_status: 200` with an access token; the decoded attestation carries `cnf` (the
  instance key), `workload.spiffe_id: spiffe://gke.banking.demo/ns/demo/sa/payment-agent`, and the
  granted `authorization_details`.
- **Negatives:**
  - `curl -X POST localhost:8080/invoke -d '{"authorization_details":[{"type":"sales_agent","sales_regions":["APAC"]}]}'`
    → `mint_status: 403` `access_denied` (over the entitlement ceiling);
  - a pod whose service account has no binding (edit the ClusterSPIFFEID selector) → `spiffe_id_not_authorized`;
  - replaying a captured `proof` verbatim against `/federation/attestation` → `invalid_instance_proof`;
  - a PoP with the wrong `aud` → token endpoint rejects (`invalid_client`).

Afterwards, persist the applied config: export `data.zip` (see
`../pingfederate/terraform/helpers/export-data-zip.sh`), drop it into the PF build context, and rebuild
as `pf:phase1-final` so pod restarts keep the demo clients.

## Phase 2 — Google-native (no SPIRE)

```bash
helm uninstall spire -n spire-mgmt          # the point: Google attests, SPIRE is gone

# The image must carry the evidence adapter (attestation_evidence / attestation_bundle_url support) —
# already true if Phase 1 was built from this branch; otherwise rebuild the merged jar:
( cd ../.. && mvn -q -DskipTests package ) && ./pf/build-module-jar.sh
( cd ../pingfederate && docker buildx build --platform linux/amd64 -t ${REGISTRY}/pf:phase2 --push . )
kubectl -n pf set image deploy/pingfederate pingfederate=${REGISTRY}/pf:phase2

# Cluster issuer + JWKS:
ISSUER="https://container.googleapis.com/v1/projects/${PROJECT_ID}/locations/us-central1-a/clusters/spiffe-demo"
export TF_VAR_gcp_project_id=$PROJECT_ID
export TF_VAR_gke_cluster_issuer=$ISSUER
export TF_VAR_gke_jwks_uri=$(curl -s ${ISSUER}/.well-known/openid-configuration | jq -r .jwks_uri)
terraform apply                             # creates demo-attest-gke-native

sed "s|IMAGE|${REGISTRY}/agent:demo|" ../../agent/deployment-phase2.yaml | kubectl apply -f -
curl -s -X POST localhost:8080/invoke | jq '{evidence_mode, mint_status, pf_status}'
```

### Phase 2 verification

Same positive chain with `evidence_mode: gke-sa-token` and the attestation's
`workload.spiffe_id: spiffe://<project>.svc.id.goog/ns/demo/sa/payment-agent`. Negatives: a token
projected with a different `audience` → `invalid_svid`; an unbound service account →
`spiffe_id_not_authorized`. If the public JWKS fetch is blocked from the pod, paste the JWKS inline as
`attestation_spiffe_bundle` instead (already supported — drop `attestation_bundle_url`).

## Costs & teardown

≈ **$3.5–4/day**: one `e2-standard-4` (~$0.134/h) + 50 GB disk; the zonal cluster fee is free-tier; no
load balancers (ClusterIP + port-forward only). A build-and-demo week ≈ $25–30.

```bash
PROJECT_ID=… ./gcp/teardown.sh
```

## Gotchas

- **Engine vs webapp classloader (THE big one)**: token-endpoint OGNL issuance criteria evaluate on
  PF's *engine* classloader, which does **not** search `pf-runtime.war`'s `WEB-INF/lib`. The module jar
  must ALSO sit in `server/default/deploy/` (the Dockerfile now does this) or
  `validateClientAttestation` fails as an opaque OGNL "Method failed" — a `ClassNotFoundException`
  with no logged trace. The servlets (webapp copy) and the OGNL hook (engine copy) share state only
  via request attributes with string keys — that contract is cross-classloader by design.
- **Same-tag image pushes don't redeploy**: GKE's default `IfNotPresent` pull policy reuses the cached
  image for an unchanged tag. Pin the Deployment to the pushed digest
  (`kubectl set image ...=<repo>@sha256:…`) or bump the tag every build.
- **PF pod restarts wipe live config**: the drop-in-deployer re-imports the baked `data.zip` at boot.
  After any restart, re-run `terraform apply`; once the config is final, export `data.zip` and bake a
  `phase1-final` image so restarts keep it.
- **ClusterSPIFFEID needs `spec.className`** matching the helm release (`spire-mgmt-spire` for these
  charts) or the controller-manager silently ignores it (`podsSelected` stays 0).
- **py-spiffe audience is a collection**: passing a bare string to `fetch_jwt_svid(audience=…)`
  iterates it into per-character audiences — the SVID then fails the attester's aud check.

- **PoP `aud`**: PF validates against its **configured base URL** (inside `data.zip`) or the exact
  request URL. The agent defaults `PF_TOKEN_AUD=https://localhost:9031` (the archive's base); change it
  only together with PF's server settings.
- **License**: DevOps eval (~7 days), fetched **only at container start** — restart the PF pod for a
  longer-lived demo.
- **Single PF pod only**: the challenge/replay store is in-memory (no Redis deployed).
- **arm64 Mac**: always `docker buildx build --platform linux/amd64`.
- **spiffe-csi socket name**: `SPIFFE_ENDPOINT_SOCKET` in `deployment-phase1.yaml` must match the SPIRE
  helm chart's agent socket (`spire-agent.sock` for the hardened charts) — check `helm get values spire`.
