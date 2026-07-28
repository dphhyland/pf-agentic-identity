# Locked demo state (GKE)

The exact state the live GKE + Railway demo runs at. Recorded 2026-07-28 (updated same day: distinct
issuer + federation anchor).

## Running images

| Component | Image |
|---|---|
| PingFederate | `us-central1-docker.pkg.dev/pf-spiffe-demo-7264/demo/pingfederate:federation-p1` (`sha256:cfc7df5c…`) |
| GKE agent | `us-central1-docker.pkg.dev/pf-spiffe-demo-7264/demo/agent@sha256:3979b01acf26a4a4ef26e82a227b44032ee190d74154c28ede6fa6c9e41d8e3e` |

The PF image is the **baked-config** build: the four attestation clients are baked into `data.zip` as
`PRIVATE_KEY_JWT` with the bridge public JWKS, so a fresh pod boots working with no Terraform step. The
bridge private key lives only in the k8s secret `pf-bridge-key` (data key `private-jwk`, kid
`cJ-4Fg9oUAar1TNoqvgJdERxxSZfTPnNiUJ_JT1Jvcc`).

## Distinct issuer + OpenID Federation trust anchor

Since `federation-p1` this PF's OAuth issuer (and therefore `pop_audience`) is its public URL
`http://35.223.142.97` — baked into `data.zip`, so it survives pod replacement. The workload deployment
pins `PF_TOKEN_AUD=http://35.223.142.97` (env overrides discovery in app.py).

The same PF is the federation **trust anchor** for the cross-cloud demo, configured by deployment env:

```
OIDF_FEDERATION_TRUST_ANCHORS=http://35.223.142.97
OIDF_FEDERATION_SUBORDINATES=http://35.223.142.97,http://<eks-elb-hostname>
OIDF_FEDERATION_TRUST_CONTROLLER_HOST=http://35.223.142.97
OIDF_FEDERATION_ATTESTER_JWKS=<mock-attester-1 public JWKS>
```

It serves `/.well-known/openid-federation` plus `/federation/{entity,fetch,list,resolve}`. Subordinate
statements about the EKS PF carry the EKS PF's **own** federation key (fetched from its entity
configuration), and both entity configurations publish the attester's public key under
`metadata.oauth_client_attester.jwks` — a remote AS resolves attestation-signing keys through the
chain instead of a locally pinned attester file. Chain verified leaf(EKS)→anchor. The AWS leaf side is
in `deploy/aws-bedrock-demo/DEMO-STATE.md`.

## Live cross-cloud agent chain

One call runs a request through three agents in two clouds and into a resource server:

```
curl -s -X POST http://34.70.227.225/run | jq
```

Agents and clients: A = `chain-agent-a` (SA payment-agent → `demo-attest-gke-native`), B = the
Bedrock AgentCore runtime (`demo-attest-agentcore`), C = `chain-agent-c` (SA delivery-agent →
`demo-attest-gke-delivery`, LB 136.112.33.181), resource = `mock-resource` on EKS. Full tree and
runbook in `deploy/cross-cloud-chain/`. Both PFs run `pingfederate:federation-p3`, whose `data.zip`
includes the delivery client, so a fresh pod boots with the whole chain working.

## Cross-cloud token exchange (P2, image `pingfederate:federation-p2b`)

Both PFs run an RFC 8693 delegation plane, config in `pf/terraform/token-exchange.tf` (+
`imports-issuer.tf`/`adopted-issuer.tf`) and baked into `data.zip`:

- `attestJwtATM` stamps `iss` = the PF's public issuer; `subjectJwtProc` validates it (a JWT token
  processor rejects issuerless subject tokens with "Invalid Issuer").
- The token-exchange mapping's `act` is built by `ClientAttestationUtils.delegationActChain` —
  `{"sub": <exchanging client>, "act": <subject token's chain>}`, one level per hop. (PF 13 mapping
  OGNL cannot reference token-exchange policy contract attributes, only `context.*`.)
- The EKS PF adds `gkeSubjectProc` (subject_token_type `urn:ietf:params:oauth:token-type:jwt`)
  validating GKE-issued tokens against `http://35.223.142.97/pf/JWKS` — the same keys the anchor
  vouches for in its subordinate statement.
- `demo-attest-agentcore` and `demo-attest-gke-native` carry the `TOKEN_EXCHANGE` grant on both PFs.

Verified live, both hops, attestation-only client auth throughout: A (GKE workload) → B (AgentCore,
AWS attestation presented at the **GKE** PF) → token2 `act={B,{A}}` → C (GKE attestation presented at
the **EKS** PF, subject_token = token2) → token3 `sub=A`, `act={C,{B,{A}}}`. Negative: a PoP minted
for one AS is rejected 401 by the other. Drivers: `hop1_exchange.py` / `hop2_inpod.py` (session
scratchpad; to be productised as the P3 agents).

## What the demo does

A workload authenticates to PingFederate using a platform-attested identity, with no client secret and no
`client_id`. The attestation is its only credential; `ClientAttestationAuthFilter` over `/as/token.oauth2`
turns the two attestation headers into a `private_key_jwt` for PF.

Three evidence types, one issuance flow: `spiffe-jwt` (real SPIRE SVID), `gke-sa-token` (GKE projected SA
token, validated by `GkeTokenValidator`), `gcp-id-token` (Google SA ID token, validated by
`GcpSaTokenValidator`).

## Live surfaces

- GKE demo console: http://34.171.232.146/
- Railway workload console: https://railway-workload-production.up.railway.app/
- Explainer: https://gke-spiffe-demo-production.up.railway.app/
- Architecture: https://gke-spiffe-demo-production.up.railway.app/architecture.html
- Client SDK (one-call): github.com/dphhyland/client-attestation-sdk-polyglot (PR #2)

## Reproduce this exact state

```sh
# PF (durable, config baked in — no Terraform needed on a fresh pod)
kubectl -n pf set image deploy/pingfederate \
  pingfederate=us-central1-docker.pkg.dev/pf-spiffe-demo-7264/demo/pingfederate@sha256:b731f697…

# Agent
kubectl -n demo set image deploy/payment-agent \
  agent=us-central1-docker.pkg.dev/pf-spiffe-demo-7264/demo/agent@sha256:3979b01a…
```

Verify: `curl -s -X POST http://34.171.232.146/invoke | jq '{mint_status, pf_status}'` → both 200.

## If the config ever drifts (rebuild data.zip)

Only needed if a client changes. Otherwise the baked image is self-sufficient.

```sh
# 1. apply Terraform to a running PF (bridge JWKS from the pf-bridge-key secret)
# 2. export the archive and overwrite the build-context data.zip:
curl -sk -u administrator:$PW -H 'X-XSRF-Header: PingFederate' \
  -o deploy/pingfederate/data.zip https://localhost:9999/pf-admin-api/v1/configArchive/export
# 3. rebuild + push deploy/pingfederate (baked-config), roll the deployment.
```
