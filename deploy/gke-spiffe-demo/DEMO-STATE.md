# Locked demo state (GKE)

The exact state the live GKE + Railway demo runs at. Recorded 2026-07-28.

## Running images (by digest)

| Component | Image |
|---|---|
| PingFederate | `us-central1-docker.pkg.dev/pf-spiffe-demo-7264/demo/pingfederate@sha256:b731f69745556df12a82bd10d9a23b6d06b6266f9cc0488046112cfd77f7020e` |
| GKE agent | `us-central1-docker.pkg.dev/pf-spiffe-demo-7264/demo/agent@sha256:3979b01acf26a4a4ef26e82a227b44032ee190d74154c28ede6fa6c9e41d8e3e` |

The PF image is the **baked-config** build: the four attestation clients are baked into `data.zip` as
`PRIVATE_KEY_JWT` with the bridge public JWKS, so a fresh pod boots working with no Terraform step. The
bridge private key lives only in the k8s secret `pf-bridge-key` (data key `private-jwk`, kid
`cJ-4Fg9oUAar1TNoqvgJdERxxSZfTPnNiUJ_JT1Jvcc`).

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
