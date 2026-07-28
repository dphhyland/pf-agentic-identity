# Locked AWS demo state

The live AWS demo. Recorded 2026-07-28 (updated same day: distinct issuer + federation leaf). Account
971422710168, region ap-southeast-2.

## Distinct issuer + OpenID Federation leaf

Since image `…dkr.ecr…/pingfederate:federation-p1` (`sha256:0af98269…`) this PF's OAuth issuer (and
`pop_audience`) is `http://<its public ELB hostname>` — baked into `data.zip`. The EKS workload pins
`PF_TOKEN_AUD=<issuer>`; the AgentCore agent reads `pop_audience` from discovery and adapts on its own.

The PF is a federation **leaf** under the GKE anchor (`http://35.223.142.97`), via deployment env:

```
OIDF_FEDERATION_TRUST_ANCHORS=http://35.223.142.97
OIDF_FEDERATION_TRUST_CONTROLLER_HOST=http://35.223.142.97
OIDF_FEDERATION_ATTESTER_JWKS=<mock-attester-1 public JWKS>
```

Its entity configuration at `/.well-known/openid-federation` carries `authority_hints` → the anchor; the
anchor's subordinate statement vouches for this PF's own federation signing key. Chain verified
leaf→anchor. Anchor details: `deploy/gke-spiffe-demo/DEMO-STATE.md`.

## The AgentCore runtime now also plays chain agent B

Since the cross-cloud chain landed (`deploy/cross-cloud-chain/`), the runtime
`attest_demo_agent-2iANTrG4vB` runs image `agentcore-agent:chain-v2` and serves two modes on
`InvokeAgentRuntime`:

- **empty payload** → the standalone AWS attestation demo described below (`client_credentials` at
  its own AS), unchanged;
- **`{"subject_token": …}`** → chain agent B: exchanges that token at the **GCP** AS using its own
  AWS-attested credential, then calls agent C.

## What's live

PingFederate runs on EKS and serves two AWS evidence paths, both verified end-to-end (no client secret):

| Path | Workload | Evidence | Token `sub` |
|---|---|---|---|
| `eks-sa-token` | EKS pod (IRSA) | projected SA token, cluster OIDC JWKS | `spiffe://eks.demo.aws/ns/demo/sa/payment-agent` |
| `aws-sts-web-identity` | **Bedrock AgentCore Runtime agent** | `sts:GetWebIdentityToken` OIDC JWT | `spiffe://971422710168.aws.demo/aws/971422710168/role/agentcore-attest-demo` |

Over-ceiling (APAC) → 403 on both. Same attester also serves the GCP demo (one attester, two clouds).

The AgentCore path runs in the real managed runtime: `InvokeAgentRuntime` on
`arn:aws:bedrock-agentcore:ap-southeast-2:971422710168:runtime/attest_demo_agent-2iANTrG4vB` returns
mint 200 / pf 200. The agent (container `agentcore-agent:latest`, arm64, HTTP protocol, PUBLIC network)
reaches PF over its public load balancer
`aedf8922e217a444d8260c5a4cbb2c45-1761953978.ap-southeast-2.elb.amazonaws.com`.

## Coordinates

- **EKS cluster** `attest-demo`, ap-southeast-2, 2× t3.large, Kubernetes 1.31, IRSA (`--with-oidc`).
- **Cluster OIDC issuer** `https://oidc.eks.ap-southeast-2.amazonaws.com/id/9B3C4E687CA92CD350F551C7E0C69A07`
  (JWKS at `<issuer>/keys`).
- **Account STS issuer** (Outbound Identity Federation) `https://a188ffe2-94b1-49e6-a35a-a937a3f68d5b.tokens.sts.global.api.aws`
  (JWKS at `<issuer>/.well-known/jwks.json`). Enabled once with `aws iam enable-outbound-web-identity-federation`.
- **AgentCore role** `arn:aws:iam::971422710168:role/agentcore-attest-demo` (trusts `bedrock-agentcore.amazonaws.com`
  and the demo user; has `sts:GetWebIdentityToken`).
- **ECR images** `971422710168.dkr.ecr.ap-southeast-2.amazonaws.com/pingfederate:latest` (the baked-aws PF, same
  digest as the GKE `baked-aws`) and `.../eks-workload:latest`.
- **PF admin** password `2FederateM0re` (baked in data.zip); bridge key + DevOps licence secrets copied from
  the GKE cluster (`pf-bridge-key`, `pf-devops-license`).

## Run the checks

```sh
export AWS_PROFILE=attest-demo AWS_REGION=ap-southeast-2
EKS="cluade@attest-demo.ap-southeast-2.eksctl.io"

# EKS IRSA path — from inside the workload pod
POD=$(kubectl --context "$EKS" -n demo get pod -l app=payment-agent -o jsonpath='{.items[0].metadata.name}')
kubectl --context "$EKS" -n demo exec "$POD" -- python3 -c \
  "import app,json; print(json.dumps({k:app.invoke().get(k) for k in ('mint_status','pf_status')}))"

# AgentCore path — assume the role, run agentcore/agent.py against the EKS PF (port-forward 19080→9080)
```

## Durable

Both clients are baked into the PF image. The EKS PF runs the re-baked image
`971422710168.dkr.ecr.ap-southeast-2.amazonaws.com/pingfederate@sha256:399d8e6dcc8a7287a499d7bd4e2bd0af6e5778ebefdcacdf2dfe466d55e39d74`,
whose `data.zip` includes `demo-attest-eks` and `demo-attest-agentcore`. A fresh pod boots with both, no
Terraform or admin-API step. Verified: after rolling to this image, `demo-attest-eks` is present as
`PRIVATE_KEY_JWT` straight from the baked config.

## Teardown

`eksctl delete cluster --name attest-demo --region ap-southeast-2` (removes EKS + nodes). Delete the ECR
repos, the `agentcore-attest-demo` role, and disable outbound federation if not needed. Delete the demo
IAM access key in the console.
