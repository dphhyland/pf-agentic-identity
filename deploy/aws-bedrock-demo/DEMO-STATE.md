# Locked AWS demo state

The live AWS demo. Recorded 2026-07-28. Account 971422710168, region ap-southeast-2.

## What's live

PingFederate runs on EKS and serves two AWS evidence paths, both verified end-to-end (no client secret):

| Path | Workload | Evidence | Token `sub` |
|---|---|---|---|
| `eks-sa-token` | EKS pod (IRSA) | projected SA token, cluster OIDC JWKS | `spiffe://eks.demo.aws/ns/demo/sa/payment-agent` |
| `aws-sts-web-identity` | Bedrock AgentCore agent | `sts:GetWebIdentityToken` OIDC JWT | `spiffe://971422710168.aws.demo/aws/971422710168/role/agentcore-attest-demo` |

Over-ceiling (APAC) → 403 on both. Same attester also serves the GCP demo (one attester, two clouds).

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

## Not yet durable

`demo-attest-eks` was added to the running EKS PF via the admin API, so a PF pod restart loses it (the
baked data.zip predates it). To lock in: export the EKS PF config archive, rebuild the ECR PF image, roll.
`demo-attest-agentcore` IS baked in.

## Teardown

`eksctl delete cluster --name attest-demo --region ap-southeast-2` (removes EKS + nodes). Delete the ECR
repos, the `agentcore-attest-demo` role, and disable outbound federation if not needed. Delete the demo
IAM access key in the console.
