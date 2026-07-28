# AWS Bedrock AgentCore demo

The AWS twin of `deploy/gke-spiffe-demo`. A workload authenticates to a PingFederate running on AWS using
an AWS-attested identity, with no client secret and no `client_id`. Same attester and
`ClientAttestationAuthFilter` model as the GKE demo; the only new code is two AWS evidence validators
(already in the servlet: `EksTokenValidator`, `AwsStsWebIdentityValidator`).

## Two evidence paths, both AWS-signed JWTs

| Path | Evidence | Validated against | SPIFFE ID |
|---|---|---|---|
| **EKS workload** (`eks-sa-token`) | IRSA projected SA token | the cluster OIDC JWKS (`<issuer>/keys`) | `spiffe://<eks-td>/ns/demo/sa/payment-agent` |
| **Bedrock AgentCore** (`aws-sts-web-identity`) | `sts:GetWebIdentityToken` OIDC JWT | the account issuer JWKS (`<issuer>/.well-known/jwks.json`) | `spiffe://<aws-td>/aws/<account>/role/<AgentExecutionRole>` |

Why two: AgentCore's own workload access token is opaque and first-party only, so it cannot be presented to
an external AS. But an AgentCore agent runs under an IAM role, so it calls `sts:GetWebIdentityToken` (AWS
Outbound Identity Federation, GA re:Invent 2025) to get an AWS-signed OIDC JWT it can present. The EKS path
is the direct analogue of the GKE demo. See `RESEARCH.md` for the full evidence analysis.

## Prerequisites (what I need from you)

1. **AWS credentials** for an IAM principal with enough to run the demo. Starting policy (tighten later):
   `eks:*`, `ec2:*` (EKS networking), `ecr:*`, `iam:*` (roles, OIDC provider, outbound federation),
   `sts:GetWebIdentityToken`, `bedrock-agentcore:*` and `bedrock:*`, `elasticloadbalancing:*`.
2. **Region** with Bedrock AgentCore (suggest `us-east-1` or `us-west-2`).
3. **One-time account enable**: `aws iam enable-outbound-web-identity-federation`. It returns the account
   issuer URL (`https://<uuid>.tokens.sts.global.api.aws`) the attester will trust. I can run this if the
   creds allow it.
4. The AgentCore agent's execution role needs `sts:GetWebIdentityToken` and the
   `sts:IdentityTokenAudience` condition pinned to the attester audience.

## Deploy (when creds land)

```sh
REGION=us-east-1
CLUSTER=attest-demo

# 1. EKS cluster
eksctl create cluster --name $CLUSTER --region $REGION --nodes 2 --node-type t3.large \
  --with-oidc                       # IRSA needs the cluster OIDC provider

# 2. PingFederate on EKS — reuse the baked-config image from the GKE build, or rebuild from
#    deploy/pingfederate. Same manifests as deploy/gke-spiffe-demo/pf, plus the pf-bridge-key secret.
kubectl create namespace pf
kubectl -n pf create secret generic pf-bridge-key --from-file=private-jwk=bridge-private.jwk
kubectl -n pf apply -f pf/pingfederate.yaml     # copy from the GKE tree, ECR image ref

# 3. Attester JWKS trust for the two paths
EKS_ISSUER=$(aws eks describe-cluster --name $CLUSTER --query 'cluster.identity.oidc.issuer' --output text)
STS_ISSUER=$(aws iam enable-outbound-web-identity-federation --query IssuerUrl --output text)

# 4. Terraform: the two AWS clients (private_key_jwt + bridge). Copy the shared PF config files
#    (extended-properties, attestJwtATM ATM, the client_credentials access-token mapping) from
#    deploy/gke-spiffe-demo/pf/terraform, then:
cd pf/terraform
export TF_VAR_pf_admin_password=... TF_VAR_bridge_public_jwks="$(cat ../../bridge-public.jwks)"
export TF_VAR_attester_signing_jwk="$(cat ../../attester-signing.jwk)"
export TF_VAR_eks_cluster_issuer="$EKS_ISSUER" TF_VAR_eks_jwks_url="$EKS_ISSUER/keys"
export TF_VAR_aws_account_id=$(aws sts get-caller-identity --query Account --output text)
export TF_VAR_aws_trust_domain="${TF_VAR_aws_account_id}.aws.demo"
export TF_VAR_aws_sts_issuer="$STS_ISSUER" TF_VAR_aws_sts_jwks_url="$STS_ISSUER/.well-known/jwks.json"
export TF_VAR_agent_execution_role=agentcore-attest-demo
terraform init && terraform apply

# 5. EKS workload
docker build -t $ECR/eks-workload workload && docker push $ECR/eks-workload
sed "s#IMAGE#$ECR/eks-workload#" workload/workload.yaml | kubectl apply -f -

# 6. Bedrock AgentCore agent (execution role = agentcore-attest-demo, with sts:GetWebIdentityToken)
#    deploy agentcore/agent.py to AgentCore Runtime; ATTESTER_BASE_URL points at PF.
```

## Verify

```sh
# EKS path
kubectl -n demo exec deploy/payment-agent -- \
  sh -c 'python3 -c "import app,json;print(json.dumps(app.invoke(),indent=2))"'
#   → mint_status 200, pf_status 200, sub = spiffe://<eks-td>/ns/demo/sa/payment-agent

# AgentCore path — invoke the agent; expect the same 200/200 with
#   sub = spiffe://<aws-td>/aws/<account>/role/agentcore-attest-demo
```

Negatives to demonstrate (same as GKE): over-ceiling request → 403, replayed proof → 401, wrong audience →
401, no attestation headers → PF rejects the credential-less request.

## Status

The servlet validators and this tree are built and committed. Deployment is pending AWS credentials.
