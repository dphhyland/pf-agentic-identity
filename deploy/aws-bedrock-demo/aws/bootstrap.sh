#!/usr/bin/env bash
# Stand up the AWS side of the demo from nothing: EKS cluster, ECR repos, the AgentCore execution
# role, AWS Outbound Identity Federation, and the secrets PingFederate needs.
#
# Idempotent — every step checks for the resource first, so re-running after a partial failure is
# safe and cheap. It does NOT deploy PingFederate or the agents; that is deploy-pf.sh and
# ../../cross-cloud-chain/deploy.sh.
#
# Why boto3 and not the aws CLI: the 2025 features this demo depends on
# (sts:GetWebIdentityToken, iam:EnableOutboundWebIdentityFederation, bedrock-agentcore-control)
# are missing from older CLI builds. A venv with a current botocore is the reliable path.
#
# Prerequisites: eksctl, kubectl, docker, and an AWS profile with admin on the demo account.
set -euo pipefail

REGION="${AWS_REGION:-ap-southeast-2}"
PROFILE="${AWS_PROFILE:-attest-demo}"
CLUSTER="${CLUSTER_NAME:-attest-demo}"
AGENT_ROLE="${AGENT_ROLE:-agentcore-attest-demo}"
VENV="${AWS_VENV:-/private/tmp/aws-venv}"
GKE_CONTEXT="${GKE_CONTEXT:-}"   # set to copy the bridge/licence secrets from the GKE cluster
REPOS=(pingfederate eks-workload agentcore-agent mock-resource)

export AWS_REGION="$REGION" AWS_PROFILE="$PROFILE"
say() { printf '\n==> %s\n' "$*"; }

say "checking prerequisites"
for tool in eksctl kubectl docker; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done
if [ ! -x "$VENV/bin/python" ]; then
  say "creating boto3 venv at $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" -q install -U boto3
fi
PY="$VENV/bin/python"
"$PY" -c "import boto3,botocore;assert hasattr(boto3.client('sts',region_name='$REGION'),'get_web_identity_token'), \
  'botocore too old for sts:GetWebIdentityToken - pip install -U boto3'" \
  || { echo "boto3 in $VENV is too old; run: $VENV/bin/pip install -U boto3" >&2; exit 1; }

ACCOUNT=$("$PY" -c "import boto3;print(boto3.client('sts',region_name='$REGION').get_caller_identity()['Account'])")
say "account $ACCOUNT, region $REGION"

# ── EKS cluster (IRSA on, so pods get projected SA tokens with a public OIDC issuer) ──────────────
if eksctl get cluster --name "$CLUSTER" --region "$REGION" >/dev/null 2>&1; then
  say "cluster $CLUSTER already exists"
else
  say "creating EKS cluster $CLUSTER (~15 min)"
  eksctl create cluster --name "$CLUSTER" --region "$REGION" \
    --node-type t3.large --nodes 2 --version 1.31 --with-oidc
fi
eksctl utils write-kubeconfig --cluster "$CLUSTER" --region "$REGION" >/dev/null
CTX=$(kubectl config current-context)
say "kubectl context: $CTX"

OIDC_ISSUER=$("$PY" - <<EOF
import boto3
c=boto3.client('eks',region_name="$REGION").describe_cluster(name="$CLUSTER")['cluster']
print(c['identity']['oidc']['issuer'])
EOF
)
# NB: the EKS cluster JWKS lives at <issuer>/keys, NOT /.well-known/jwks.json. This is the one place
# EKS diverges from GKE, and the attester's eks-sa-token validator depends on getting it right.
say "cluster OIDC issuer: $OIDC_ISSUER"
say "cluster OIDC JWKS:   $OIDC_ISSUER/keys"

# ── ECR repositories ─────────────────────────────────────────────────────────────────────────────
say "ensuring ECR repositories"
"$PY" - <<EOF
import boto3
c=boto3.client('ecr',region_name="$REGION")
have={r['repositoryName'] for r in c.describe_repositories()['repositories']}
for name in "${REPOS[*]}".split():
    if name in have: print('  exists  '+name)
    else: c.create_repository(repositoryName=name); print('  created '+name)
EOF

# ── AWS Outbound Identity Federation: the account-level OIDC issuer for workload tokens ──────────
say "enabling AWS Outbound Identity Federation (account STS issuer)"
STS_ISSUER=$("$PY" - <<'EOF'
import boto3, os, botocore
region = os.environ["AWS_REGION"]
iam = boto3.client("iam", region_name=region)
try:
    iam.enable_outbound_web_identity_federation()
except botocore.exceptions.ClientError as e:
    # already enabled is not an error for our purposes
    if e.response["Error"]["Code"] not in ("InvalidActionException", "ValidationError",
                                           "EntityAlreadyExists", "OperationNotPermitted"):
        raise
sts = boto3.client("sts", region_name=region)
# The issuer is stamped into any token this account mints; read it back rather than guessing.
tok = sts.get_web_identity_token(Audience=["https://attester.example.com"],
                                 SigningAlgorithm="RS256")["WebIdentityToken"]
import base64, json
p = tok.split(".")[1]
print(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))["iss"])
EOF
)
say "account STS issuer: $STS_ISSUER"
say "account STS JWKS:   $STS_ISSUER/.well-known/jwks.json"

# ── AgentCore execution role ─────────────────────────────────────────────────────────────────────
say "ensuring IAM role $AGENT_ROLE"
"$PY" - <<EOF
import boto3, json, botocore
iam = boto3.client("iam", region_name="$REGION")
trust = {"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Principal":{"Service":"bedrock-agentcore.amazonaws.com"},"Action":"sts:AssumeRole"},
  {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::$ACCOUNT:root"},"Action":"sts:AssumeRole"}]}
try:
    iam.create_role(RoleName="$AGENT_ROLE", AssumeRolePolicyDocument=json.dumps(trust),
                    Description="Bedrock AgentCore execution role for the client-attestation demo")
    print("  created")
except botocore.exceptions.ClientError as e:
    if e.response["Error"]["Code"] != "EntityAlreadyExists": raise
    iam.update_assume_role_policy(RoleName="$AGENT_ROLE", PolicyDocument=json.dumps(trust))
    print("  exists (trust policy refreshed)")
# GetWebIdentityToken is what makes the agent attestable without a secret.
iam.put_role_policy(RoleName="$AGENT_ROLE", PolicyName="attest-demo",
  PolicyDocument=json.dumps({"Version":"2012-10-17","Statement":[
    {"Effect":"Allow","Action":["sts:GetWebIdentityToken"],"Resource":"*"},
    {"Effect":"Allow","Action":["ecr:GetAuthorizationToken","ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer","logs:CreateLogStream","logs:PutLogEvents",
      "logs:CreateLogGroup","logs:DescribeLogStreams"],"Resource":"*"}]}))
print("  policy attached")
EOF

# ── secrets PingFederate needs (bridge key + DevOps licence) ──────────────────────────────────────
kubectl create namespace pf --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create namespace demo --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if [ -n "$GKE_CONTEXT" ]; then
  say "copying pf-bridge-key and pf-devops-license from $GKE_CONTEXT"
  for secret in pf-bridge-key pf-devops-license; do
    kubectl --context "$GKE_CONTEXT" -n pf get secret "$secret" -o yaml \
      | grep -vE '^\s+(uid|resourceVersion|creationTimestamp|namespace|selfLink):' \
      | kubectl apply -n pf -f - >/dev/null && echo "  $secret"
  done
else
  cat <<'NOTE'

  !! No GKE_CONTEXT set, so the PF secrets were NOT copied. PingFederate will not boot without them.
     Either re-run with GKE_CONTEXT=<gke kubectl context>, or create them by hand:
       kubectl -n pf create secret generic pf-bridge-key --from-file=private-jwk=<bridge.jwk>
       kubectl -n pf create secret generic pf-devops-license \
         --from-literal=PING_IDENTITY_DEVOPS_USER=<email> --from-literal=PING_IDENTITY_DEVOPS_KEY=<key>
     A fresh bridge key comes from ../../gke-spiffe-demo/pf/gen-bridge-key.sh — but note that BOTH
     PingFederates and every attestation client must carry the SAME key, so generating a new one
     means re-applying terraform on both sides.
NOTE
fi

cat <<SUMMARY

==> done. Values the rest of the deploy needs:

  export AWS_ACCOUNT=$ACCOUNT
  export EKS_CONTEXT="$CTX"
  export EKS_CLUSTER_ISSUER="$OIDC_ISSUER"
  export EKS_JWKS_URL="$OIDC_ISSUER/keys"
  export AWS_STS_ISSUER="$STS_ISSUER"
  export AWS_STS_JWKS_URL="$STS_ISSUER/.well-known/jwks.json"
  export AGENT_EXECUTION_ROLE="$AGENT_ROLE"
  export ECR="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"

Next: deploy PingFederate (see ../DEMO-STATE.md), apply ../pf/terraform, then
../../cross-cloud-chain/deploy.sh for the agents and the resource.
SUMMARY
