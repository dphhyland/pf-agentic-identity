#!/usr/bin/env bash
# Tear the AWS side down. Deletes the cluster (nodes, load balancers), the AgentCore runtime, the
# ECR repositories and the demo IAM role.
#
# Order matters: the AgentCore runtime and any Service of type LoadBalancer must go before the
# cluster, or you are left paying for orphaned ELBs that eksctl will not clean up.
#
# Refuses to run without --yes, because this is not recoverable from the repo alone: the PF config
# archive (data.zip) is encrypted with a master key that is deliberately NOT in git. Read RECOVERY.md
# before tearing down if you intend to rebuild.
set -euo pipefail

REGION="${AWS_REGION:-ap-southeast-2}"
PROFILE="${AWS_PROFILE:-attest-demo}"
CLUSTER="${CLUSTER_NAME:-attest-demo}"
AGENT_ROLE="${AGENT_ROLE:-agentcore-attest-demo}"
VENV="${AWS_VENV:-/private/tmp/aws-venv}"
KEEP_ECR="${KEEP_ECR:-0}"   # 1 keeps the images, so a rebuild does not re-push gigabytes
export AWS_REGION="$REGION" AWS_PROFILE="$PROFILE"
PY="$VENV/bin/python"
say() { printf '\n==> %s\n' "$*"; }

[ "${1:-}" = "--yes" ] || {
  cat >&2 <<'WARN'
Refusing to tear down without --yes.

This deletes the EKS cluster, the AgentCore runtime and (unless KEEP_ECR=1) the container images
including the baked PingFederate. The baked config CANNOT be rebuilt from the repo alone — data.zip
is encrypted with a gitignored master key. See ../RECOVERY.md for the rebuild path, and consider
exporting the config archive first:

  kubectl -n pf port-forward pod/<pf-pod> 29992:9999 &
  curl -sk -u administrator:$PW -H 'X-XSRF-Header: PingFederate' \
    -o data.zip https://localhost:29992/pf-admin-api/v1/configArchive/export

Re-run with:  ./teardown.sh --yes
WARN
  exit 1
}

# ── AgentCore runtimes (before the cluster: they are account-level, not cluster resources) ────────
say "deleting Bedrock AgentCore runtimes tagged for this demo"
"$PY" - <<'EOF' || echo "  (none, or bedrock-agentcore-control unavailable)"
import boto3, os
c = boto3.client("bedrock-agentcore-control", region_name=os.environ["AWS_REGION"])
for rt in c.list_agent_runtimes().get("agentRuntimes", []):
    name = rt.get("agentRuntimeName", "")
    if "attest" not in name:
        continue
    c.delete_agent_runtime(agentRuntimeId=rt["agentRuntimeId"])
    print("  deleted " + name)
EOF

# ── LoadBalancer Services (so their ELBs go with them, not after the cluster) ─────────────────────
if kubectl config get-contexts -o name 2>/dev/null | grep -q "$CLUSTER"; then
  say "deleting LoadBalancer services (releases their ELBs)"
  for ns in demo pf; do
    kubectl -n "$ns" delete svc --all --ignore-not-found --timeout=120s 2>/dev/null || true
  done
  # ELB deletion is asynchronous; give AWS a moment before pulling the cluster out from under it.
  sleep 45
fi

# ── the cluster ──────────────────────────────────────────────────────────────────────────────────
if eksctl get cluster --name "$CLUSTER" --region "$REGION" >/dev/null 2>&1; then
  say "deleting EKS cluster $CLUSTER (~10 min)"
  eksctl delete cluster --name "$CLUSTER" --region "$REGION" --wait
else
  say "cluster $CLUSTER not present"
fi

# ── ECR ──────────────────────────────────────────────────────────────────────────────────────────
if [ "$KEEP_ECR" = "1" ]; then
  say "keeping ECR repositories (KEEP_ECR=1)"
else
  say "deleting ECR repositories"
  "$PY" - <<'EOF'
import boto3, os
c = boto3.client("ecr", region_name=os.environ["AWS_REGION"])
for name in ("pingfederate", "eks-workload", "agentcore-agent", "mock-resource"):
    try:
        c.delete_repository(repositoryName=name, force=True); print("  deleted " + name)
    except c.exceptions.RepositoryNotFoundException:
        print("  absent  " + name)
EOF
fi

# ── IAM role ─────────────────────────────────────────────────────────────────────────────────────
say "deleting IAM role $AGENT_ROLE"
"$PY" - <<EOF
import boto3, botocore
iam = boto3.client("iam", region_name="$REGION")
try:
    for p in iam.list_role_policies(RoleName="$AGENT_ROLE")["PolicyNames"]:
        iam.delete_role_policy(RoleName="$AGENT_ROLE", PolicyName=p)
    iam.delete_role(RoleName="$AGENT_ROLE"); print("  deleted")
except botocore.exceptions.ClientError as e:
    if e.response["Error"]["Code"] != "NoSuchEntity": raise
    print("  absent")
EOF

cat <<'SUMMARY'

==> AWS side torn down.

Left deliberately in place:
  - AWS Outbound Identity Federation stays enabled (account-level, no cost, and disabling it
    changes the account STS issuer, which would invalidate every attestation_evidence_issuer
    already configured). Disable manually only if you are done with the demo for good.
  - The demo IAM user and its access key. Rotate or delete in the console.
SUMMARY
