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
#
# Hardened 2026-08-02 after a real incident: the scratch python venv this script drives AWS through
# lost boto3 mid-session (pip and the package vanished; the interpreter symlink was still intact, so
# nothing upstream noticed). The AgentCore step's blanket `|| echo "none found"` swallowed the
# resulting ModuleNotFoundError as if no runtimes existed, and the script was invoked as
# `./teardown.sh --yes | tail -20`, whose exit code is tail's, not the script's — so the caller saw
# "completed, exit code 0" while the AgentCore runtime and IAM role were still live. It was only
# caught by an independent check run by hand afterward. Two changes close this:
#   1. every python step is checked explicitly and reported in a final summary — nothing is silently
#      swallowed, and a broken venv is diagnosed by name instead of surfacing as a bare traceback deep
#      in the run;
#   2. the script ends with its OWN independent verification of AWS's actual state, using the aws CLI
#      rather than the same venv the steps above went through — so a broken venv cannot also blind the
#      check that is supposed to catch it. Do not pipe this script's output through `tail`; if you must
#      truncate it, check ${PIPESTATUS[0]}, not $?, for the real exit code.
set -uo pipefail   # deliberately NOT -e — see run_py() below for why

REGION="${AWS_REGION:-ap-southeast-2}"
PROFILE="${AWS_PROFILE:-attest-demo}"
CLUSTER="${CLUSTER_NAME:-attest-demo}"
AGENT_ROLE="${AGENT_ROLE:-agentcore-attest-demo}"
VENV="${AWS_VENV:-/private/tmp/aws-venv}"
KEEP_ECR="${KEEP_ECR:-0}"   # 1 keeps the images, so a rebuild does not re-push gigabytes
export AWS_REGION="$REGION" AWS_PROFILE="$PROFILE"
PY="$VENV/bin/python"

FAILURES=()
say()  { printf '\n==> %s\n' "$*"; }
fail() { printf '\n!! %s\n' "$*" >&2; FAILURES+=("$*"); }

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

# ── preflight: confirm the python/boto3 side actually works before relying on it below ────────────
# Checked ONCE, up front, so a broken venv produces one clear diagnostic here instead of three
# separate confusing tracebacks scattered through the run. Does not abort the script: cluster and
# LoadBalancer deletion (the expensive resources) go through eksctl/kubectl, not python, so they must
# still be attempted even if this check fails.
say "checking the python/boto3 side ($PY)"
PY_OK=1
if [ ! -x "$PY" ]; then
  fail "no python at $PY — the venv is missing. Rebuild it: python3 -m venv $VENV && $VENV/bin/pip install -U boto3"
  PY_OK=0
elif ! BOTO3_CHECK=$("$PY" -c "import boto3; print(boto3.__version__)" 2>&1); then
  fail "python at $PY cannot import boto3 ($BOTO3_CHECK) — rebuild it: $VENV/bin/pip install -U boto3"
  PY_OK=0
else
  echo "  ok (boto3 $BOTO3_CHECK)"
fi

# Runs a python heredoc step by writing it to a temp file first (heredocs and function-local
# variables interact badly). Records failure in FAILURES rather than aborting the script — every
# later step, including the final verification, still runs regardless of an earlier one breaking.
run_py() {
  local label="$1" script="$2" out status
  if [ "$PY_OK" != "1" ]; then
    fail "$label — skipped (python/boto3 unavailable, see preflight above)"
    return 1
  fi
  out=$("$PY" -c "$script" 2>&1); status=$?
  echo "$out"
  if [ "$status" -ne 0 ]; then
    fail "$label — python step exited $status"
    return 1
  fi
}

# ── AgentCore runtimes (before the cluster: they are account-level, not cluster resources) ────────
say "deleting Bedrock AgentCore runtimes tagged for this demo"
run_py "AgentCore runtime deletion" '
import boto3, botocore, os
region = os.environ["AWS_REGION"]
try:
    c = boto3.client("bedrock-agentcore-control", region_name=region)
except botocore.exceptions.UnknownServiceError:
    # Genuinely unsupported by this botocore build (older CLI) - not the same as a broken venv, and
    # not something to hide as a plain "none found".
    print("  bedrock-agentcore-control not in this botocore build - cannot check; upgrade boto3 to verify")
else:
    found = [rt for rt in c.list_agent_runtimes().get("agentRuntimes", []) if "attest" in rt.get("agentRuntimeName", "")]
    if not found:
        print("  none found")
    for rt in found:
        c.delete_agent_runtime(agentRuntimeId=rt["agentRuntimeId"])
        print("  deleted " + rt["agentRuntimeName"])
'

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
  if ! eksctl delete cluster --name "$CLUSTER" --region "$REGION" --wait; then
    fail "eksctl delete cluster failed — cluster may be partially deleted; check the console"
  fi
else
  say "cluster $CLUSTER not present"
fi

# ── ECR ──────────────────────────────────────────────────────────────────────────────────────────
if [ "$KEEP_ECR" = "1" ]; then
  say "keeping ECR repositories (KEEP_ECR=1)"
else
  say "deleting ECR repositories"
  run_py "ECR repository deletion" '
import boto3, os
c = boto3.client("ecr", region_name=os.environ["AWS_REGION"])
for name in ("pingfederate", "eks-workload", "agentcore-agent", "mock-resource"):
    try:
        c.delete_repository(repositoryName=name, force=True); print("  deleted " + name)
    except c.exceptions.RepositoryNotFoundException:
        print("  absent  " + name)
'
fi

# ── IAM role ─────────────────────────────────────────────────────────────────────────────────────
say "deleting IAM role $AGENT_ROLE"
run_py "IAM role deletion" "
import boto3, botocore, os
iam = boto3.client('iam', region_name=os.environ['AWS_REGION'])
role = '$AGENT_ROLE'
try:
    for p in iam.list_role_policies(RoleName=role)['PolicyNames']:
        iam.delete_role_policy(RoleName=role, PolicyName=p)
    iam.delete_role(RoleName=role); print('  deleted')
except botocore.exceptions.ClientError as e:
    if e.response['Error']['Code'] != 'NoSuchEntity': raise
    print('  absent')
"

# ── independent verification ────────────────────────────────────────────────────────────────────
# Deliberately via the aws CLI, not $PY/boto3: the whole point is to catch a broken venv, which a
# venv-dependent check cannot do. This is the step that would have caught the 2026-08-02 incident on
# its own even if every step above had gone unnoticed.
say "verifying actual AWS state (aws CLI, independent of the venv above)"
if ! command -v aws >/dev/null; then
  fail "aws CLI not found — cannot verify teardown; check the console manually"
else
  clusters=$(aws eks list-clusters --region "$REGION" --query 'clusters' --output text 2>&1)
  if [ $? -ne 0 ]; then
    fail "could not query EKS clusters to verify teardown: $clusters"
  elif [ -n "$clusters" ]; then
    fail "EKS cluster(s) still present: $clusters"
  else
    echo "  EKS clusters: none"
  fi

  elbv2_count=$(aws elbv2 describe-load-balancers --region "$REGION" --query 'length(LoadBalancers)' --output text 2>&1)
  classic_count=$(aws elb describe-load-balancers --region "$REGION" --query 'length(LoadBalancerDescriptions)' --output text 2>&1)
  if [ "$elbv2_count" != "0" ] || [ "$classic_count" != "0" ]; then
    fail "load balancers still present (v2: $elbv2_count, classic: $classic_count) — these cost money while orphaned"
  else
    echo "  load balancers: none"
  fi

  if aws iam get-role --role-name "$AGENT_ROLE" >/dev/null 2>&1; then
    fail "IAM role $AGENT_ROLE still present"
  else
    echo "  IAM role: deleted"
  fi
fi

# AgentCore has no aws-CLI-only check (the stock CLI predates bedrock-agentcore-control), so this part
# of verification still needs the venv. If the venv is broken, say so explicitly rather than skip it
# quietly — that silence is exactly what caused the incident this hardening responds to.
if [ "$PY_OK" = "1" ]; then
  remaining=$("$PY" -c "
import boto3, os
c = boto3.client('bedrock-agentcore-control', region_name=os.environ['AWS_REGION'])
print(','.join(r.get('agentRuntimeName') for r in c.list_agent_runtimes().get('agentRuntimes', [])))
" 2>&1)
  if [ $? -ne 0 ]; then
    fail "could not verify AgentCore runtime deletion: $remaining"
  elif [ -n "$remaining" ]; then
    fail "AgentCore runtime(s) still present: $remaining (may still be DELETING — re-check shortly)"
  else
    echo "  AgentCore runtimes: none"
  fi
else
  fail "could not verify AgentCore runtimes — python/boto3 unavailable (see preflight above)"
fi

# ── final verdict ────────────────────────────────────────────────────────────────────────────────
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo
  echo "############################################################"
  echo "  TEARDOWN INCOMPLETE — ${#FAILURES[@]} problem(s):"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  echo "############################################################"
  exit 1
fi

cat <<'SUMMARY'

==> AWS side torn down and independently verified.

Left deliberately in place:
  - AWS Outbound Identity Federation stays enabled (account-level, no cost, and disabling it
    changes the account STS issuer, which would invalidate every attestation_evidence_issuer
    already configured). Disable manually only if you are done with the demo for good.
  - The demo IAM user and its access key. Rotate or delete in the console.
SUMMARY
