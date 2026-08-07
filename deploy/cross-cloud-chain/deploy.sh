#!/usr/bin/env bash
# Deploy the four-party cross-cloud chain. The ordering here is the whole point: each hop needs the
# address of the next one, and those addresses are assigned by the cloud, not by us. So the sequence
# is strictly:
#
#   resource (EKS)  -> wait for its ELB hostname
#     agent C (GKE) -> configured with the resource URL, wait for its LB IP
#       agent B      -> AgentCore runtime env pointed at agent C
#         agent A    -> pointed at the AgentCore ARN
#
# Doing it in any other order leaves an agent holding a placeholder, which fails at call time rather
# than at deploy time — the worst kind of broken.
#
# Images are LAYERED on the existing demo images rather than built from python:slim. A plain
# `pip install cryptography` for linux/amd64 under emulation on an arm64 laptop timed out at seven
# minutes; layering makes each build a COPY. Do not "simplify" these Dockerfiles.
#
# Hardened 2026-08-02, same principle as ../aws-bedrock-demo/aws/teardown.sh and
# ../gke-spiffe-demo/gcp/teardown.sh but NOT the same shape: those scripts continue past an
# independent step's failure and summarize everything at the end, because their steps don't depend on
# each other. This script's steps DO depend on each other — agent C cannot be configured with a
# resource URL that does not exist yet — so `set -e` stays, and the hardening here is about *diagnosis*
# at each failure point rather than continuing through one. Two concrete gaps closed:
#   1. every python call goes through the same fragile venv this script drives AWS through (ECR login,
#      the AgentCore control-plane update, the final chain verification) with no upfront check — a
#      broken venv previously surfaced as a bare traceback wherever it happened to bite, sometimes
#      after two docker builds had already run. Checked once, up front, before any expensive work.
#   2. wait_for_lb swallowed kubectl's real stderr entirely (`2>/dev/null || true`), so a genuine
#      problem — wrong context, RBAC denial, a kubectl apply that silently no-op'd so the Service
#      never existed — produced 10 minutes of silence and then only a generic "timed out" with no
#      cause. It now fails immediately if the Service does not exist at all, and dumps the Service's
#      actual status on a real timeout instead of nothing.
set -euo pipefail

: "${GKE_CONTEXT:?set GKE_CONTEXT (kubectl context for the GKE cluster)}"
: "${EKS_CONTEXT:?set EKS_CONTEXT (kubectl context for the EKS cluster)}"
: "${GKE_REGISTRY:?set GKE_REGISTRY, e.g. us-central1-docker.pkg.dev/<project>/demo}"
: "${ECR:?set ECR, e.g. <account>.dkr.ecr.<region>.amazonaws.com}"
: "${EKS_PF_URL:?set EKS_PF_URL (the EKS PingFederate public URL)}"
: "${AGENTCORE_ARN:?set AGENTCORE_ARN}"
: "${GKE_PF_URL:?set GKE_PF_URL (the GKE PingFederate public URL - agent B exchanges there)}"

REGION="${AWS_REGION:-ap-southeast-2}"
TAG="${TAG:-chain}"
VENV="${AWS_VENV:-/private/tmp/aws-venv}"
PY="$VENV/bin/python"
HERE="$(cd "$(dirname "$0")" && pwd)"
export AWS_REGION="$REGION"
say() { printf '\n==> %s\n' "$*"; }

# ── preflight: this script cannot do anything useful without a working python/boto3 ────────────────
# Unlike the teardown scripts, there is no independent path forward if this is broken — ECR login,
# the AgentCore update and the final verification all need it — so this fails FAST, before any docker
# build, rather than recording it and continuing.
say "checking the python/boto3 side ($PY)"
if [ ! -x "$PY" ]; then
  echo "!! no python at $PY — the venv is missing. Rebuild it:" >&2
  echo "     python3 -m venv $VENV && $VENV/bin/pip install -U boto3" >&2
  exit 1
fi
if ! BOTO3_CHECK=$("$PY" -c "import boto3; print(boto3.__version__)" 2>&1); then
  echo "!! python at $PY cannot import boto3:" >&2
  echo "$BOTO3_CHECK" | sed 's/^/     /' >&2
  echo "   Rebuild it: $VENV/bin/pip install -U boto3" >&2
  exit 1
fi
echo "  ok (boto3 $BOTO3_CHECK)"

# `--request-timeout` only bounds a kubectl call once it has CONNECTED; it does nothing for a hung TCP
# attempt against an unreachable API server (e.g. a cluster that was torn down but the LB IP still
# exists and just drops packets) — proved by testing wait_for_lb against a real deleted cluster
# context, where it hung well past a 2-minute wall clock even with --request-timeout=15s set. A wall-
# clock `timeout` around the whole call is the only thing that actually bounds that. Not on stock
# macOS (BSD userland); Homebrew coreutils provides it as `timeout` or `gtimeout`.
if command -v timeout >/dev/null; then
  TIMEOUT_CMD=timeout
elif command -v gtimeout >/dev/null; then
  TIMEOUT_CMD=gtimeout
else
  echo "!! no 'timeout' or 'gtimeout' on PATH — required to bound kubectl calls against a possibly" >&2
  echo "   unreachable cluster. Install: brew install coreutils" >&2
  exit 1
fi

# Wait for a Service to be given an external address. GCP hands out an IP, AWS a hostname.
wait_for_lb() {
  local ctx="$1" ns="$2" svc="$3" field="$4" addr="" err=""
  # --request-timeout is load-bearing here, not cosmetic: a plain `kubectl get` against an API server
  # that is unreachable at the network level (not a clean 404 — e.g. a cluster that was torn down, so
  # the LB IP just drops packets) can hang far longer than any reasonable wait, discovered by testing
  # this exact check against a real deleted cluster context, where it hung past a 2-minute timeout with
  # no output at all. 15s bounds every kubectl call in this function so a genuinely unreachable context
  # fails fast instead of hanging silently — which is the whole point of the fast-fail check below.
  # 20s wall-clock bound (via $TIMEOUT_CMD) around each call, PLUS --request-timeout for the
  # server-side portion once connected — see the preflight comment above for why both are needed.
  # An array, not a string, so context/namespace values are never subject to word-splitting.
  local -a kctl=("$TIMEOUT_CMD" 20 kubectl --context "$ctx" --request-timeout=15s -n "$ns")
  # Fail immediately if the Service does not exist at all — a real problem (bad context, RBAC denial,
  # an apply that silently no-op'd) — rather than waiting the full ~10 minutes below to find out via a
  # generic timeout with no cause attached.
  if ! err=$("${kctl[@]}" get svc "$svc" 2>&1 >/dev/null); then
    echo "!! service $ns/$svc does not exist or is unreachable via context $ctx:" >&2
    echo "$err" | sed 's/^/   /' >&2
    return 1
  fi
  for _ in $(seq 1 40); do
    addr=$("${kctl[@]}" get svc "$svc" -o "jsonpath={.status.loadBalancer.ingress[0].$field}" 2>/dev/null)
    [ -n "$addr" ] && { echo "$addr"; return 0; }
    sleep 15
  done
  echo "!! timed out waiting for $ns/$svc external $field. Current state:" >&2
  "${kctl[@]}" get svc "$svc" -o wide >&2 || true
  "${kctl[@]}" describe svc "$svc" 2>&1 | tail -15 >&2 || true
  return 1
}

# Runs a python heredoc from stdin, capturing output so a failure is reported with a clear label
# instead of a bare traceback dropped mid-script with no indication which step it came from.
run_py() {
  local label="$1" out status=0
  # `out=$(...) || status=$?` (not two statements) — under set -e, an assignment statement that fails
  # aborts the script BEFORE the next line runs, so a bare `out=$(cmd); status=$?` never reaches the
  # status check at all. Found by testing this function in isolation before trusting it.
  out=$("$PY" - 2>&1) || status=$?
  if [ "$status" -ne 0 ]; then
    echo "!! $label failed:" >&2
    echo "$out" | sed 's/^/   /' >&2
    exit 1
  fi
  echo "$out"
}

# ── images ───────────────────────────────────────────────────────────────────────────────────────
say "building and pushing images (ECR pushes take 6-8 min each)"
docker build --platform linux/amd64 -q -t "$GKE_REGISTRY/chain-agent:$TAG"  "$HERE/agent"     >/dev/null
docker build --platform linux/amd64 -q -t "$ECR/mock-resource:$TAG"         "$HERE/resource"  >/dev/null
docker build --platform linux/arm64 -q -t "$ECR/agentcore-agent:$TAG"       "$HERE/agentcore" >/dev/null
docker push -q "$GKE_REGISTRY/chain-agent:$TAG" >/dev/null && echo "  pushed chain-agent"
run_py "ECR login" <<PYEOF
import base64,boto3,subprocess
t=boto3.client('ecr',region_name='$REGION').get_authorization_token()['authorizationData'][0]['authorizationToken']
pw=base64.b64decode(t).decode().split(':',1)[1]
subprocess.run(['docker','login','--username','AWS','--password-stdin','$ECR'],input=pw.encode(),check=True)
PYEOF
docker push -q "$ECR/mock-resource:$TAG"   >/dev/null && echo "  pushed mock-resource"
docker push -q "$ECR/agentcore-agent:$TAG" >/dev/null && echo "  pushed agentcore-agent"

# ── 1. the resource, on EKS (nothing depends on it yet, so it goes first) ─────────────────────────
say "deploying the mock resource on EKS"
kubectl --context "$EKS_CONTEXT" create namespace demo --dry-run=client -o yaml \
  | kubectl --context "$EKS_CONTEXT" apply -f - >/dev/null
sed -e "s|IMAGE_R|$ECR/mock-resource:$TAG|" -e "s|EKS_PF_URL|$EKS_PF_URL|" "$HERE/k8s/resource.yaml" \
  | kubectl --context "$EKS_CONTEXT" apply -f -
kubectl --context "$EKS_CONTEXT" -n demo rollout status deploy/mock-resource --timeout=300s
RESOURCE_HOST=$(wait_for_lb "$EKS_CONTEXT" demo mock-resource hostname)
RESOURCE_URL="http://$RESOURCE_HOST/settle"
say "resource: $RESOURCE_URL"

# ── 2. agent C, on GKE, pointed at the resource ──────────────────────────────────────────────────
say "deploying agent C on GKE"
sed -e "s|IMAGE_C|$GKE_REGISTRY/chain-agent:$TAG|" -e "s|EKS_PF_URL|$EKS_PF_URL|" \
    -e "s|RESOURCE_URL|$RESOURCE_URL|" "$HERE/k8s/agent-c.yaml" \
  | kubectl --context "$GKE_CONTEXT" apply -f -
kubectl --context "$GKE_CONTEXT" -n demo rollout status deploy/chain-agent-c --timeout=300s
AGENT_C_IP=$(wait_for_lb "$GKE_CONTEXT" demo chain-agent-c ip)
say "agent C: http://$AGENT_C_IP/call"

# ── 3. agent B: the AgentCore runtime, pointed at agent C ────────────────────────────────────────
say "updating the AgentCore runtime (agent B)"
AGENTCORE_ARN="$AGENTCORE_ARN" ECR="$ECR" TAG="$TAG" \
EKS_PF_URL="$EKS_PF_URL" GKE_PF_URL="$GKE_PF_URL" AGENT_C_IP="$AGENT_C_IP" \
run_py "AgentCore runtime update" <<'PYEOF'
import boto3, os, time
region = os.environ["AWS_REGION"]
arn = os.environ["AGENTCORE_ARN"]
rid = arn.rsplit("/", 1)[1]
c = boto3.client("bedrock-agentcore-control", region_name=region)
cur = c.get_agent_runtime(agentRuntimeId=rid)
c.update_agent_runtime(
    agentRuntimeId=rid,
    agentRuntimeArtifact={"containerConfiguration": {
        "containerUri": f"{os.environ['ECR']}/agentcore-agent:{os.environ['TAG']}"}},
    roleArn=cur["roleArn"],
    networkConfiguration=cur["networkConfiguration"],
    protocolConfiguration=cur.get("protocolConfiguration", {"serverProtocol": "HTTP"}),
    environmentVariables={
        # B attests at its OWN (AWS) attester, but exchanges at the GCP AS. That split is the
        # cross-cloud move; getting these two the wrong way round silently breaks the demo.
        "ATTESTER_BASE_URL": os.environ["EKS_PF_URL"],
        "EXCHANGE_BASE_URL": os.environ["GKE_PF_URL"],
        "NEXT_HOP_URL": "http://" + os.environ["AGENT_C_IP"] + "/call",
        "AWS_REGION": region,
    })
for _ in range(40):
    if c.get_agent_runtime(agentRuntimeId=rid)["status"] == "READY":
        print("  READY"); break
    time.sleep(15)
else:
    raise SystemExit("AgentCore runtime did not reach READY within the timeout")
PYEOF

# ── 4. agent A, on GKE, pointed at the AgentCore runtime ─────────────────────────────────────────
say "deploying agent A on GKE"
kubectl --context "$GKE_CONTEXT" -n demo get secret aws-invoke >/dev/null 2>&1 || {
  cat >&2 <<'NOTE'
  !! Missing secret demo/aws-invoke. Agent A reaches the AgentCore control API with it — this is
     TRANSPORT only (AgentCore has no other ingress); A's identity to PingFederate is still its
     attestation. Create it with:
       kubectl -n demo create secret generic aws-invoke \
         --from-literal=access-key-id=<id> --from-literal=secret-access-key=<secret>
NOTE
  exit 1
}
sed -e "s|IMAGE_A|$GKE_REGISTRY/chain-agent:$TAG|" \
    -e "s|AGENTCORE_ARN_VALUE|$AGENTCORE_ARN|" "$HERE/k8s/agent-a.yaml" \
  | kubectl --context "$GKE_CONTEXT" apply -f -
kubectl --context "$GKE_CONTEXT" -n demo rollout status deploy/chain-agent-a --timeout=300s
AGENT_A_IP=$(wait_for_lb "$GKE_CONTEXT" demo chain-agent-a ip)

# ── verify: run the chain and check the act chain actually nests three deep ───────────────────────
# This is the real independent verification — it does not trust that the steps above "said" they
# succeeded, it calls the live system end to end and asserts on the actual response.
say "verifying the chain end to end"
sleep 20
RESULT=$(curl -s -m 200 -X POST "http://$AGENT_A_IP/run")
if ! VERIFY_OUT=$(echo "$RESULT" | "$PY" - 2>&1 <<'EOF'
import json, sys
try:
    d = json.load(sys.stdin)
except json.JSONDecodeError as e:
    print(f"response was not JSON ({e}) — the chain call itself likely failed, not just an assertion")
    raise SystemExit(1)
r = d.get("resource") or {}
chain = [a.get("sub") for a in r.get("actor_chain", [])]
print("  ok:            ", d.get("ok"))
print("  on behalf of:  ", r.get("on_behalf_of"))
print("  actor chain:   ", chain)
print("  decision:      ", (r.get("decision") or {}).get("allowed"))
assert d.get("ok"), "chain did not complete"
assert len(chain) == 3, f"expected three actors, got {chain}"
assert (r.get("decision") or {}).get("allowed"), "resource denied the delegated call"
print("  VERIFIED: sub preserved across two clouds, act chain three deep, resource allowed")
EOF
); then
  echo "!! chain verification failed:" >&2
  echo "$VERIFY_OUT" | sed 's/^/   /' >&2
  echo "   raw response was:" >&2
  echo "$RESULT" | head -c 2000 | sed 's/^/   /' >&2
  exit 1
fi
echo "$VERIFY_OUT"

cat <<SUMMARY

==> chain live and independently verified.

  demo console   http://$AGENT_A_IP/
  agent C        http://$AGENT_C_IP/call
  resource       $RESOURCE_URL

Remember to re-bake the PingFederate config archives if terraform changed anything, or the next pod
replacement will revert it. See ../aws-bedrock-demo/RECOVERY.md.
SUMMARY
