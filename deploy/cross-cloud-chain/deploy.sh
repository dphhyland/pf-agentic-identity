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

# Wait for a Service to be given an external address. GCP hands out an IP, AWS a hostname.
wait_for_lb() {
  local ctx="$1" ns="$2" svc="$3" field="$4" addr=""
  for _ in $(seq 1 40); do
    addr=$(kubectl --context "$ctx" -n "$ns" get svc "$svc" \
      -o "jsonpath={.status.loadBalancer.ingress[0].$field}" 2>/dev/null || true)
    [ -n "$addr" ] && { echo "$addr"; return 0; }
    sleep 15
  done
  echo "timed out waiting for $svc external $field" >&2; return 1
}

# ── images ───────────────────────────────────────────────────────────────────────────────────────
say "building and pushing images (ECR pushes take 6-8 min each)"
docker build --platform linux/amd64 -q -t "$GKE_REGISTRY/chain-agent:$TAG"  "$HERE/agent"     >/dev/null
docker build --platform linux/amd64 -q -t "$ECR/mock-resource:$TAG"         "$HERE/resource"  >/dev/null
docker build --platform linux/arm64 -q -t "$ECR/agentcore-agent:$TAG"       "$HERE/agentcore" >/dev/null
docker push -q "$GKE_REGISTRY/chain-agent:$TAG" >/dev/null && echo "  pushed chain-agent"
"$PY" -c "
import base64,boto3,subprocess
t=boto3.client('ecr',region_name='$REGION').get_authorization_token()['authorizationData'][0]['authorizationToken']
pw=base64.b64decode(t).decode().split(':',1)[1]
subprocess.run(['docker','login','--username','AWS','--password-stdin','$ECR'],input=pw.encode(),check=True)" >/dev/null
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
EKS_PF_URL="$EKS_PF_URL" GKE_PF_URL="$GKE_PF_URL" AGENT_C_IP="$AGENT_C_IP" "$PY" - <<'EOF'
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
    raise SystemExit("AgentCore runtime did not reach READY")
EOF

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
say "verifying the chain end to end"
sleep 20
RESULT=$(curl -s -m 200 -X POST "http://$AGENT_A_IP/run")
echo "$RESULT" | "$PY" - <<'EOF'
import json, sys
d = json.load(sys.stdin)
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

cat <<SUMMARY

==> chain live.

  demo console   http://$AGENT_A_IP/
  agent C        http://$AGENT_C_IP/call
  resource       $RESOURCE_URL

Remember to re-bake the PingFederate config archives if terraform changed anything, or the next pod
replacement will revert it. See ../aws-bedrock-demo/RECOVERY.md.
SUMMARY
