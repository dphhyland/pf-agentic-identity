#!/usr/bin/env bash
# Insert the Azure hop (agent D) into an ALREADY-DEPLOYED chain, making it four agents across three
# clouds. Run ./deploy.sh first; this script only rewires.
#
#   before:  A (GKE) -> B (AgentCore/AWS) -> C (GKE) ------------------> resource (EKS)
#   after:   A (GKE) -> B (AgentCore/AWS) -> C (GKE) -> D (Azure) -----> resource (EKS)
#
# D is a transparent interposer: it accepts exactly the call C already makes to the resource and makes
# exactly the call the resource already expects, so inserting it is pure rewiring — no agent code
# changes. Two things do get re-applied:
#
#   * agent C's NEXT_HOP_URL, from the resource to D.
#   * the resource's TRUSTED_ISSUER and REQUIRED_FINAL_ACTOR. The last exchange now happens at
#     EXCHANGE_PF_URL (D's target AS) and the last actor is now D, so a resource still pinned to the
#     old pair would correctly reject the longer chain. Re-pointing it is the whole reason this is a
#     script and not a one-line kubectl.
#
# NOT YET RUN — no Azure subscription has been opened (see ../azure-aks-demo/DEMO-STATE.md). Every
# other script in this tree has been exercised against live infrastructure; this one has not.
set -euo pipefail

: "${GKE_CONTEXT:?set GKE_CONTEXT (kubectl context for the GKE cluster)}"
: "${EKS_CONTEXT:?set EKS_CONTEXT (kubectl context for the EKS cluster)}"
: "${AKS_CONTEXT:?set AKS_CONTEXT (kubectl context for the AKS cluster)}"
: "${ACR:?set ACR, e.g. attestdemoacr.azurecr.io}"
: "${GKE_REGISTRY:?set GKE_REGISTRY (agent C is re-applied from its existing image)}"
: "${ECR:?set ECR (the resource is re-applied from its existing image)}"
: "${EXCHANGE_PF_URL:?set EXCHANGE_PF_URL (the AS agent D exchanges at — the Azure PF for a three-AS chain, or the EKS PF to leave the trust pinning on the resource untouched)}"

TAG="${TAG:-chain}"
# The asserted Entra Agent ID D claims. Must be a key in the attester's OIDF_ENTRA_AGENT_DIRECTORY, or
# the mint is refused with access_denied. Empty means D presents only its own evidenced identity.
ASSERTED_OID="${ASSERTED_COPILOT_AGENT_ID:-}"
# D's PF client id, which becomes the resource's expected final actor.
AGENT_D_CLIENT="${AGENT_D_CLIENT:-demo-attest-aks-chain}"
HERE="$(cd "$(dirname "$0")" && pwd)"
say() { printf '\n==> %s\n' "$*"; }

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

# The resource's current address — D forwards to it, so it must be read before C is repointed away.
RESOURCE_HOST=$(wait_for_lb "$EKS_CONTEXT" demo mock-resource hostname)
RESOURCE_URL="http://$RESOURCE_HOST/settle"
say "existing resource: $RESOURCE_URL"

# ── image ────────────────────────────────────────────────────────────────────────────────────────
say "building and pushing agent D"
az acr login --name "${ACR%%.*}" >/dev/null
docker build --platform linux/amd64 -q \
  --build-arg "BASE_IMAGE=$ACR/aks-workload:latest" \
  -t "$ACR/chain-agent-d:$TAG" "$HERE/azure" >/dev/null
docker push -q "$ACR/chain-agent-d:$TAG" >/dev/null && echo "  pushed chain-agent-d"

# ── 1. agent D on AKS, pointed at the real resource ──────────────────────────────────────────────
say "deploying agent D on AKS"
kubectl --context "$AKS_CONTEXT" create namespace demo --dry-run=client -o yaml \
  | kubectl --context "$AKS_CONTEXT" apply -f - >/dev/null
sed -e "s|IMAGE_D|$ACR/chain-agent-d:$TAG|" \
    -e "s|EXCHANGE_PF_URL|$EXCHANGE_PF_URL|" \
    -e "s|RESOURCE_URL|$RESOURCE_URL|" \
    -e "s|ASSERTED_OID|$ASSERTED_OID|" "$HERE/k8s/agent-d.yaml" \
  | kubectl --context "$AKS_CONTEXT" apply -f -
kubectl --context "$AKS_CONTEXT" -n demo rollout status deploy/chain-agent-d --timeout=300s
AGENT_D_IP=$(wait_for_lb "$AKS_CONTEXT" demo chain-agent-d ip)
AGENT_D_URL="http://$AGENT_D_IP/settle"
say "agent D: $AGENT_D_URL"

# ── 2. the resource: trust the AS D exchanges at, and expect D as the final actor ─────────────────
say "re-pointing the resource at the new final hop"
sed -e "s|IMAGE_R|$ECR/mock-resource:$TAG|" \
    -e "s|EKS_PF_URL|$EXCHANGE_PF_URL|" \
    -e "s|demo-attest-gke-delivery|$AGENT_D_CLIENT|" "$HERE/k8s/resource.yaml" \
  | kubectl --context "$EKS_CONTEXT" apply -f -
kubectl --context "$EKS_CONTEXT" -n demo rollout status deploy/mock-resource --timeout=300s

# ── 3. agent C: forward to D instead of straight to the resource ─────────────────────────────────
# Deliberately last. Until this applies, the chain still runs end to end the old way; the moment it
# does, D is already up and the resource already trusts the new issuer. No window where C points at
# something that is not ready.
say "re-pointing agent C at agent D"
: "${EKS_PF_URL:?set EKS_PF_URL (agent C still exchanges there — unchanged by this script)}"
sed -e "s|IMAGE_C|$GKE_REGISTRY/chain-agent:$TAG|" -e "s|EKS_PF_URL|$EKS_PF_URL|" \
    -e "s|RESOURCE_URL|$AGENT_D_URL|" "$HERE/k8s/agent-c.yaml" \
  | kubectl --context "$GKE_CONTEXT" apply -f -
kubectl --context "$GKE_CONTEXT" -n demo rollout status deploy/chain-agent-c --timeout=300s

# ── verify: the act chain should now nest FOUR deep ──────────────────────────────────────────────
say "verifying the extended chain end to end"
AGENT_A_IP=$(wait_for_lb "$GKE_CONTEXT" demo chain-agent-a ip)
sleep 20
curl -s -m 240 -X POST "http://$AGENT_A_IP/run" | python3 - <<'EOF'
import json, sys
d = json.load(sys.stdin)
r = d.get("resource") or {}
chain = [a.get("sub") for a in r.get("actor_chain", [])]
print("  ok:            ", d.get("ok"))
print("  on behalf of:  ", r.get("on_behalf_of"))
print("  actor chain:   ", chain)
print("  decision:      ", (r.get("decision") or {}).get("allowed"))
assert d.get("ok"), "chain did not complete"
assert len(chain) == 4, f"expected four actors, got {chain}"
assert (r.get("decision") or {}).get("allowed"), "resource denied the delegated call"
print("  VERIFIED: sub preserved across three clouds, act chain four deep, resource allowed")
EOF

cat <<SUMMARY

==> Azure leg inserted.

  demo console   http://$AGENT_A_IP/
  agent D        $AGENT_D_URL   (GET / for its health + asserted-oid config)

To demo the asserted-context narrowing against this same deployment, call D directly with and
without the header — the un-narrowed call carries D's full evidenced ceiling, the narrowed one only
what the directory entry allows:

  curl -s -X POST $AGENT_D_URL -H 'Authorization: Bearer <a token from agent C>' \\
    -H 'X-Copilot-Agent-Id: <an oid in OIDF_ENTRA_AGENT_DIRECTORY>' \\
    -H 'Content-Type: application/json' -d '{"amount":250,"currency":"AUD"}' | jq .trace

To back the Azure leg out, re-run ./deploy.sh — it re-applies C pointed straight at the resource and
the resource pinned to the EKS AS, which is exactly the pre-insertion state.
SUMMARY
