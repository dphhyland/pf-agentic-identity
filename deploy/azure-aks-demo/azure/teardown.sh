#!/usr/bin/env bash
# Tear the Azure side down. Deletes the AKS cluster, the Container Apps environment + gateway
# managed identity, and (unless KEEP_ACR=1) the ACR repositories.
#
# NOT YET RUN — see the note at the top of ../azure/bootstrap.sh. Mirrors
# ../../aws-bedrock-demo/aws/teardown.sh's structure and its refuse-without---yes safety rule.
#
# Refuses to run without --yes, because this is not recoverable from the repo alone: the PF config
# archive (data.zip) is encrypted with a master key that is deliberately NOT in git.
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-attest-demo-rg}"
AKS_CLUSTER="${AKS_CLUSTER:-attest-demo-aks}"
ACR_NAME="${ACR_NAME:-attestdemoacr}"
GATEWAY_IDENTITY="${GATEWAY_IDENTITY:-attest-demo-gateway-mi}"
CONTAINERAPPS_ENV="${CONTAINERAPPS_ENV:-attest-demo-env}"
KEEP_ACR="${KEEP_ACR:-0}"   # 1 keeps the images, so a rebuild does not re-push gigabytes
say() { printf '\n==> %s\n' "$*"; }

[ "${1:-}" = "--yes" ] || {
  cat >&2 <<'WARN'
Refusing to tear down without --yes.

This deletes the AKS cluster, the Container Apps environment + gateway identity, and (unless
KEEP_ACR=1) the ACR repositories including the baked PingFederate image. The baked config CANNOT be
rebuilt from the repo alone — data.zip is encrypted with a gitignored master key. Consider exporting
the config archive first (see ../../aws-bedrock-demo/aws/teardown.sh's equivalent note).

Re-run with:  ./teardown.sh --yes
WARN
  exit 1
}

# ── Container Apps environment + gateway (before the cluster/RG: independent resources) ───────────
say "deleting Container Apps environment $CONTAINERAPPS_ENV"
az containerapp env delete --resource-group "$RESOURCE_GROUP" --name "$CONTAINERAPPS_ENV" \
  --yes >/dev/null 2>&1 && echo "  deleted" || echo "  absent"

say "deleting managed identity $GATEWAY_IDENTITY"
az identity delete --resource-group "$RESOURCE_GROUP" --name "$GATEWAY_IDENTITY" \
  >/dev/null 2>&1 && echo "  deleted" || echo "  absent"

# ── the AKS cluster ─────────────────────────────────────────────────────────────────────────────
if az aks show --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER" >/dev/null 2>&1; then
  say "deleting AKS cluster $AKS_CLUSTER (~10 min)"
  az aks delete --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER" --yes >/dev/null
else
  say "cluster $AKS_CLUSTER not present"
fi

# ── ACR ──────────────────────────────────────────────────────────────────────────────────────────
if [ "$KEEP_ACR" = "1" ]; then
  say "keeping ACR $ACR_NAME (KEEP_ACR=1)"
else
  say "deleting ACR $ACR_NAME"
  az acr delete --resource-group "$RESOURCE_GROUP" --name "$ACR_NAME" --yes \
    >/dev/null 2>&1 && echo "  deleted" || echo "  absent"
fi

cat <<'SUMMARY'

==> Azure side torn down.

Left deliberately in place:
  - The resource group itself (attest-demo-rg by default) — delete it separately with
    `az group delete --name attest-demo-rg --yes` once you are certain nothing else in it matters.
  - No Azure-account-level feature toggle needs undoing (unlike AWS's Outbound Identity Federation) —
    AKS Workload Identity Federation and managed identities are per-resource, not account-level.
SUMMARY
