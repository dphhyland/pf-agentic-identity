#!/usr/bin/env bash
# Stand up the Azure side of the demo from nothing: an AKS cluster with its OIDC issuer public
# (Workload Identity Federation), a Container Apps environment + user-assigned managed identity for
# the gateway, ACR repositories, and the secrets PingFederate needs.
#
# NOT YET RUN AGAINST A REAL SUBSCRIPTION — this mirrors ../../aws-bedrock-demo/aws/bootstrap.sh's
# structure and idempotent-check pattern (check-then-create, safe to re-run after a partial
# failure) but has not itself been exercised end to end the way the AWS/GKE scripts have (both of
# those were proven via a full teardown-and-rebuild verification pass — see their DEMO-STATE.md).
# Treat this as a strong first draft, not a battle-tested script, until it has been run once for real.
#
# Does NOT deploy PingFederate or the agents; that is deploy-pf.sh (not yet written — copy
# ../../aws-bedrock-demo/aws/*.sh's PF-on-AKS equivalent) and ../../cross-cloud-chain/deploy.sh once
# an Azure leg is added there.
#
# Prerequisites: az CLI (logged in, `az account show` succeeds), kubectl, docker.
set -euo pipefail

LOCATION="${AZURE_LOCATION:-australiaeast}"
RESOURCE_GROUP="${RESOURCE_GROUP:-attest-demo-rg}"
AKS_CLUSTER="${AKS_CLUSTER:-attest-demo-aks}"
ACR_NAME="${ACR_NAME:-attestdemoacr}"           # must be globally unique, alphanumeric only
GATEWAY_IDENTITY="${GATEWAY_IDENTITY:-attest-demo-gateway-mi}"
CONTAINERAPPS_ENV="${CONTAINERAPPS_ENV:-attest-demo-env}"
GKE_CONTEXT="${GKE_CONTEXT:-}"   # set to copy the bridge/licence secrets from the GKE cluster
REPOS=(pingfederate aks-workload azure-gateway)

say() { printf '\n==> %s\n' "$*"; }

say "checking prerequisites"
for tool in az kubectl docker; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done
az account show >/dev/null || { echo "run 'az login' first" >&2; exit 1; }
SUBSCRIPTION=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)
say "subscription $SUBSCRIPTION, tenant $TENANT_ID, location $LOCATION"

# ── resource group ──────────────────────────────────────────────────────────────────────────────
if az group show --name "$RESOURCE_GROUP" >/dev/null 2>&1; then
  say "resource group $RESOURCE_GROUP already exists"
else
  say "creating resource group $RESOURCE_GROUP"
  az group create --name "$RESOURCE_GROUP" --location "$LOCATION" >/dev/null
fi

# ── AKS cluster with a PUBLIC OIDC issuer + Workload Identity Federation enabled ──────────────────
# Both flags are required, and neither is the AKS default: without --enable-oidc-issuer the cluster
# has no resolvable issuer URL for the attester's aks-sa-token JWKS fetch; without
# --enable-workload-identity a pod's serviceAccountToken projection cannot carry a custom audience.
if az aks show --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER" >/dev/null 2>&1; then
  say "AKS cluster $AKS_CLUSTER already exists"
else
  say "creating AKS cluster $AKS_CLUSTER (~10 min)"
  az aks create --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER" \
    --node-count 2 --node-vm-size Standard_D2s_v5 \
    --enable-oidc-issuer --enable-workload-identity \
    --generate-ssh-keys >/dev/null
fi
az aks get-credentials --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER" --overwrite-existing >/dev/null
CTX=$(kubectl config current-context)
say "kubectl context: $CTX"

OIDC_ISSUER=$(az aks show --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER" \
  --query oidcIssuerProfile.issuerUrl -o tsv)
# The AKS cluster JWKS lives at <issuer>openid/v1/jwks (the standard OIDC discovery path) — unlike EKS,
# which serves it at <issuer>/keys. This is the one place AKS diverges from EKS in this shape.
say "cluster OIDC issuer: $OIDC_ISSUER"
say "cluster OIDC JWKS:   ${OIDC_ISSUER}openid/v1/jwks"

# ── ACR repositories ────────────────────────────────────────────────────────────────────────────
if az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" >/dev/null 2>&1; then
  say "ACR $ACR_NAME already exists"
else
  say "creating ACR $ACR_NAME"
  az acr create --resource-group "$RESOURCE_GROUP" --name "$ACR_NAME" --sku Basic >/dev/null
fi
ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)
az aks update --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER" --attach-acr "$ACR_NAME" >/dev/null
say "ACR repositories are created on first push (docker push $ACR_LOGIN_SERVER/<repo>:<tag>): ${REPOS[*]}"

# ── user-assigned managed identity for the Container Apps gateway (azure-mi-token evidence) ───────
if az identity show --resource-group "$RESOURCE_GROUP" --name "$GATEWAY_IDENTITY" >/dev/null 2>&1; then
  say "managed identity $GATEWAY_IDENTITY already exists"
else
  say "creating managed identity $GATEWAY_IDENTITY"
  az identity create --resource-group "$RESOURCE_GROUP" --name "$GATEWAY_IDENTITY" >/dev/null
fi
GATEWAY_IDENTITY_OID=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$GATEWAY_IDENTITY" \
  --query principalId -o tsv)
GATEWAY_IDENTITY_CLIENT_ID=$(az identity show --resource-group "$RESOURCE_GROUP" --name "$GATEWAY_IDENTITY" \
  --query clientId -o tsv)
say "gateway managed identity oid:       $GATEWAY_IDENTITY_OID"
say "gateway managed identity client id: $GATEWAY_IDENTITY_CLIENT_ID"

# ── Container Apps environment (hosts the gateway with the identity above attached) ────────────────
if az containerapp env show --resource-group "$RESOURCE_GROUP" --name "$CONTAINERAPPS_ENV" >/dev/null 2>&1; then
  say "Container Apps environment $CONTAINERAPPS_ENV already exists"
else
  say "creating Container Apps environment $CONTAINERAPPS_ENV"
  az containerapp env create --resource-group "$RESOURCE_GROUP" --name "$CONTAINERAPPS_ENV" \
    --location "$LOCATION" >/dev/null
fi

# ── secrets PingFederate needs (bridge key + DevOps licence) ───────────────────────────────────────
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
     Either re-run with GKE_CONTEXT=<gke kubectl context>, or create them by hand — see
     ../../aws-bedrock-demo/aws/bootstrap.sh's equivalent note (same secrets, same shared bridge key).
NOTE
fi

cat <<SUMMARY

==> done. Values the rest of the deploy needs:

  export AZURE_TENANT_ID=$TENANT_ID
  export AKS_CONTEXT="$CTX"
  export AKS_CLUSTER_ISSUER="$OIDC_ISSUER"
  export AKS_JWKS_URL="${OIDC_ISSUER}openid/v1/jwks"
  export ACR_LOGIN_SERVER="$ACR_LOGIN_SERVER"
  export GATEWAY_IDENTITY_OID="$GATEWAY_IDENTITY_OID"
  export GATEWAY_IDENTITY_CLIENT_ID="$GATEWAY_IDENTITY_CLIENT_ID"

Next: deploy PingFederate on AKS (see ../DEMO-STATE.md — not yet written, mirror
../../aws-bedrock-demo's PF-on-EKS deployment), apply ../pf/terraform (fold in
../pf/terraform/extended-properties-addition.tf.example), push the images in ../workload and
../agent-runtime to ACR, then deploy ../workload/workload.yaml and the gateway as a Container App
using --user-assigned "\$GATEWAY_IDENTITY_CLIENT_ID" and --registry-server "\$ACR_LOGIN_SERVER".
SUMMARY
