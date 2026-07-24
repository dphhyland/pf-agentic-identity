#!/usr/bin/env bash
# Bootstrap the GCP project + GKE cluster for the SPIFFE → Client Attestation → PingFederate demo.
#
# Prereqs: gcloud CLI authenticated (`gcloud auth login`), and a billing account you can link.
# Billing linking may require doing it once in the console instead — the script tolerates that.
#
# Usage:
#   PROJECT_ID=pf-spiffe-demo-1234 BILLING_ACCOUNT=XXXXXX-XXXXXX-XXXXXX ./bootstrap.sh
set -euo pipefail

: "${PROJECT_ID:?set PROJECT_ID (globally unique, e.g. pf-spiffe-demo-$RANDOM)}"
ZONE="${ZONE:-us-central1-a}"
REGION="${REGION:-us-central1}"
CLUSTER="${CLUSTER:-spiffe-demo}"

echo "== project =="
gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1 || gcloud projects create "$PROJECT_ID"
if [ -n "${BILLING_ACCOUNT:-}" ]; then
  gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT"
else
  echo "!! BILLING_ACCOUNT not set — link billing in the console before continuing." >&2
fi

echo "== APIs =="
gcloud services enable container.googleapis.com artifactregistry.googleapis.com \
  --project "$PROJECT_ID"

echo "== Artifact Registry =="
gcloud artifacts repositories describe demo --location="$REGION" --project "$PROJECT_ID" >/dev/null 2>&1 \
  || gcloud artifacts repositories create demo --repository-format=docker \
       --location="$REGION" --project "$PROJECT_ID"
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

echo "== GKE cluster (Standard zonal: spiffe-csi needs hostPath-adjacent privileges Autopilot restricts;"
echo "   one zonal cluster's management fee is covered by the GKE free tier) =="
gcloud container clusters describe "$CLUSTER" --zone "$ZONE" --project "$PROJECT_ID" >/dev/null 2>&1 \
  || gcloud container clusters create "$CLUSTER" \
       --zone "$ZONE" --project "$PROJECT_ID" \
       --num-nodes 1 --machine-type e2-standard-4 --disk-size 50 \
       --workload-pool="${PROJECT_ID}.svc.id.goog"   # Phase 2: the PROJECT.svc.id.goog trust domain

gcloud container clusters get-credentials "$CLUSTER" --zone "$ZONE" --project "$PROJECT_ID"

echo "== done =="
echo "Registry: ${REGION}-docker.pkg.dev/${PROJECT_ID}/demo"
echo "Cluster:  ${CLUSTER} (${ZONE}) — kubectl context set"
