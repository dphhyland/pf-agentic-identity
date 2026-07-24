#!/usr/bin/env bash
# Tear down the demo: delete the cluster, then the whole project (kills registry + stragglers).
# Usage: PROJECT_ID=pf-spiffe-demo-1234 ./teardown.sh
set -euo pipefail

: "${PROJECT_ID:?set PROJECT_ID}"
ZONE="${ZONE:-us-central1-a}"
CLUSTER="${CLUSTER:-spiffe-demo}"

gcloud container clusters delete "$CLUSTER" --zone "$ZONE" --project "$PROJECT_ID" --quiet || true
gcloud projects delete "$PROJECT_ID" --quiet
