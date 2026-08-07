#!/usr/bin/env bash
# Tear down the demo: delete the named cluster, then the whole project (kills the registry and any
# stragglers with it). Usage: PROJECT_ID=pf-spiffe-demo-1234 ./teardown.sh --yes
#
# Refuses to run without --yes: deleting the project is the most destructive thing in this repo.
# gcloud locks the project ID for ~30 days afterward, so a rebuild lands on a NEW project id — which
# changes the SPIFFE trust domain (<project>.svc.id.goog) that every client binding, evidence issuer
# and spiffe_id in the demo is built from. Read ../../aws-bedrock-demo/RECOVERY.md before tearing down
# if you intend to rebuild, and consider exporting the PF config archive first:
#
#   kubectl -n pf port-forward pod/<pf-pod> 29998:9999 &
#   curl -sk -u administrator:$PW -H 'X-XSRF-Header: PingFederate' \
#     -o data.zip https://localhost:29998/pf-admin-api/v1/configArchive/export
#
# Hardened 2026-08-02, matching ../../aws-bedrock-demo/aws/teardown.sh: the original script deleted
# the named cluster with a blanket `|| true`, so a wrong ZONE/CLUSTER (the exact thing that happens
# after a capacity-driven rebuild lands in a different zone than the defaults) failed silently and the
# script pressed on as if the cluster had been handled — it happened to be harmless only because
# project deletion removes the cluster regardless of zone, but the script gave no indication either
# way. This version lists what clusters actually exist before attempting the named one, distinguishes
# "not found" from a real error, and verifies the project's lifecycle state independently afterward
# instead of trusting the delete command's own exit code. Do not pipe this script's output through
# `tail`; if you must truncate it, check ${PIPESTATUS[0]}, not $?, for the real exit code.
set -uo pipefail   # deliberately NOT -e — see fail() below

: "${PROJECT_ID:?set PROJECT_ID}"
ZONE="${ZONE:-us-central1-a}"
CLUSTER="${CLUSTER:-spiffe-demo}"

FAILURES=()
say()  { printf '\n==> %s\n' "$*"; }
fail() { printf '\n!! %s\n' "$*" >&2; FAILURES+=("$*"); }

[ "${1:-}" = "--yes" ] || {
  cat >&2 <<WARN
Refusing to tear down without --yes.

This deletes GCP project $PROJECT_ID outright — the cluster, the Artifact Registry (every pushed PF
and agent image), and anything else in it. gcloud locks the project id for ~30 days afterward, so a
rebuild lands on a NEW project id and changes the SPIFFE trust domain everything is built from. See
../../aws-bedrock-demo/RECOVERY.md before proceeding if you intend to rebuild.

Re-run with:  PROJECT_ID=$PROJECT_ID ./teardown.sh --yes
WARN
  exit 1
}

# ── preflight: confirm gcloud can actually see this project before doing anything ─────────────────
# The AWS incident this mirrors was a broken python venv silently no-oping every step. There is no
# venv here, but the equivalent failure mode is the same shape: proceeding against a project gcloud
# cannot actually reach (wrong active account, no permissions, already gone) produces a cascade of
# confusing errors that a blanket `|| true` would have hidden just as effectively as the venv did.
say "checking gcloud can see project $PROJECT_ID"
if ! command -v gcloud >/dev/null; then
  echo "!! gcloud CLI not found on PATH" >&2
  exit 1
fi
ACCOUNT=$(gcloud config get-value account 2>/dev/null)
if [ -z "$ACCOUNT" ] || [ "$ACCOUNT" = "(unset)" ]; then
  echo "!! no active gcloud account — run: gcloud auth login" >&2
  exit 1
fi
echo "  active account: $ACCOUNT"

STATE=$(gcloud projects describe "$PROJECT_ID" --format="value(lifecycleState)" 2>&1)
STATUS=$?
if [ "$STATUS" -ne 0 ]; then
  cat >&2 <<EOF
!! could not describe project $PROJECT_ID as $ACCOUNT:
   $STATE

   Either the project id is wrong, it was already deleted, or $ACCOUNT lacks access. If it was
   already deleted there is nothing left to do here — check with:
     gcloud projects describe $PROJECT_ID
EOF
  exit 1
fi
echo "  project state: $STATE"
if [ "$STATE" != "ACTIVE" ]; then
  say "project $PROJECT_ID is already $STATE — nothing to tear down"
  exit 0
fi

# ── see what clusters actually exist before touching the named one ────────────────────────────────
# This is the check that would have caught the actual incident: ZONE/CLUSTER defaults did not match
# where the cluster had really landed (a capacity-driven rebuild put it in a different region), so the
# delete call 404'd. Project deletion still removed it regardless of zone, but the script gave no sign
# either way. Listing first makes a mismatch visible instead of silent.
say "listing clusters in $PROJECT_ID"
CLUSTER_LIST=$(gcloud container clusters list --project "$PROJECT_ID" --format="value(name,location,status)" 2>&1)
LIST_STATUS=$?
if [ "$LIST_STATUS" -ne 0 ] && echo "$CLUSTER_LIST" | grep -qiE "has not been used|is disabled"; then
  # Container API never enabled on this project == categorically no cluster exists. Same signal as
  # "not found", just a different error shape — found live-testing against a fresh disposable project.
  echo "  Container API never enabled on this project — no cluster could exist"
  CLUSTER_LIST=""
elif [ "$LIST_STATUS" -ne 0 ]; then
  fail "could not list clusters: $CLUSTER_LIST"
elif [ -z "$CLUSTER_LIST" ]; then
  echo "  none"
else
  echo "$CLUSTER_LIST" | sed 's/^/  /'
  if ! echo "$CLUSTER_LIST" | grep -q "^$CLUSTER"; then
    echo "  note: '$CLUSTER' (the name teardown will target) is not in this list."
    echo "        If one of the clusters above is the real one, re-run with CLUSTER=<name> ZONE=<zone>."
    echo "        Continuing anyway — deleting the whole project removes every cluster in it regardless."
  fi
fi

# ── the named cluster (best-effort: project deletion below removes it regardless of zone) ────────
say "deleting cluster $CLUSTER (zone $ZONE)"
DELETE_OUT=$(gcloud container clusters delete "$CLUSTER" --zone "$ZONE" --project "$PROJECT_ID" --quiet 2>&1)
DELETE_STATUS=$?
if [ "$DELETE_STATUS" -ne 0 ]; then
  if echo "$DELETE_OUT" | grep -qiE "not found|has not been used|is disabled"; then
    echo "  not found at $CLUSTER/$ZONE (or the Container API was never enabled there) — expected if it never existed"
  else
    fail "cluster delete failed for a reason other than 'not found': $DELETE_OUT"
  fi
else
  echo "$DELETE_OUT" | sed 's/^/  /'
fi

# ── the whole project ────────────────────────────────────────────────────────────────────────────
say "deleting project $PROJECT_ID"
PROJECT_DELETE_OUT=$(gcloud projects delete "$PROJECT_ID" --quiet 2>&1)
if [ $? -ne 0 ]; then
  fail "gcloud projects delete failed: $PROJECT_DELETE_OUT"
else
  echo "$PROJECT_DELETE_OUT" | sed 's/^/  /'
fi

# ── independent verification ────────────────────────────────────────────────────────────────────
# `gcloud projects delete` returns once deletion is REQUESTED, not once the project is actually gone
# — checking its own exit code is not the same as confirming the state changed. Query it back rather
# than trusting the delete call.
say "verifying project state independently"
FINAL_STATE=$(gcloud projects describe "$PROJECT_ID" --format="value(lifecycleState)" 2>&1)
if [ $? -ne 0 ]; then
  fail "could not verify final project state: $FINAL_STATE"
elif [ "$FINAL_STATE" = "ACTIVE" ]; then
  fail "project $PROJECT_ID still shows ACTIVE after the delete call — it did not take"
else
  echo "  project state: $FINAL_STATE"
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

cat <<EOF

==> GCP side torn down and independently verified ($PROJECT_ID: $FINAL_STATE).

The project id is locked for ~30 days. Undo within that window with:
    gcloud projects undelete $PROJECT_ID
Past that window, or if you proceed with a new project, see ../../aws-bedrock-demo/RECOVERY.md — the
new project id changes the SPIFFE trust domain and every value derived from it.
EOF
