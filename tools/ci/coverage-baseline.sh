#!/usr/bin/env bash
# The coverage ratchet's baseline: coverage-dashboard.json from a successful Build run on main.
#
#   tools/ci/coverage-baseline.sh <out.json> [<sha>]
#
# Picks the successful Build run that a push to main made for <sha> - the base of the pull request under test, or
# the commit before a push - so the comparison is with the main this build was made from even when main has moved
# on since. When that run is missing (it failed, or a newer push cancelled it) it falls back to the newest
# successful Build run on main. Only push runs count: a pull request from a fork's own `main` branch is also a run
# on a branch called main, and must not be able to supply the baseline.
#
# Writes the baseline to <out.json> and exits 0. With no baseline to write - no such run yet, the run's artefact
# expired (90 days), or an artefact from before the generator wrote JSON - it writes nothing, says so as a notice
# and in the step summary, and exits 0: the ratchet then passes, which is what the first run on main needs. Any
# other failure (the API refusing the token, the network) exits non-zero, so a broken fetch never passes as "no
# baseline".
#
# Needs GH_TOKEN (the job's GITHUB_TOKEN with `actions: read`) and GITHUB_REPOSITORY, both set in CI. Locally,
# `gh run download <run-id> -n coverage-dashboard` gets the same file, and `tools/coverage-report.py --baseline`
# takes it directly.
set -euo pipefail

out=${1:?usage: coverage-baseline.sh <out.json> [<sha>]}
sha=${2:-}
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}
runs="repos/$repo/actions/workflows/build.yml/runs?branch=main&event=push&status=success&per_page=1"

say() {
  echo "::notice title=coverage ratchet::$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# One row per run: id, repository, commit. The jq filter emits nothing for an empty list.
pick() {
  gh api "$1" --jq '.workflow_runs[] | [.id, .head_repository.full_name, .head_sha] | @tsv'
}

row=""
if [[ "$sha" =~ ^[0-9a-f]{40}$ ]] && [ "$sha" != 0000000000000000000000000000000000000000 ]; then
  row=$(pick "$runs&head_sha=$sha")
fi
if [ -z "$row" ]; then
  row=$(pick "$runs")
fi
if [ -z "$row" ]; then
  say "No successful Build run on main to ratchet against, so the ratchet passes this time."
  exit 0
fi
IFS=$'\t' read -r run from commit <<< "$row"
if [ "$from" != "$repo" ]; then
  echo "::error::Build run $run is from $from, not $repo" >&2
  exit 1
fi

artifact=$(gh api "repos/$repo/actions/runs/$run/artifacts?name=coverage-dashboard" \
  --jq '[.artifacts[] | select(.expired | not)][0].id // empty')
if [ -z "$artifact" ]; then
  say "Build run $run on main ($commit) has no coverage-dashboard artefact left (expired, or never uploaded), so the ratchet passes this time."
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gh api "repos/$repo/actions/artifacts/$artifact/zip" > "$work/artefact.zip"
# 3 is "no JSON in this artefact"; anything else non-zero (a corrupt download) fails the step.
status=0
python3 - "$work/artefact.zip" "$out" <<'PY' || status=$?
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    if "coverage-dashboard.json" not in z.namelist():
        sys.exit(3)
    data = z.read("coverage-dashboard.json")
with open(sys.argv[2], "wb") as fh:
    fh.write(data)
PY
if [ "$status" = 3 ]; then
  say "Build run $run on main ($commit) published no coverage-dashboard.json (a run from before the ratchet), so the ratchet passes this time."
  exit 0
elif [ "$status" != 0 ]; then
  exit "$status"
fi
say "Ratcheting against coverage-dashboard.json from Build run $run on main ($commit)."
