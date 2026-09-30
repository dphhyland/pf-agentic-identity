#!/usr/bin/env bash
# The coverage ratchet's baseline: coverage-dashboard.json from a successful Build run on main.
#
#   tools/ci/coverage-baseline.sh <out.json> <sha>
#
# Picks the newest successful Build run that a push to main made for a commit <sha> descends from, where <sha> is
# the commit under test (github.sha: a pull request's merge commit, the pushed commit, or a dispatched branch's
# head). So the comparison is with the main this build was made from - not a newer main, whose added gated methods
# a branch behind it never had - and it survives the run for the previous commit having been cancelled by a newer
# push. Ancestry is asked of the compare API, for up to the 30 newest successful
# runs. Only push runs count: a pull request from a fork's own `main` branch is also a run on a branch called
# main, and must not be able to supply the baseline.
#
# Writes the baseline to <out.json> and exits 0. With no baseline to write - no such run yet, the run's artefact
# expired (90 days), or an artefact from before the generator wrote JSON - it writes nothing, says so as a notice
# and in the step summary, and exits 0: the ratchet then passes, which is what the first run on main needs. Any
# other failure (the API refusing the token, the network) exits non-zero, so a broken fetch never passes as "no
# baseline"; a commit the compare API does not know (404) is only "not an ancestor".
#
# Needs GH_TOKEN (the job's GITHUB_TOKEN with `actions: read`) and GITHUB_REPOSITORY, both set in CI. Locally,
# `gh run download <run-id> -n coverage-dashboard` gets the same file, and `tools/coverage-report.py --baseline`
# takes it directly.
set -euo pipefail

out=${1:?usage: coverage-baseline.sh <out.json> <sha>}
sha=${2:-}
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}
if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::coverage-baseline.sh needs the commit to find a baseline for, as a 40-character sha" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

say() {
  echo "::notice title=coverage ratchet::$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# One row per run, newest first: id, repository, commit. The jq filter emits nothing for an empty list.
candidates=$(gh api "repos/$repo/actions/workflows/build.yml/runs?branch=main&event=push&status=success&per_page=30" \
  --jq '.workflow_runs[] | [.id, .head_repository.full_name, .head_sha] | @tsv')

row=""
while IFS=$'\t' read -r run from commit; do
  [ -n "$run" ] || continue
  if [ "$commit" = "$sha" ]; then
    row="$run"$'\t'"$from"$'\t'"$commit"
    break
  fi
  # "ahead": <sha> is ahead of the run's commit, which is therefore an ancestor. A commit the API cannot find
  # (404) is not an ancestor; any other failure fails the step.
  if ! relation=$(gh api "repos/$repo/compare/$commit...$sha?per_page=1" --jq '.status' 2>"$work/compare.err"); then
    if ! grep -q 'HTTP 404' "$work/compare.err"; then
      cat "$work/compare.err" >&2
      exit 1
    fi
    relation=""
  fi
  if [ "$relation" = ahead ]; then
    row="$run"$'\t'"$from"$'\t'"$commit"
    break
  fi
done <<< "$candidates"
if [ -z "$row" ]; then
  say "No successful Build run on main among the newest 30 is one this commit ($sha) descends from, so the ratchet passes this time."
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
