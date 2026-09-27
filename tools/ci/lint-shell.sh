#!/usr/bin/env bash
# Runs shellcheck over every tracked script, from the repository root: what build.yml's lint job runs, so a
# checkout gives the same answer. The settings are .shellcheckrc's. A comment opening with the tool's own
# name is read as a directive, so none here does.
#
# build/pingfederate/*.sh are left out for now. Package IMAGE of the production programme's Phase 1 rewrites
# those scripts and makes them shellcheck-clean; it removes the exclusion below with that change.
set -euo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
git ls-files -z -- '*.sh' ':!build/pingfederate/' | xargs -0 shellcheck --
echo "ok: shellcheck has nothing to say about $(git ls-files -- '*.sh' ':!build/pingfederate/' | wc -l | tr -d ' ') scripts"
