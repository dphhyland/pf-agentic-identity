# CI jobs pick their runner from a repository variable

## Changelog

- Every job in Build, Docs, Mutation, conformance-federation and iOS runs on the runner the repository variable
  `RUNNER_LINUX` (or `RUNNER_MACOS` for iOS) names, and on GitHub's hosted runner when the variable is unset or
  when Dependabot opened the pull request. Nothing is set yet, so every job still runs hosted. Release stays on
  hosted runners.
- `tools/ci/install-lint-tools.sh` records Linux arm64 checksums for actionlint, shellcheck, zizmor, gitleaks,
  grype and syft, so the lint and image steps run on an arm64 Linux runner.

## Before you deploy

None.

## Notes

Groundwork for running CI on self-hosted runners once the repository is private: the runners are registered and
the variables set only after that, and `.github/workflows/codeql.yml` is removed then, not here. Removing a
variable returns every job to the hosted runner.
