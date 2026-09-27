# The coverage gate and the ratchet in CI

## Changelog

- `tools/coverage-report.py` also writes `docs/coverage-dashboard.json` (git-ignored, published in the
  `coverage-dashboard` artefact): per module, each jacoco check's methods with their line and branch counters,
  the test counts, and the `@Requirement` ids and matrix rows its tests pin.
- `--gate` fails on a jacoco check or `<include>` pattern that selects no method and on an undeclared
  `@Requirement` prefix, and counts the ids no conformance-matrix row declares.
- `--baseline <json>` ratchets against an earlier build: a check gone or shrunk, a gated method below 100%, or
  fewer pinned matrix rows fails. Build's java job runs both, against the last successful Build on main
  (`tools/ci/coverage-baseline.sh`, with `actions: read` on that job only).

## Before you deploy

None.

## Notes

Nothing here changes what is deployed; it changes what a pull request can merge with.

What the gate refuses (`--gate`, each line on stderr and in the step summary starts `gate:`):

- a jacoco check that includes no method;
- an `<include>` pattern that names no method in the jacoco report. jacoco passes a rule that selects nothing,
  so a renamed method or a typo in a pom left the method ungated and the build green. Fix the pattern;
- an `@Requirement` id whose prefix `Requirement.java` does not declare. Declare the prefix once the document
  behind it has been read, or fix the id.

An id naming a section no conformance-matrix row declares is printed as a `gate warning:` and counted, not
refused. Measured on 2026-09-28 (origin/main 982e4cd, `mvn -B clean verify` on JDK 17): 65 of the 500 ids, under
21 prefixes, seven of which no matrix has a row for, and the repository has no spec index to declare them
instead. Refusing them would fail every build until the matrices catch up; F-0145 records the gap and the
one-line change that turns the warning into a refusal.

What the ratchet refuses (`--baseline`, lines start `ratchet:`), against the `coverage-dashboard.json` of an
earlier build:

- a jacoco check the baseline had is gone, or includes fewer methods - the line names the methods it no
  longer includes;
- a gated method below 100% line or branch coverage;
- fewer pinned matrix rows - the line names the rows.

A new module, check or method passes, so Phase 2's new modules need no edit to the tool. CI's baseline is the
JSON that the successful push Build on main published for the pull request's base commit, or for the commit
before a push, and the newest successful push Build on main when that run is missing (failed, or cancelled by a
newer push). Runs from pull requests never supply it, even from a fork's branch called `main`. No baseline -
the first run after this merges, which finds artefacts without the JSON, or an artefact past its 90 days -
passes with a notice in the step summary; a failed fetch fails the step. A ratchet failure naming a check or
method the branch never had means main moved on since the base: merge main into the branch.

Read a failure from the java job's step summary, or run the same locally with a main run's artefact
(CONTRIBUTING.md, "Generated files"). Verified on 2026-09-28: the generator's 29 unit tests, one per rule with
fixture reports; `--gate` on a full JDK 17 build of 982e4cd (718 gate patterns, all resolving, no undeclared
prefix); the ratchet against that build's own JSON (passes) and against an edited copy with a module gone, a
method removed and a pinned row removed (three failures); `coverage-baseline.sh` against this repository (it
found the right runs and their artefacts without JSON) and against a stubbed `gh` for a found baseline, a run
from another repository and a corrupt download; actionlint, zizmor and shellcheck from
`tools/ci/install-lint-tools.sh`, clean.

The plan's JDK 21 test run on pushes to main (PingFederate 13.1.3's image runs OpenJDK 21.0.12.1, CI tests on
Temurin 17) is not added here: U-0155 records what would settle it.
