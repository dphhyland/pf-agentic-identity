# The coverage gate and the ratchet in CI

## Changelog

- `tools/coverage-report.py` also writes `docs/coverage-dashboard.json` (git-ignored, published in the
  `coverage-dashboard` artefact): per module, each jacoco check's methods with their line and branch counters,
  the test counts, and the `@Requirement` ids and matrix rows its tests pin.
- `--gate` fails on a jacoco check or `<include>` pattern that selects no method and on an undeclared
  `@Requirement` prefix, and counts the ids no conformance-matrix row declares.
- `--baseline <json>` ratchets against an earlier build: a check gone or shrunk, a gated method below 100%, or
  fewer pinned matrix rows fails, less the deliberate reductions `tools/coverage-ratchet-allow.txt` names.
  Build's java job runs both, against the newest successful Build on main that the commit descends from
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

A new module, check or method passes, so Phase 2's new modules need no edit to the tool. A reduction that is the
point of a change - dead code deleted with its `<include>`, a check renamed, a module moved, a matrix row
retired - needs a line in `tools/coverage-ratchet-allow.txt` in the same pull request (`method <module>
<method>`, `check <module> <execution id>` or `row <matrix row>`, copied from the `ratchet:` line). The pull
request's run and the push to main after it both read the file, so a reviewed reduction does not leave main
red, and a red merge is cleared by adding the line rather than by editing the tool. Nothing in the file excuses
a gated method below 100%. A line whose item the baseline no longer has allows nothing and is listed in the step
summary, ready to delete.

CI's baseline is the JSON of the newest successful push Build on main that the commit under test descends from:
a pull request's merge commit, a push, or a dispatched branch, which may be behind main (so a release dry run
on an older branch is not compared with a newer main). Runs from pull requests never supply it, even from a
fork's branch called `main`. No baseline - the first run after this merges, which finds artefacts without the
JSON, or an artefact past its 90 days - passes with a notice in the step summary, and so does a baseline in
another JSON format; a failed fetch fails the step, and a baseline that is missing or not JSON, or a malformed
allowance, exits 2.

Read a failure from the java job's step summary, or run the same locally with a main run's artefact
(CONTRIBUTING.md, "Generated files"). Verified on 2026-09-28: the generator's 41 unit tests, one or more per rule
with fixture reports, each rule's guard mutated and caught; `--gate` on a full JDK 17 build of 982e4cd (718 gate patterns, all resolving, no undeclared
prefix); the ratchet against that build's own JSON (passes) and against an edited copy with a module gone, a
method removed and a pinned row removed (three failures); `coverage-baseline.sh` against this repository (it
found the run PR #40's merge commit descends from, and its artefact without JSON) and against a stubbed `gh`
for a found baseline, a newest run that is not an ancestor, a compare that 404s (skipped) or 500s (fails), a
run from another repository and a corrupt download; actionlint, zizmor and shellcheck from
`tools/ci/install-lint-tools.sh`, clean.

The plan's JDK 21 test run on pushes to main (PingFederate 13.1.3's image runs OpenJDK 21.0.12.1, CI tests on
Temurin 17) is not added here: U-0155 records what would settle it.
