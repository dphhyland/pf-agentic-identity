# Contributing

How work on this repository is done: the build, the tests that need a database, worktrees, the version tools,
the files that are generated, what a pull request carries, and how a release is cut. The house style for
anything written - prose, comments, commits, pull requests, release notes - is in [docs/development/style-guide.md](docs/development/style-guide.md).
The production programme's plan and its findings are the backlog: [docs/findings](docs/findings/README.md)
holds every finding and unverified assumption, and a pull request names the ones it closes.

## Building

```sh
mvn -o -B clean verify        # every module, tests on, coverage gates enforced
```

`verify`, not `package`: the jacoco critical-method gates are bound to the verify phase, and stopping at
`package` builds the artefacts and skips every gate. `-o` is offline; drop it for the first build on a machine,
and after that the reactor resolves everything from `~/.m2`. Never `mvn install`: parallel worktrees share
`~/.m2`, and an installed module from one branch is what another branch then builds against.

The two `provided` PingFederate jars (`pf-protocolengine`, `pingfederate-sdk`) and the jars gm-api and the
plugins name under `local.pingfederate` come from the public `pingidentity/pingfederate` image, pinned by tag
and digest in `build/pf-version.env`. Running PingFederate needs a licence; extracting its jars does not, so
the reactor builds with no private dependency. CI installs them with
[.github/actions/pf-provided-jars/action.yml](.github/actions/pf-provided-jars/action.yml). Locally, do what it
does once: `docker create` the image at the digest the file names, `docker cp` its `server/default/lib` and
`lib` directories out, and run its `mvn install:install-file` lines against them. The jars are then in `~/.m2`
for every worktree on the machine.

`tools/pf-linkcheck.py --lib pf-lib --lib pf-jetty-lib --reactor .` checks, against those extracted
directories, that every PingFederate and servlet member the artefacts link resolves on the pinned image. Run it
when you touch anything that calls the SDK or `pf-protocolengine`.

## Tests that need Postgres

Most tests need nothing. `libs/device-instance`'s registry suite (`IomInstanceRegistryTest`) needs a
PostgreSQL it can create tables in: it takes `IDM_TEST_JDBC_URL`, `IDM_TEST_JDBC_USER` and
`IDM_TEST_JDBC_PASSWORD`, and otherwise tries Testcontainers (the version the reactor pins is reported not to
see Docker Desktop 29; plan item DB-1 moves it to 1.21.4), and otherwise skips - and a skipped suite
under-counts the coverage dashboard. So give it a database:

```sh
docker run -d --rm --name pg-mine -e POSTGRES_USER=dashboard -e POSTGRES_PASSWORD=dashboard -e POSTGRES_DB=idm \
  -p 127.0.0.1:55432:5432 postgres:16-alpine
IDM_TEST_JDBC_URL=jdbc:postgresql://127.0.0.1:55432/idm IDM_TEST_JDBC_USER=dashboard IDM_TEST_JDBC_PASSWORD=dashboard \
  mvn -o -B clean verify
docker stop pg-mine
```

Pick a port nobody else on the machine is using; several worktrees build at once here. From Phase 2 (plan item
DB-1) every store has a real-Postgres test and a unique database per test class, and CI runs a Postgres service
container (R-CI5).

## Worktrees

One branch per package of work, in its own worktree under `.claude/worktrees/` (git-ignored), never in the
main checkout - other sessions use it. Name the branch for the package (`prod/p1-docs-register`), base it on
`origin/main` unless the package is stacked on an open pull request, and run `git branch --show-current`
before every commit. Never commit to or push `main`; never tag; never merge a pull request or enable
auto-merge from a script - those are the maintainer's.

The stash is shared by every worktree: prefer a temporary WIP commit to `git stash`.

## The version tools

- `build/pf-version.env` is the one place the PingFederate version is written down: the image tag and digest,
  the SDK version the reactor compiles against, and the product version the Terraform provider is told.
  `tools/pf-version-check.py` checks every other place that names the version agrees with it;
  `tools/pf-version-sync.py` rewrites them when it changes.
- `tools/set-version.py` keeps every pom on one project version: `--check` in CI, `0.5.0-SNAPSHOT` to bump.
  gm-api is in the lockstep.
- `tools/pf-provided-versions.py` compares the BOM's `version.pf.*` properties with the jars the image ships.

Each has unit tests under `tools/tests/`, run by CI before the tool itself is trusted:
`python3 -m unittest discover -s tools/tests`.

## Generated files

Reactor-wide files derived from the code are built by CI and published, not committed (plan decision 18): a
file that every test or documentation change regenerated conflicted whenever two pull requests met. PR #15
(merged 2026-09-27) took the dashboard and the showcase render out of git. Each Build run whose reactor build
completes publishes them as artefacts, and locally they land at the same paths, git-ignored:

- **The coverage dashboard, `docs/coverage-dashboard.md`, `.html` and `.json`** - `python3
  tools/coverage-report.py` writes all three from the jacoco and surefire reports of a full build (`mvn -o
  verify` first, with Postgres, see above) and the `@Requirement` annotations. The JSON is the machine-readable
  copy: per module, each jacoco check's methods with their line and branch counters, the test counts, and the
  requirement ids and matrix rows its tests pin. CI publishes the three as the `coverage-dashboard` artefact.
- **The showcase's documents, `showcase/docs.js`** - `node tools/build-showcase-docs.mjs` renders every tracked
  Markdown file, and the dashboard when the last build left one (`npm ci --prefix tools` once first, the
  renderer is pinned). `python3 tools/check-showcase-links.py` then checks the pages' file:line citations. CI
  publishes `showcase/` as the `showcase` artefact.

Per-component generated pages, such as `docs/configuration/` once ST-4 lands, stay committed and byte-checked.
So does `docs/development/doc-lint-baseline.txt`: `python3 tools/doc-lint.py --update-baseline` lowers it after
hits are fixed; never run it to admit new ones.

### The coverage gate and the ratchet

CI's java job runs `tools/coverage-report.py --strict --gate --baseline <json>` after `mvn verify`. It fails
the job for three kinds of reason, each printed as one line on stderr and in the job's step summary:

- `incomplete build:` (`--strict`, the default) - a module with tests left no surefire report, a module that
  configures jacoco left no `jacoco.xml`, or a jacoco check includes no method. Something skipped the tests.
- `gate:` (`--gate`) - a jacoco check includes no method; an `<include>` pattern names no method in the jacoco
  report, which jacoco itself passes (a renamed method or a typo leaves the method ungated and the build green),
  so fix the pattern; or an `@Requirement` id's prefix is not declared in
  `libs/conformance/.../Requirement.java`, so declare it there, once the document behind it has been read, or
  fix the id. An id naming a section that no conformance-matrix row declares is printed as a `gate warning:`
  and counted, not refused: on 2026-09-28, 65 of 500 ids were, under 21 prefixes, 7 of which no matrix has a
  row for. The dashboard lists them, with the matrix each belongs in.
- `ratchet:` (`--baseline`) - against the `coverage-dashboard.json` of an earlier build: a jacoco check the
  baseline had is gone or includes fewer methods (the line names the methods it no longer includes), a gated
  method is below 100% line or branch coverage, or fewer matrix rows are pinned (the line names them). Anything
  new passes: a new module, check or method needs no edit to the tool. A method renamed in the source and in
  its pattern passes too, since the count is the same.

CI's baseline is fetched by `tools/ci/coverage-baseline.sh`: the dashboard JSON that the successful push Build
on main published for the pull request's base commit (or, on a push, for the commit before it), and the newest
successful push Build on main when that run is missing. When there is none - the first run on main, an artefact
past its 90 days, a run from before the JSON existed - the ratchet passes, and the step summary says so.

To run the same locally, build, download a main run's artefact and pass its JSON:

```sh
mvn -o -B clean verify
gh run download <run-id> -n coverage-dashboard -D /tmp/baseline    # a successful Build run on main
python3 tools/coverage-report.py --gate --baseline /tmp/baseline/coverage-dashboard.json
```

`gh run list --workflow build.yml --branch main --event push --status success --limit 1` gives the run id. A
failure that names a check or method your branch never had means main has moved on since the base: merge main
into the branch.

## Pull requests

The template asks for what a reviewer needs, in this order: Summary, What changed, Verification, Adversarial
review, Merge order, Upgrade notes, Findings, Unverified. Before opening one:

1. `mvn -o -B clean verify`, with Postgres when a store is touched; every generator's `--check`;
   `python3 tools/set-version.py --check`; `python3 tools/pf-version-check.py`; `python3 tools/doc-lint.py`;
   `python3 tools/findings.py --check`; the tools' tests. A local build is not CI: after pushing,
   `gh run list` and link the run.
2. The adversarial review: a second reader told to assume the change is wrong, who tests the security,
   correctness and documentation claims and reports pass or fail. Its verdict and each issue's resolution go
   in the body.
3. A release-note fragment, `docs/releases/unreleased/<ID>.md`, named for the package: its changelog bullet
   naming the plan item, and its notes. The shape is in
   [docs/releases/unreleased/README.md](docs/releases/unreleased/README.md), and `python3
   tools/release-notes.py check` (the Docs workflow runs it) refuses a malformed one. Do not edit
   CHANGELOG.md's `Unreleased` section or a release page directly: the release folds the fragments into both.
4. An upgrade note for anything a consumer must change: an item under the fragment's "Before you deploy",
   opening with a bold title, and named by that title, never by its number, since the fold renumbers it.
5. The findings: `Closes F-NNNN` in the body, and the finding's file updated - status, `prs`, verification
   with a date. A new defect or assumption gets a new file.
6. Tests for every behaviour change; a new decision method joins its module's 100% jacoco METHOD gate (the
   pattern is in each module's pom); settings documented in the module README; docs in the same pull request.

Merge commits only, never squash or rebase: commit ids are cited in documents, pull request bodies and
release notes. The maintainer merges.

## Releasing

The maintainer cuts a release. A pull request folds the fragments (`python3 tools/release-notes.py assemble
<version>`, which appends them to `docs/releases/<version>.md` and CHANGELOG.md's `Unreleased` section and
deletes them), sets every pom to the version (`python3 tools/set-version.py <version>`), gives the changelog's
`Unreleased` heading the version and date, and finishes `docs/releases/<version>.md`; its merge commit is tagged `v<version>` and the tag pushed. The tag starts
[release.yml](.github/workflows/release.yml), which publishes the build it verified and nothing before it; the
order is in the workflow's header. A `workflow_dispatch` with `dry_run` runs the same steps and stops once
`dist/` is assembled, publishing nothing. Afterwards a pull request moves the poms to the next `-SNAPSHOT`.

The release's second gate, after the tag-version check, is a green Build on the tagged commit. The newest Build
run that a push to `main` or a dispatch started there must have concluded success, and so must the latest attempt
of every job [.github/required-checks.txt](.github/required-checks.txt) names. A pull request's Build never
counts, even when its head is the tagged commit: it tested the pull request's merge with its base, not the
commit. From 0.4.0 the gate waits for a Build that is still running, because a tag pushed straight after its
merge arrives while it is: v0.3.0's did, the gate read `java` in progress and failed, and the release was re-run
by hand (run 36278709651, F-0069). It reads the Build runs every 30 seconds for up to 20 minutes, waits while
the run is queued or pending - a run can wait over a minute behind the previous `main` Build before its jobs
exist - and logs what it is waiting for and for how long. It fails, with nothing published, when:

- the run concludes anything but success, or a required job's latest attempt does. That includes a run
  cancelled because another push to `main` came before it finished. Start a fresh Build on the tag
  (`gh workflow run build.yml --ref v<version>`) and, once it is green, re-run the release
  (`gh run rerun <run-id>`, the release's run).
- there is no such run after two minutes: Build was never started on the commit. It runs on a push to `main`,
  a pull request or by hand, never on a tag alone, so a commit that reached GitHub only through its tag, or
  only through a pull request, has none. Start one as above, then re-run the release.
- the run passed without a job `required-checks.txt` names: the tagged commit's `required-checks.txt` names a
  job its `build.yml` does not have, and no re-run can pass. Correct the file in a new commit and release from
  that.
- `required-checks.txt` names no job, or is missing. Before 0.4.0 a file that named no job passed the gate.
- the runs cannot be read three times in a row, or 20 minutes pass. Re-run the release once the API answers or
  the Build has finished.

A dry run is gated the same way, so a dry run on a branch needs a Build started there by hand first
(`gh workflow run build.yml --ref <branch>`); from 0.4.0 that holds for a branch with a pull request too.

## Style

[docs/development/style-guide.md](docs/development/style-guide.md). The short version: plain short sentences,
British spelling, a spaced hyphen and never an em dash, specification identifiers as the specification spells
them, evidence with a date, and normative claims only after reading the primary text. `tools/doc-lint.py`
checks what a machine can.
