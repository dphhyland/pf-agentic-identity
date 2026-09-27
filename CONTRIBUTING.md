# Contributing

How work on this repository is done: the build, the tests that need a database, worktrees, the version tools,
the files that are generated, and what a pull request carries. The house style for anything written -
prose, comments, commits, pull requests, release notes - is in [docs/development/style-guide.md](docs/development/style-guide.md).
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

Some files are derived from the code and checked rather than written:

- **`docs/coverage-dashboard.md` and `.html`** - `python3 tools/coverage-report.py` writes them from the jacoco
  and surefire reports of a full build and the `@Requirement` annotations; `--check` compares.
- **The showcase's documents** - `node tools/build-showcase-docs.mjs` renders every tracked Markdown file into
  `showcase/index.html`'s `DOCS_HTML` line (`npm ci --prefix tools` once first, the renderer is pinned);
  `--check` compares. `python3 tools/check-showcase-links.py` checks the page's file:line citations exist.
- **`docs/development/doc-lint-baseline.txt`** - `python3 tools/doc-lint.py --update-baseline` lowers it after
  hits are fixed; never run it to admit new ones.

The dashboard and the showcase render are being moved out of git by a concurrent pull request
(`prod/p1-generated-files`, plan item R-CI5 brought forward): until it merges, both are tracked and CI fails
on a stale copy, so regenerate the dashboard after any change to a Java test (with Postgres, see above) and
the showcase after any change to a tracked `.md`, and commit the result. After it merges, CI generates and
publishes both and there is nothing to regenerate; this section is rewritten then. Per-component generated
pages, such as `docs/configuration/` once ST-4 lands, stay committed and byte-checked either way.

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
3. A release-note fragment: one bullet under `Unreleased` in [CHANGELOG.md](CHANGELOG.md), naming the plan
   item.
4. An upgrade note in `docs/releases/<version>.md` under "Before you deploy" for anything a consumer must
   change (create the page from the previous one's shape if it is missing).
5. The findings: `Closes F-NNNN` in the body, and the finding's file updated - status, `prs`, verification
   with a date. A new defect or assumption gets a new file.
6. Tests for every behaviour change; a new decision method joins its module's 100% jacoco METHOD gate (the
   pattern is in each module's pom); settings documented in the module README; docs in the same pull request.

Merge commits only, never squash or rebase: commit ids are cited in documents, pull request bodies and
release notes. The maintainer merges.

## Style

[docs/development/style-guide.md](docs/development/style-guide.md). The short version: plain short sentences,
British spelling, a spaced hyphen and never an em dash, specification identifiers as the specification spells
them, evidence with a date, and normative claims only after reading the primary text. `tools/doc-lint.py`
checks what a machine can.
