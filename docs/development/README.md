# Developer documentation

How the repository is worked on:

- [CONTRIBUTING.md](../../CONTRIBUTING.md) - building, the PingFederate jars, the Postgres-backed tests,
  worktrees, the version tools, generated files, what a pull request carries, and how a release is cut and
  what its workflow waits for.
- [style-guide.md](style-guide.md) - the house style for prose, code comments, commits, pull requests,
  release notes and upgrade notes, and the "verify, don't reason" rule. `tools/doc-lint.py` checks the part of
  it a machine can check, against [doc-lint-baseline.txt](doc-lint-baseline.txt).
- [classloaders.md](classloaders.md) - the loaders one PingFederate JVM loads this repository's classes in, and
  the five rules that follow: statics are per loader, only the webapp's copy starts threads, code an OGNL
  criterion reaches never throws, loaders talk only through string-keyed request attributes and the System
  properties already in use, and plugins shade and relocate platform.

Phase 7's developer guide (plan item D-8) - builds, PingFederate jars, Postgres tests, worktrees, mutation
testing, the generators, rigs and classloaders - lands here too.
