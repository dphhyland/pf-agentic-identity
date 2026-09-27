# Phase 1 follow-ups the wave-1 reviews left, and the register brought up to date

## Changelog

- **Phase 1 follow-ups** (package HYG; plan items X-D02, R-I1, P0-7, M-2, R-CI4 and R-CI5; closes F-0014 and
  F-0066, opens F-0120, F-0121 and U-0130, updates F-0006): Build's `java` job runs `RedisLiveTest`'s plain half
  on a `redis:7-alpine` service and its TLS half on a TLS-only Redis that `tools/ci/start-tls-redis.sh` starts
  with a CA and a localhost certificate made for the run; CodeQL does not analyse the iOS client's Swift yet, for
  the reason U-0130 records; the showcase describes the image as the staging profiles and the entrypoint left it
  and the release as its gate runs now; the device-instance, device-enrolment and ssf READMEs describe the code
  as it is.

## Before you deploy

1. **device-enrolment reads `IDM_DATABASE_URL`, whatever its README said.** The README's configuration table
   named `DATABASE_URL`. `Main` requires `IDM_DATABASE_URL` - the Identity Object Model directory, as a JDBC URL
   or a `postgresql://` DSN - and refuses to start when only `DATABASE_URL` is set, naming the rename. The code
   did not change here; if you configured the service from the README, rename the variable. The table now lists
   every variable `Main` reads, `REGISTRY` and the connector path's twelve included.
2. **Delete a `pf.plugins.ciba-sim.jar` that v0.3.0's assets left behind.** v0.3.0's release assets carry the
   CIBA simulator (checked 2026-09-27), and there it runs on `OIDF_CIBA_SIM_ENABLED` alone. From 0.4.0 the
   release stages the production profile and its assets leave the simulator out, so copying the new assets over
   the old ones keeps the old jar. In `modules/` the assembler refuses it, because 0.4.0's `MANIFEST` does not
   name it; a jar you copied into `server/default/deploy` yourself stays loaded until you delete it.

## Notes

What changed:

- **CI.** build.yml's `java` job gains a `redis:7-alpine` service and two steps. The first gives the service its
  password over `docker exec ... CONFIG SET requirepass`, because a service container takes no command line
  (actionlint 1.7.12 lists the keys a service accepts: credentials, env, image, options, ports, volumes). The
  second runs `tools/ci/start-tls-redis.sh`, which makes a CA and a certificate for `DNS:localhost` only (the
  CA's key is deleted once the certificate is signed; nothing is tracked), starts `redis:7-alpine` serving TLS
  only on `127.0.0.1:6380` as the runner's user, waits for a `PONG` over TLS and prints the two TLS variables
  into `$GITHUB_ENV`. The job sets only `OIDF_TEST_REDIS_*`: `OIDF_REDIS_URL` or `REDIS_URL` would configure
  the stores themselves, and `AttestationSupportTest` skips itself when it sees either. The script works the
  same on a Mac, and the client-attestation README and `RedisLiveTest`'s javadoc point at it.
- **CodeQL and Swift.** A `swift` entry on macos-latest with a manual `swift build --arch arm64` of
  AgentIdentityKit worked (PR #33's run 36309012583: Xcode 26.6, Swift 6.3.3, 27 rules, nothing found), but took
  13 min 35 s, 11 min 37 s of it the traced build, against about 5 min for Java. Running it only when
  clients/ios changes would leave every other pull request without a category main has, which code scanning
  reports as "Code scanning cannot determine the alerts introduced by this pull request, because 1
  configuration present on refs/heads/main was not found" (github/codeql discussion 18506). So codeql.yml says
  why Swift is not analysed, and U-0130 records the options.
- **The register.** F-0014 is closed with the staging, assembler and gate evidence below. F-0066 is closed: no
  statement describes the 13.0.3 build except the history PR #13 kept. F-0120 (every release publishes the
  simulator to GitHub Packages), F-0121 (documentation later changes made false, left for the packages that own
  it) and U-0130 are new; F-0006 names this pull request.
- **The showcase.** PR #19 (staging profiles, the entrypoint) and PR #30 (the release gate) changed the image
  build and the release after PR #13 re-read the page, and this branch grew build.yml's `java` job. The page
  said nine jars in every image, a plaintext archive boots with a warning, the inline age identity goes to a
  temporary file, four workflows and fourteen gated poms. 56 statements whose cited lines had only moved were
  re-pointed through a line diff from 915f682; the rest citing the image build and the workflows were read
  beside the code and corrected. The image's settings gain `$5 PROFILE`, `STAGING_PROFILE`, `PF_ARCHIVE_FILE`,
  `PF_ARCHIVE_SHA256`, `PF_BOOTSTRAP` and the entrypoint's `OIDF_DEPLOYMENT_PROFILE`; the CIBA simulator's
  statements name its three-part gate; and the playground's registry gate says what P0-8 established about a
  failed criterion (400 `invalid_grant` with the criterion's Error Result, for expression criteria on 13.1.3)
  and that its conditional criteria have not been run.
- **READMEs.** device-instance names the SSF receiver as `CaepSignalApplier`'s one live caller and says both
  profiles stage the jar; device-enrolment's table is complete; ssf counts the staged jars by profile.
- **Already done elsewhere.** build.yml's `workflow_dispatch` comment was corrected by PR #30 itself (merged
  2026-09-27T09:12Z); it matches release.yml, which reads only push and dispatch Builds. `tools/doc-lint.py`
  and `tools/findings.py` needed nothing for `docs/releases/unreleased/`: doc-lint checks every tracked `.md`,
  this one included, and findings.py reads only `docs/findings/`.
- **For the 0.4.0 fold-in.** 0.4.0.md's line that the Redis service in CI is R-CI5 is out of date from this
  package: CI runs both halves of `RedisLiveTest`.

Verified on 2026-09-27:

- `mvn -o -B clean verify` on JDK 20, with Postgres 16, a plain Redis given its password as CI does and the
  script's TLS Redis: BUILD SUCCESS, 2937 tests, 0 failures, 4 skipped (the federation live-chain tests);
  `RedisLiveTest` 5 of 5, `AttestationSupportTest` 3 of 3, `IomInstanceRegistryTest` 22 of 22; every coverage
  check met. On JDK 17, the modules this branch touches and their dependencies (conformance, oidf-jose,
  device-instance, client-attestation, ciba-sim): 391 tests, 0 failures, `RedisLiveTest` 5 of 5.
- CI on this pull request: the `java` job (run 36309012552) ran `RedisLiveTest` with none skipped, after
  `CONFIG SET` answered `OK` and the TLS server answered on 6380. actionlint 1.7.12 and zizmor 1.30.1 (online
  audits) are clean; the one finding zizmor suppresses that main's workflows lack is `unpinned-images` on the
  Redis service, which the Postgres service shares.
- F-0014: `stage-modules.sh` with no argument staged eight jars under `MANIFEST/2 profile=production`, none
  holding a simulator class; `--profile conformance` added `pf.plugins.ciba-sim.jar`; the assembler refused a
  conformance stage for a production image and the reverse, leaving no war.
- `check-showcase-links.py` resolves all 1082 references; the page's script parses (`node --check`).

Residual risk:

- The TLS step depends on the runner's Docker and on `redis:7-alpine` by tag, as the Postgres service depends on
  its image; a change to either fails the `java` job, loudly.
- The iOS client has no static analysis in CI until U-0130 is settled.
- Showcase statements that cite files other than the image build and the workflows were not re-read here.
