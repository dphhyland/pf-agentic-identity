# Reproducible jars and wars, compared before anything is published

## Changelog

- Every pom sets `project.build.outputTimestamp`, the date written on each jar and war entry, so a rebuild of
  one commit makes the same bytes. `tools/set-version.py` sets it with the version - HEAD's commit time, in UTC,
  for a release, and `2000-01-01T00:00:00Z` for a snapshot - and `--check` refuses a pom without it, a value that
  does not parse, and a release that still carries the snapshot's date (plan item P0-5).
- Before anything is published, the release makes the rebuild its deploy will make with `mvn install` and
  compares every rebuilt jar and war with `dist/`, byte for byte, so a mismatch stops it before a draft or a
  package exists. It compares again after the deploy. The wars are no longer let off with a note. A dry run runs
  the same install and comparison, so the step that failed v0.5.0 is exercised before a tag.

## Before you deploy

None.

## Notes

**What failed.** The v0.5.0 Release, run 36518030296 on the tag's commit 0d049d79, failed at "what Packages got
is what dist/ holds": 12 of the 14 dist jars did not match the files `mvn -B -DskipTests deploy` had just
published; only agent-registry and platform did (the step's log, read 2026-09-29). deploy runs the lifecycle
again, and the compiler recompiles every module whose reactor dependency verify has rebuilt ("Recompiling the
module because of changed dependency"), so the jar plugin builds those jars again. No pom set
`project.build.outputTimestamp`, so each rebuilt jar's entries carried the new build's times. Rebuilt the same
way locally (at a5a2d49e, 2026-09-29), rar-model's jar has the same entries, sizes and CRCs as the first build's,
and different entry dates. The comparison ran only after the deploy, so the mismatched jars were in Packages by
the time it failed, and the dry run never reached it: it stopped once `dist/` was assembled. The workflow's
comment that deploy leaves an up-to-date jar alone was wrong, and is corrected.

**The new order.** After `dist/` is assembled, `mvn -B -DskipTests install` makes the rebuild the deploy would
make, writing only `target/` and the runner's `~/.m2`, and `sha256sum -c --strict dist-sources.sha256` holds
every dist jar and war to it. Both modes run this; the dry run stops after it. Only then is the draft created
and `mvn -B -DskipTests deploy` run. deploy rebuilds once more (the install rebuilt every reactor dependency
again), so the comparison runs a second time on what deploy published, before the draft is published.

**Where v0.5.0 stands (checked 2026-09-29).** The tag v0.5.0 exists, at 0d049d79. The release is still a draft;
its assets are the `dist/` files that run verified and assembled before the deploy. That run's deploy step
succeeded, so GitHub Packages holds the 0.5.0 artefacts it published. The Packages jars and the draft's jars were
built from the same commit in the same job, but their bytes were not compared here: the local gh token cannot
read Packages (the packages API answers "Not Found"). By the failed step's own log, 12 of those Packages jars
differ from the draft's, in the way the paragraph above describes. Whether to publish the draft, and what to do
about the Packages jars, is the maintainer's call; this change does not touch either.

**The design.** No parent pom is shared, so the property is in each of the 27 poms the reactor lists, the
aggregator, the BOM and the demo-rs relocation pom included. A release's value is HEAD's committer time at the
bump, which is the commit before the release, so bumping twice on one commit writes the same poms and the value
comes from the repository rather than a clock. A snapshot's is fixed. `--check`, which Build's lint job and the
release's tag check both run, holds all 27 to one value in the form `2026-09-29T03:30:00Z` inside the range
maven-archiver accepts, and pairs it with the version. The archive plugins the v0.5.0 release job ran all honour
it: maven-jar 3.3.0, 3.4.1 and 3.5.0 (the version the runner's Maven binds by default), maven-war 3.4.0,
maven-shade 3.5.3 and maven-assembly 3.7.1; the build uses no source, antrun or other archiver. Shade copies a dependency's entries with that jar's
own dates, which are fixed with the dependency. platform, the RAR plugin and the CIBA simulator now rebuild their
plain jar every time (`forceCreation`): shade puts the shaded jar in its place, and a second build that found the
plain jar up to date shaded the shaded jar again. The published jar was the same either way, but its
`original-` input was not.

**Verified locally (2026-09-29, JDK 17, Maven 3.9.8, a per-worktree local repository).** `mvn -B -DskipTests
clean verify`, then `mvn -B -DskipTests install` over it, then `mvn -B -DskipTests clean install`, with the sha256
of every jar and war under each module's `target/` taken after each. The install recompiled 34 times and rebuilt
21 archives, and all 46 files were byte-identical across the three builds: once at 0.6.0-SNAPSHOT, and once with
the poms set to 0.6.0 by `tools/set-version.py` (then set back). Before the change, the same two builds at
origin/main a5a2d49e left 27 of the 46 different, gm-api.war and oidf.war among them. The release's own order
was run too, at 0.6.0-SNAPSHOT: `clean verify`, `install`, then `install` again in place of the deploy. The
second install recompiled 34 times and rebuilt 21 archives as the first did, and all 46 files matched the verify
build's after each.

**Residual.** A release bumped straight from another release by hand, without the tool, keeps the older
release's date: its archives are still reproducible, but dated at the earlier cut. `--check` catches the
hand-made bump from a snapshot, not that one.
