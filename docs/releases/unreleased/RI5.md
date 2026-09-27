# The war assembler: filters.xml, read and checked with the JDK's DOM

## Changelog

- New module `build/war-assembler` (`com.pingidentity.ps.oidf:war-assembler`, JDK only, compiled for 17): it
  builds `pf-runtime.war` from the stock war, the staged jars and `build/pingfederate/filters.xml`, which now
  declares the seven filters, their paths and the order rules the script used to write with awk (plan item
  R-I5). It refuses a war in which a declared filter lacks exactly one `<filter>` and one `<filter-mapping>` over
  exactly its paths, an order pair does not hold, a path is one the stock `web.xml` does not serve, the root is
  `metadata-complete="true"`, or a declared filter's class is in no jar, and prints each path's filter chain.
- `assemble-pf-runtime-war.sh` keeps its command line and exit codes and is now a wrapper that runs it; the
  `MANIFEST`, profile and namespace checks moved into the assembler with their messages. A refusal still leaves
  no output war. With too few or too many arguments it now exits 2 with a usage line (it exited 1 on an unbound
  variable).
- `stage-modules.sh` also stages the assembler, as `assembler/war-assembler.jar` beside `modules/`; the Dockerfile
  copies it with `filters.xml`, and `conformance/compose-context.sh` carries both.

## Before you deploy

1. **Copy `filters.xml` and `assembler/` into a build context you compose yourself.** A consumer that builds with
   `docker build build/pingfederate` after `mvn package` and `stage-modules.sh` has nothing to do. A consumer that
   copies files out of `build/pingfederate` into its own context (pf-oidf-modules' `compose-context.sh` copies
   `Dockerfile`, `assemble-pf-runtime-war.sh`, `pf-entrypoint.sh`, `modules/` and `overlay/config-store/`) must
   also copy `filters.xml` and the `assembler/` directory `stage-modules.sh` now writes beside `modules/`, and
   must build this repository's whole reactor first, which it already does. Without them `docker build` stops at
   the assembler's `COPY` with `"/assembler/war-assembler.jar": not found` (checked 2026-09-28), so no image is
   built without its filters.
2. **Give the script Java 17 or later where you run it outside Docker.** The command line is unchanged:
   `assemble-pf-runtime-war.sh STOCK_WAR MODULES JOSE4J_JAR OUT_WAR [PROFILE]`. It now runs
   `$JAVA_HOME/bin/java` (or `java` on the `PATH`) with the staged `assembler/war-assembler.jar` and the
   `filters.xml` beside it (`WAR_ASSEMBLER_JAR` and `WAR_FILTERS_XML` move them). With no Java or no jar it
   refuses with exit 1 and deletes `OUT_WAR`, as any other refusal does. The image build uses the base image's
   own Java 21, so the Dockerfile needs nothing more.
3. **Expect a refusal where the script used to leave a registration alone.** The script skipped any filter whose
   name was already in the stock `web.xml`. The assembler keeps one only if it is exactly as declared - the same
   class, one mapping, the same paths, no servlet-name or dispatcher - and refuses the war otherwise, naming what
   differs. A stock war from the base image has none of these names, so this bites only a war that was
   hand-edited or assembled by something else. Re-assembling the assembler's own output is accepted and writes
   the same war.

## Notes

What was verified, 2026-09-28, against 13.1.3's stock `pf-runtime.war` (the image `build/pf-version.env` pins by
digest):

- The golden result: the shell script as of `276bcd6`, run for both profiles, wrote a `web.xml` with sha256
  `b0674250dca975b5a1046554ccb14440054bb5b66c4c8f500bc7f9d07e1ff50f` (the same for both). The assembler writes
  that file byte for byte: the stock bytes with the same block inserted before `</web-app>`. PingFederate's file
  is not in the repository; its digest and our block are (`build/war-assembler/src/test/resources/golden`), and
  `StockWarGoldenTest` compares the two when given the stock war (`-DwarAssembler.stockWar=...`), which it was,
  on JDK 17 and 20. In CI it is skipped until plan item R-CI6 supplies the stock war; U-0185 records that.
- Assembling the assembler's own output wrote the same war byte for byte (a test, and by hand on the real war).
- `docker build` of the production image, and of the conformance image from `compose-context.sh`'s context, ran
  the assembler on the base image's Java 21: the same seven filters in the same order as before, 11 and 12 jars in
  the war and in `server/default/deploy`, and the war `0640` and owned by PingFederate's user, as the script left
  it. A production stage built as conformance was refused with the script's message; a context without
  `assembler/` stopped at the `COPY`. Neither image was booted.
- The tests use descriptors written here in the stock one's shape: a duplicate mapping, a path nothing serves,
  a wrong order, `metadata-complete="true"`, a jar built for the other namespace, a declared listener whose class
  no jar holds - each refused with a message naming the problem and no war left behind. Their decision methods
  are in the module's 100% line and branch gate.

Why a jar and not the single-file source launcher, and why the `MANIFEST` checks moved into Java, is in
[build/war-assembler/README.md](../../../build/war-assembler/README.md). `filters.xml` declares no listener yet;
plan item F-2 adds the lifecycle listener, which the assembler will register and check.
