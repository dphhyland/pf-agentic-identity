# PingFederate 13.1 and the Jakarta migration - plan

**Status: done in this repo, 2026-09-26.** What happened to each of [the steps](#the-steps):

| Step | What happened |
|---|---|
| 0 | The namespace guard in `assemble-pf-runtime-war.sh` and the conformance work both landed on `main` on 2026-09-22. `v0.1.4` was cut from `main` on 2026-09-23. The `pf-13.0` branch starts at the last `javax.servlet` commit on `main` (`a7a8758`, 2026-09-24, the parent of the migration), and `v0.1.5` on it is the last `javax.servlet` release. `pf-13.0` is frozen from 2026-09-26: no backports. |
| 1-5 | Done on `main` in `12626ec` (2026-09-24) - the rename (58 files: the plan's 46 plus the CIBA rig's), the coordinates, the plugin's tests on the `Builder`, both descriptors, the workflows, the `FROM` line, and `tools/pf-linkcheck.py` in CI. 0.2.0 is the first `jakarta.servlet` version. `mvn clean verify` against the real 13.1.3 jars: 1392 tests, 0 failures, 4 skipped, every gate passing; the link checker reports 0 unresolved on 13.1.3 and 59 on 13.0.3. |
| 6 | Booted. The conformance rig runs 13.1.3 with every module in it, and the FAPI 2.0, SSF, FAPI-CIBA and both OpenID Federation plans ran against it on 2026-09-24 and 2026-09-25 - results in [conformance/README.md](../conformance/README.md). |
| 7 | 0.2.0 was never tagged: the first release for 13.1.3 is v0.3.0, and upgrades are supported from it. The consumers have not moved - on 2026-09-26 `idp-agentic-demo`'s `Dockerfile` and `pf-oidf-modules`' export helper still name 13.0.3. They move as pairs, PingFederate 13.1.3 and v0.3.0 in one commit, in their own repos. |
| 8 | Decided 2026-09-26, and not as first written: the audience rule stays in `Fapi2ProfileFilter`; the plugin reads `getJakartaRequest()` from v0.3.0; `getUserKey()` waits for the principal resolver. See step 8 below. |

What was still open when this landed is in [what is not verified](#what-is-not-verified), with what
has been settled since.

PingFederate 13.1 moved its servlet container from `javax.servlet` to `jakarta.servlet`. This repo
is compiled against `javax.servlet`, so an image built on 13.1.3 boots to a 503. This plan says what
has to move, what does not, in what order, and what it costs. Every claim carries the command that
produced it. Where something is inference rather than observation, it says so.

Compared throughout: `pingidentity/pingfederate:13.0.3-alpine_3.23.4-al21-latest`
(`sha256:b52d6888…e126`) and `pingidentity/pingfederate:13.1.3-alpine_3.24.1-al21-latest`
(`sha256:0d559261…3a4a`), with spot checks of `13.1.0-latest`. None was run - running needs a
licence, extracting does not.

The plan was put through two adversarial reviews before it was called finished. They overturned
several things in the first draft, including its advice to consumers. What they found is recorded
under [probes and claims that were wrong](#probes-and-claims-that-were-wrong).

---

## The recommendation

1. **Cut the servlet modules over to `jakarta.servlet` in one step, on `main`, as release 0.2.0.**
   Keep 13.0.x alive as a maintenance branch for security backports only. Do not build both lines
   from one source tree.
2. **Leave the two SDK plugins alone for now.** They are not on the critical path - see
   [the premise, corrected](#the-premise-corrected). (Later, 2026-09-26: the RAR plugin moved to
   `getJakartaRequest()` for v0.3.0, and both plugins are now built and supported for 13.1 only.)
3. **Three things land first, on the javax line, in this order:** a namespace guard in
   `assemble-pf-runtime-war.sh` (**done**); the conformance work, which was uncommitted in a worktree
   (**done** - landed on `main` 2026-09-22); and a final javax release, **`v0.1.4`, cut from `main`**.
4. **Pin consumers to `v0.1.4` - not to `v0.1.3`.** `v0.1.3` is 19 commits behind `main`, and those
   commits are the 15 September audit fixes. Pinning to it would roll a deploy back past them.
   (`v0.1.5` has since followed on `pf-13.0`; a consumer still on 13.0.x pins that, the last javax
   release.)

The cost of the cut-over is small and measured, not estimated. 48 files name `javax.servlet`; 46 are
rewritten by a blind replace (182 lines), one plugin test changes by hand, and one plugin source file
deliberately stays. Add two test-scope dependency swaps and the coordinates. A scratch copy of the
reactor built that way passes `mvn clean verify` against the real 13.1.3 jars with **1193 tests, 0
failures, 4 skipped - identical, module for module, to the 13.0.3 baseline**, with all 14 coverage
gates executing and passing on both sides. What is left is the part static analysis cannot do:
booting it.

(The spike predates the conformance merge, so those figures are the 45-file / 166-line tree and its
1193 tests; the tree is now 48 files, 184 lines and 1302 tests. The three files that arrived use only
types the spike already covered, so the shape of the result does not change - but the spike has not
been re-run on top of them, and should be before the cut-over commit is written.)

---

## The premise, corrected

The starting finding was that upgrading is impossible "without migrating every servlet and filter".
That is right about servlets and filters, and it under-counts and over-counts at the same time.

**It under-counts.** `javax.servlet` is not confined to the five modules named in the brief. It
reaches into two libraries - `libs/client-attestation` (a `@WebServlet`) and `libs/openid-federation`
(two config classes reading `ServletConfig`) - both of which are staged into `pf-runtime.war`.

**It over-counts.** The plugins do not have to move. Ping made the SDK plugin seam dual-namespace in
13.1 and ships a bridge to back it:

```
13.0.3  public javax.servlet.http.HttpServletRequest   getRequest();
13.1.3  public javax.servlet.http.HttpServletRequest   getRequest();          // kept, bridged
13.1.3  public jakarta.servlet.http.HttpServletRequest getJakartaRequest();   // new
```

`pf.plugins.pf-rar-paz-plugin.jar` and `pf.plugins.instance-registry-datasource.jar`, **as built
today**, resolve every PingFederate member they reference on 13.1.3. Built against the 13.1.3 SDK
instead, they still resolve on 13.0.3. The plugin binary is line-independent; the servlet binaries
cannot be.

The bridge is a transition aid, not a contract. On 13.1.3 both the javax getter and the context's
public constructor carry

```
java.lang.Deprecated(since="13.1", forRemoval=true)
```

so the plugin moves to `getJakartaRequest()` before whichever release removes the getter - not now.

**And the break is narrower than "everything".** Across the whole linked surface of every artifact
this repo ships - constant pools, not imports - exactly one PingFederate member fails to resolve on
13.1.3:

```
org/sourceid/oauth20/issuer/OAuthIssuerUtils.getIssuerValue:(Ljavax/servlet/http/HttpServletRequest;)Ljava/lang/String;
```

It has ten callers in four modules. `OAuthIssuerUtils` is
PingFederate-internal, not SDK, and got no second overload - the parameter simply became
`jakarta.servlet.http.HttpServletRequest`, already so in 13.1.0. That single method is why one binary
cannot serve both lines, independently of what Jetty will load.

---

## Inventory

### What moves

`javax.servlet` appears on **184 lines in 48 files**. 183 are plain `import` lines. The one
exception is a fully-qualified name in a test (`ClientAttestationAuthFilterTest.java:275`). There
are no wildcard imports.

| Module | main files / lines | test files / lines | What it holds |
|---|---|---|---|
| `servlets/pf-integration` | 11 / 52 | 7 / 25 | 3 filters, 4 servlets, the OGNL-side utils |
| `servlets/ssf` | 9 / 42 | 6 / 12 | 1 filter, 5 servlets |
| `servlets/attestation-issuer` | 3 / 18 | 3 / 8 | 3 servlets |
| `services/gm-api/servlet` | 3 / 15 | 0 / 0 | 3 servlets, registered in its own `web.xml` |
| `libs/client-attestation` | 1 / 6 | 1 / 2 | 1 servlet (`/federation/attestation-challenge`) |
| `libs/openid-federation` | 2 / 2 | 0 / 0 | `ServletConfig` readers |
| `plugins/rar-paz-plugin` | 1 / 1 | 1 / 1 | main **stays javax**; the test import changes by hand |
| `servlets/oidf-war` | 0 / 0 | 0 / 0 | no Java; a descriptor and an assembly |

That is 13 `@WebServlet` servlets on **26 paths** in the root context, 3 servlets in `gm-api.war`,
and 4 filters registered by `assemble-pf-runtime-war.sh`. None of the 26 paths collides with any of
the 32 URL patterns PingFederate 13.1.3 maps itself.

Source names **14 servlet types**; bytecode links **16**, because `ServletOutputStream` and
`ServletContext` arrive as return values and are never imported. All 16 are member-for-member
identical between the `jetty-servlet-api-4.0.9.jar` and `jetty-jakarta-servlet-api-5.0.2.jar` that
13.1.3 ships, once the namespace is normalised. So are 84 of the 85 classes in those jars; the
exception, `HttpSessionBindingEvent`, is not used here. The change is a pure rename.

### What does not move

`javax.net.ssl` (20 lines) and `javax.sql` (23 lines) are JDK packages. They are not part of the
Jakarta rename and stay exactly as they are. There is no `javax.annotation`, `javax.inject`,
`javax.ws.rs` or `javax.xml.bind` anywhere in the tree. A tool that rewrites `javax.` wholesale
would break the build; the replace has to be `javax.servlet` and nothing wider.

### Outside the Java

| File | What names the old line |
|---|---|
| `bom/pom.xml` | `javax.servlet:javax.servlet-api:4.0.0`; `version.pingfederate` 13.0.0.3; `commons-lang` 2.4 |
| 7 module poms | the version-less `javax.servlet-api` dependency (six switch; the plugin's stays) |
| `services/gm-api/servlet/pom.xml` | its own convention: `local.pingfederate:servlet-api:4.0.9`, `pingfederate.version` 13.0.3. It imports no BOM |
| `servlets/oidf-war/…/web.xml` | `xmlns.jcp.org/xml/ns/javaee`, `web-app_4_0.xsd` |
| `services/gm-api/…/web.xml` | `xmlns.jcp.org/xml/ns/javaee`, `web-app_3_1.xsd`; comments naming "Jetty EE8" and Servlet 3.1 |
| `.github/workflows/build.yml`, `release.yml` | `PF_IMAGE`; six hard-coded `-Dversion=13.0.0.3` / `13.0.3`; `jetty-servlet-api:4.0.9` |
| `build/pingfederate/Dockerfile`, `README.md` | the `FROM` line; "PF 13.0.3" in prose |

The coordinate `13.0.0.3` is a label that `install:install-file` assigns. The jars call themselves
`13.0.3.0` and `13.1.3.0` in their own `pom.properties`. The new line should use the real string.

Prose that goes stale with the move, none of it load-bearing (all updated on 2026-09-26, bar the gm-api
gaps report, which stays a dated report against 13.0.3): `docs/unverified.md`,
`docs/client-attestation-architecture.md`, `servlets/pf-integration/README.md`, the three READMEs
under `plugins/` and `services/gm-api/`, `services/gm-api/docs/pingfederate-gm-api-gaps.md`, and two
vendored skill copies that will mislead the next agent to read them:
`services/gm-api/.claude/skills/pingfederate-java-extensions/SKILL.md` ("PF 13's WARs declare Servlet
3.1 with the `javax.servlet` namespace") and
`plugins/rar-paz-plugin/.claude/skills/pf-rar-paz-plugin/SKILL.md` (the context "has only
`getRequest()`, `getClientId()`, `getScope()`" - no longer true).

### The conformance work - landed 2026-09-22

This was the plan's biggest sequencing risk while it sat uncommitted in the `ssf-conformance`
worktree. It is now on `main`, and the counts above include it.

What it added to the migration's surface: `Fapi2ProfileFilter` and `Fapi2RequestPolicy` with their
tests, plus a new SSF servlet test - **a fourth filter** (mapped over eight PingFederate endpoint
patterns and ordered ahead of the other three), a **tenth caller of `getIssuerValue`**, and 18 more
`javax.servlet` lines across three files. It uses only types the inventory already lists, so the
replace covers it unchanged.

It also rewrote `assemble-pf-runtime-war.sh`, the same file the namespace guard edits. The two merged
without conflict, verified by trial merge before either landed and again on the real merge.

---

## What changed between 13.0.3 and 13.1.3

| Thing | 13.0.3 | 13.1.3 | Consequence here |
|---|---|---|---|
| Jetty | 12.0.34.1, **ee8** only | 12.0.36.1, **ee9** only | No ee8 context is left for a loose WAR, so `gm-api.war` and `oidf.war` migrate too. 13.1.0 checked directly: already ee9, bridge already present. The cut is the whole 13.1 line |
| Servlet API jars | `jetty-servlet-api-4.0.9` | that, **plus** `jetty-jakarta-servlet-api-5.0.2` | The javax jar stays as a type library - for the SDK's javax seam, the bridge, and Ping's own bundled adapters, which are still javax. It is why javax code still *links*. No container is left to *load* it |
| Bridge | - | `pingcommons-jakarta-ee8-bridge.jar`, 17 classes | Adapters in both directions. On the javax request adapter, `getAttribute`, `getParameter` and `setAttribute` delegate. Four methods throw `UnsupportedOperationException`: both `startAsync`, `getAsyncContext`, `upgrade`. `getServletContext()` and `getRequestDispatcher()` return `null`. The plugin calls none of these |
| `AuthorizationDetailContext` | javax getter, public ctor | `getRequest()` and the ctor both `forRemoval`; new `getJakartaRequest()`, `Builder`, `getUserKey()` | Plugin main is unaffected. Its tests construct the context - use the `Builder`. `getUserKey()` may retire the plugin's resource-owner workaround; not explored |
| `AuthorizationDetailProcessor` | | one constant added | No new abstract method; the plugin still implements it |
| `OAuthIssuerUtils` | 5 methods take a javax request | the same 5 take a jakarta request; nothing javax left | The one hard linkage break |
| `context.HttpRequest` (OGNL) | a javax request | a **jakarta** request - never a javax adapter | After migration the OGNL-side cast succeeds. Before it, the cast throws |
| `org.sourceid…Client` | uses `commons-lang` 2 | uses `commons-lang3` (from 13.1.0; the old jar lingers until 13.1.2) | Test classpath of two modules. Runtime unaffected - this repo never references lang 2 itself |
| `Client` API | - | `hasClientCertCredentials()` removed; 46 members added | The removed method is not used here. Additions include a multi-auth model, `isCimd()`, and per-client DPoP proof settings (nonce, lifetime, replay - no algorithm control) |
| `MgmtFactory` | class, public ctor | `final`; ctor now private; `getMasterKeyEncryptor()` gone; `getSessionSettingsManager()` returns a different type | This repo calls only `getClientManager()`, which is unchanged |
| `ClientManager` | | one abstract method added | Linked but never imported - reached through `MgmtFactory`. Nothing here implements it, and the four methods called are unchanged |
| The other 28 imported PF classes | | | Identical `javap -protected` output, including all three `com.pingidentity.access.*` accessors. That view cannot see annotations; the two deprecations above are the only new ones |
| `pf-runtime.war` `web.xml` | `javaee`, 3.1 | `jakartaee`, 5.0 | Otherwise identical: same 19 filters in the same order, plus one new mapping (`/.well-known/apple-app-site-association`) |
| Bytecode / JDK | Java 17 classes, JDK 21.0.11 | Java 17 classes, JDK 21.0.12.1 | Temurin 17 in CI and `release 17` both stand |
| Third-party | jose4j 0.9.6, Jackson 2.21.1, log4j 2.25.3, BC-FIPS 2.0.x | same jose4j and Jackson; log4j 2.25.4; BC-FIPS family 2.1.x; `pf-authn-api-sdk` 1.x → 2.x | Nothing to do. BouncyCastle is used here only at test scope, non-FIPS, in modules that are never staged into PingFederate. `pf-authn-api-sdk` is not used |
| New jar | - | `pf-sdk-common.jar` | An outbound OAuth helper. Nothing this repo imports references it; CI still installs two PF jars |
| Audience flag | literal absent from every jar | `Rfc7523bisCompliantAudienceVerification`, `defaultForUpgrade="false"` | Confirms the reason for moving. The engine reads it with a default of `false`, so an upgraded archive arrives with it off and it has to be set |

### The image layout the Dockerfile leans on

All of it holds. `pf-runtime.war` is at `/opt/server/server/default/deploy/`; `/opt/bootstrap.sh`
exists; `run.properties.subst.default` still has exactly one `^pf.http.port=-1`; `log4j2.xml` still
has exactly one `</Loggers>`; the licence hook is still `17-check-license.sh`; the Alpine community
repository (where `age` lives) is still enabled; the stock `DataDeployer.xml` has the same three
items; the five audit logger names `SsfAuditLogSource` attaches to are still declared and still
exist as classes. Neither image has `/opt/server/sdk`, so the workflows' fallback of picking the SDK
jar by content is what actually runs, on both.

**`assemble-pf-runtime-war.sh` needs no change to work.** Run unmodified against the 13.1.3 war it
inserts all three filters and its ordering check passes. That is also the problem: it has no idea
which namespace it is assembling, which is how a javax-in-jakarta war got built and failed only at
boot.

An aside, not a 13.1 change: both images also ship
`/opt/staging/instance/server/default/conf/log4j2.xml.subst.default`, and the start-up hooks expand
staging templates and lay them over the instance. The Dockerfile patches `run.properties` through
its staging template but patches `log4j2.xml` in `/opt/server`. Reading the hook, the module's DEBUG
logger line looks likely to be overwritten at boot - on 13.0.3 today as much as on 13.1.3. Read from
source, not observed.

---

## Strategy

### Option A - hard cut-over (recommended)

`main` becomes the 13.1 line. `v0.1.4` is the last javax release; a `pf-13.0` branch is cut from it
and takes security fixes only.

Cost: the work in [the steps](#the-steps). One mechanical commit, reviewable as a rename. One set of
artifacts, one CI job, one `FROM` line, no new build machinery.

What it gives up: `main` can no longer produce a build for PingFederate 13.0.x. A fix needed on both
lines is made twice. Because 183 of the 184 lines are imports, a cherry-pick to `pf-13.0` conflicts
only when it touches an import block - but a pick that applies cleanly can still carry a
`jakarta.servlet` import across and fail to compile there. That failure is loud, and CI on the branch
catches it.

### Option B - one tree, both lines

The pattern in the `pingauthorize-java-extensions` skill: keep `src/main/java` on javax, and for the
other line copy it to `target/generated-sources` through a `javax.servlet` → `jakarta.servlet` token
filter, then compile that. The replace is a pure rename here, so the mechanism would work. It is the
surroundings that do not transplant:

- **That skill describes one pom. Here six module poms would need the source-root swap**, each
  standalone by design (`bom/pom.xml`: "no parent inheritance, keeping the absorbed modules'
  provenance property intact"). The same switch would also have to exist in the BOM, in `oidf-war`
  for its descriptor, and in gm-api's separate coordinates. Either that is written out nine times
  or the no-parent rule goes.
- **`-P` does not reach the BOM.** Every module except gm-api takes its versions from `bom/pom.xml`
  by `scope=import`, and Maven does not apply command-line profile ids to an imported pom. Tested:
  `-Ppf131` activated the consumer's own profile and left the BOM's managed dependency on javax;
  `-Dpf.line=13.1` flipped it. So the switch has to be a property, activated the same way everywhere
  - not the profile id the skill uses.
- **The plugin is the exception to its own rule.** A blind token filter breaks it (step 1), so the
  filter needs a carve-out, and the plugin's tests need different sources per line regardless.
- **Two artifact sets.** Servlet binaries are per-line, so every release carries two of each:
  classifiers or version suffixes in GitHub Packages, two `modules/` sets and two `MANIFEST`s from
  `stage-modules.sh` (which derives filenames from the one BOM version), two halves of
  `release.yml`, and a CI matrix that extracts two images.
- **It is a blind string replace**, so it also rewrites comments and strings. Harmless today, a trap
  for whoever next writes `javax.servlet` in a doc-comment meaning it literally.

What it buys: both lines from one commit, no cherry-picks.

**Why not.** Option B pays for itself when an extension ships to customers you do not control, on
versions you cannot choose. Here there are three consumers, all in the same hands, and the reason
to move at all is a FAPI 2.0 behaviour that 13.0.x cannot be configured to have. There is nobody to
keep on 13.0.x for long. B would add permanent machinery to nine poms to serve a line whose only
future is security backports.

B becomes the right answer if that changes - if one consumer has to stay on 13.0.x for more than a
release or two *and* needs new features there. The cut-over does not close that door: the rename is
reversible by the same token filter, in the other direction.

### Option C - stay on 13.0.x

Free today. Keeps `Fapi2ProfileFilter`'s audience half as a permanent in-house reimplementation of
something the product now does, and leaves the repo unable to take any 13.1+ fix. Deferring is
reasonable; it is not a strategy. The cost of A does not grow much with time, but the amount of code
written against javax does.

---

## The consumers

All three are present under `~/Source` and were read, not assumed.

| Repo | How it takes delivery | If the cut-over lands and nothing else is done | How it pins |
|---|---|---|---|
| `pf-oidf-modules` | Two paths. **The deploy workflow** checks out this repo with no `ref:` and pins its own `PF_IMAGE` - for the compile classpath only; the runtime base comes from this repo's copied `Dockerfile`. It is **deliberately disabled today**: its secrets step is an unconditional `exit 1` until the master key is rotated. **By hand** - `compose-context.sh` against a sibling checkout, then `railway up` - is the path that actually runs | **The by-hand path ships the 503.** `compose-context.sh` re-stages modules only when `modules/MANIFEST` is absent. `modules/` is gitignored, and in the main checkout it holds jars staged on 30 August while `HEAD` is 15 September. Pull the cut-over and the context gets `FROM 13.1.3` with those javax jars; they match their own MANIFEST, so the build passes | The guard (step 0) is what stops it. Then: sibling at `v0.1.4`, and always re-stage - delete `modules/` first, or drop the `if`. Add `ref:` to the workflow for the day it is re-enabled, and move it with `PF_IMAGE` and the install coordinates |
| `pf-agentic-identity-domain-authority` | A sibling checkout; pins no image tag of its own, so it inherits this repo's `FROM`. Built by hand from `REBUILD.md`, which still calls `build-module-jar.sh` - superseded, and hard-coded to `*-0.1.0.jar` filenames | The same stale-`modules/` exposure, pushed to ECR | Sibling at a tag, recorded in `REBUILD.md`; re-stage; point `REBUILD.md` at `stage-modules.sh` |
| `idp-agentic-demo` | **Vendored**: `oidf.war`, `gm-api.war`, the plugin jar and the legacy single `pf-oidf-modules.jar` are committed in its tree, on its own 13.0.3 `Dockerfile`. It does not use the assemble script. It also bakes the PingOne MFA integration kit, a third-party javax-era SDK plugin | Nothing. It is pinned by construction | Already pinned. The hazard is the reverse: bumping its `FROM` without re-vendoring, or re-vendoring without bumping. The guard does not protect this repo |

The stale `modules/` is a problem **today**, independent of this migration: a context composed by
hand from the main checkout right now would carry jars from before the 15 September audit fixes,
and the MANIFEST guard would pass it, because it checks the directory against its manifest and
neither against the build.

Moving a consumer onto `v0.1.4` also brings two changes from 15 September that need configuration:
no federation chain validates without `OIDF_FEDERATION_TRUST_ANCHOR_JWKS`, and the attestation
filter rejects clients whose bridge-keys entry names no attesters. Neither is part of this
migration; both arrive in the same motion for anything still on the 30 August jars.

They do not have to move on the same day. They have to move **as pairs**: a repo's PingFederate tag
and the line of the artifacts it consumes change in one commit, never separately.

---

## The steps

**0. On the javax line, before anything else, in this order.**

- ~~*The namespace guard* (step 5's first half), as its own change.~~ **Done, 2026-09-22.** It reads
  the stock war to learn the namespace, so it is correct on both lines, and it is the only thing that
  stops a stale `modules/` meeting a new `FROM`.
- *Commit and merge the conformance work* - the untracked filter and the 15 modified files.
- *Cut `v0.1.4` from `main`.* Branch `pf-13.0` from it. Record in its `PROVENANCE.txt` that it
  targets PingFederate 13.0.x.
- *Pin the consumers to it*, per the table. Until the tag exists, pin the commit they already
  build, `23ede86`.

**1. The rename.** `javax.servlet` → `jakarta.servlet` in `*.java` under `servlets/`,
`services/gm-api/`, `libs/client-attestation/` and `libs/openid-federation/`, main and test trees
both: 46 files, 182 lines. **Not** `plugins/rar-paz-plugin` - a blind replace there does not
compile, because `getRequest()` still returns the javax type:

```
AttestationAwareRarProcessor.java:[300,64] incompatible types:
  javax.servlet.http.HttpServletRequest cannot be converted to jakarta.servlet.http.HttpServletRequest
```

**2. Coordinates.** In `bom/pom.xml`: `version.pingfederate` → `13.1.3.0`; add
`jakarta.servlet:jakarta.servlet-api:5.0.0` and keep `javax.servlet-api` managed for the plugin
alone; `commons-lang:commons-lang` → `org.apache.commons:commons-lang3`. In six module poms: the
servlet coordinate. In `servlets/pf-integration` and `servlets/attestation-issuer`: the test-scope
`commons-lang` → `commons-lang3`. Without it, both fail - observed, 17 errors and 2 failures + 4
errors respectively, every one
`NoClassDefFoundError: org/apache/commons/lang3/StringUtils`. In
`services/gm-api/servlet/pom.xml`: `pingfederate.version` and the `servlet-api` version, in its own
convention.

**3. The plugin's tests.** Main is untouched. The tests *construct* `AuthorizationDetailContext`,
whose constructor now takes a jakarta request and is itself `forRemoval`. Use the `Builder`:

```java
return new AuthorizationDetailContext.Builder().withRequest(request).withClientId("agent-client").build();
```

One import changes in `ClientAssertedPrincipalTest`, and the pom gains `jakarta.servlet-api` and the
bridge jar at test scope. With that, the plugin's tests run its javax code through Ping's real
bridge: 54 of 54, no deprecation warnings left.

**4. Descriptors, CI, release.** Both `web.xml` files to the `jakartaee` namespace and
`web-app_5_0.xsd`, copied from the stock 13.1.3 war; fix gm-api's comments. In `build.yml` and
`release.yml`: `PF_IMAGE`; the six version strings; and **a second `docker cp`, of
`/opt/server/lib/`**, because the jakarta servlet jar lives there and CI copies only
`server/default/lib` today. The bridge jar is in the directory CI already extracts. The Dockerfile
`FROM` line, and the prose listed above. For 0.2.0, note that the project version appears 35 times
across 19 poms while `release.yml` asserts only the BOM's, so a partial bump tags cleanly and ships
mixed coordinates. `PROVENANCE.txt` now states which PingFederate line the assets target, added when
`v0.1.4` was cut; keep that line honest when the cut-over lands, because it is the fact a consumer
most needs and it will be the thing that changes.

**5. Two guards, so this cannot fail at boot again.**

*In `assemble-pf-runtime-war.sh`* - **done, 2026-09-22.** It reads the stock war's descriptor to
learn which namespace this PingFederate speaks, and refuses any staged jar compiled against the
other. It sits after the jars are staged into the work tree and before they are zipped in, so one
check covers the directory mode, the legacy single-jar mode and a supplied jose4j jar alike.
Exercised over all four module × image combinations in both modes: it passes the two matched pairs
and refuses the two mismatched ones, naming the same five jars the inventory found.

Count with `grep -c`; **do not write this with `grep -q`.** The script runs under `set -o pipefail`.
`grep -q` exits at the first match, `unzip` dies of SIGPIPE, the pipeline reports failure, and a
*match* reads as "no match". My first version of this guard passed all four combinations for exactly
that reason.

The same change made a refusal *delete* the output war. The script's first act is to copy the stock
war to the output path, so until now every check - the MANIFEST checks included - failed with a
plausible `pf-runtime.war` already in place, carrying no modules and no filters. The `EXIT` trap now
reads the exit status and removes it on any non-zero one, so a refusal leaves nothing rather than
something subtly wrong.

*In CI.* After `mvn verify`:

```bash
tools/pf-linkcheck.py --lib pf-lib --lib pf-jetty-lib --reactor .
```

It exits non-zero on any unresolved PingFederate or servlet member, and on any artifact where it
found nothing to check. It would have caught `getIssuerValue`, and it will catch the day
`getRequest()` is finally removed. It cannot see what Jetty will refuse to load; the first guard
covers that.

**6. Boot it.** See [what is not verified](#what-is-not-verified). This is the step that needs a
licence and a person.

**7. Release 0.2.0, then move the consumers** as pairs, per the table above.

**8. Afterwards, separately.** Set `Rfc7523bisCompliantAudienceVerification` to `true`. The
Dockerfile already lays `overlay/config-store/*.xml` over the instance, which is a place it could
live; whether the archive import then overwrites it is not something I checked. Once it is on and
the suite's three `par-test-*-audience-fails` modules pass without help, delete the audience half of
`Fapi2ProfileFilter`. Keep the DPoP-algorithm half: 13.1's new per-client DPoP settings are nonce,
lifetime and replay only. Move the plugin to `getJakartaRequest()` before the release that removes
`getRequest()`; at that point the plugin stops being line-independent. Look at whether
`getUserKey()` retires its resource-owner workaround while there.

*Decided 2026-09-26, in the production plan:*

- **The audience half of `Fapi2ProfileFilter` stays.** The switch is one setting for the whole server,
  so it cannot hold the FAPI 2.0 clients to their issuer while other clients keep the token-endpoint
  audience OpenID Connect Core gives them; and even on, it counts audience values, so a one-element
  array passes. A production PF turns the switch on and keeps the filter; the rig keeps the switch off
  for the SSF suite. The overlay question is answered: an archive import writes the config store, so
  `conformance/config-store/` lays the file over the image and carries it in the archive, and
  `export.sh` refuses an archive without it. Position and evidence:
  [the PingFederate audience switch](../servlets/pf-integration/README.md#the-pingfederate-audience-switch).
- **The plugin reads `getJakartaRequest()` from v0.3.0** (production plan Phase 0), so it no longer
  links on 13.0.
- **`getUserKey()` is production plan item S2b**, the principal resolver: PF fills it from a different
  source per grant type, and a client id must never be taken for a user.

---

## What is verified, and how

| Claim | How |
|---|---|
| The rename compiles and every test passes against 13.1.3 | A scratch copy of the reactor, steps 1-3 applied, `mvn clean verify`. The jars it compiled against match 13.1.3's by sha256. 1193 / 0 / 4, identical per module to a baseline run of the untouched tree on the same machine; 14 jacoco `check` executions, 14 passes, on each side |
| Exactly one PF member fails to link | `tools/pf-linkcheck.py --reactor .` over all 15 shipped artifacts, wars opened. **Control:** against 13.0.3 it reports 0. Against 13.1.3 it reports that one member, once in each of the four artifacts that hold a caller |
| Servlet binaries are per-line; plugin binaries are not | The same tool on the scratch-built artifacts: 0 unresolved on 13.1.3; on 13.0.3, 43 unresolved across the servlet artifacts and **0 for both plugins** |
| The plugin's javax code works through Ping's bridge | By execution, in a unit test: a value stubbed on a *jakarta* mock, handed to the real 13.1.3 context, read back by the plugin's untouched *javax* code. Not inside a running PingFederate |
| `context.HttpRequest` is a jakarta request, never a javax adapter | Traced to the ground. In `pf-protocolengine.jar` 20 classes populate it at 21 sites, every one with a jakarta request in its signature, straight into `AttrValueSupport.make` → `AttrValueSupportServiceImpl`, which has no servlet or bridge reference at all. Four more classes elsewhere read the constant; none touches the bridge. The OGNL evaluator classes are bytecode-identical across versions. It may be one of Ping's own jakarta request wrappers |
| Servlet API parity | `javap` both jars, namespace-normalised `diff`, all 85 classes. **Control:** the same diff between two different types does show a difference |
| The assemble script works unmodified on both lines, and the guard works | All four module × image combinations, through the real script, in directory and single-jar mode. A trial three-way merge against the conformance worktree's uncommitted copy is clean, and the merged script still refuses both mismatches |
| A BOM import ignores `-P` | A two-pom experiment, three invocations, three saved effective poms (below) |
| ee9 maps only `jakarta.servlet.annotation.WebServlet` | The string constant in `jetty-ee9-annotations`' `WebServletAnnotationHandler`; ee8's counterpart holds the javax name |

### Probes and claims that were wrong

A clean result from an unchecked probe is not evidence, and a plausible step is not a checked one.
These were wrong before they were right.

*Caught by my own controls.* The link checker mis-split `extends HashMap<String, V>` on its comma
and reported an inherited method missing - the 13.0.3 control caught it. Two `grep` passes for the
`context.HttpRequest` literal came back empty when a byte-level scan found it. The namespace guard
passed everything, as above.

*Caught by the adversarial reviews.*

- **The first draft told consumers to pin to `v0.1.3`.** I assumed the latest tag was the current
  javax state. It is 19 commits behind, and the gap is security work.
- **It said `pf-oidf-modules`' next deploy would "fail loudly at build".** Its workflow is disabled
  on purpose, the live path is by hand, and that path ships the 503 quietly.
- A `grep` for `@WebServlet` dropped one annotation that wraps a line - so "23 paths" was 26, and
  the collision check had silently skipped three of them. Re-run with a planted control.
- The link checker reported `oidf.war` clean without opening the jars inside it, and passed any
  artifact in which it found nothing to check. Both fixed; both now have a test case.
- The bridge's stub list came from a loose `grep -B12`: I had `getServletContext()` throwing. It
  returns `null`.
- The guard snippet printed in the first draft, abbreviated for the page, no longer matched what had
  been tested - it died on an unset variable under `set -u`. The guard now lives in the script, where
  it is exercised rather than transcribed.
- The draft said CI "already has" the jakarta servlet jar. It does not.
- `attestation-issuer`'s need for `commons-lang3` was inferred; the module had been *skipped* in the
  run I cited. It has now been observed failing without it. My first attempt at that was itself
  contaminated - `-pl` without `-am` pulled a stale `0.1.3` sibling from `~/.m2`.

---

## What is not verified

The list as it stood when the migration landed, with what has been settled since. What is still open
goes to the findings register planned for v0.4.0 (`docs/findings/`, production plan item D-2), as `U-`
entries; this list stays as the record.

- **Nothing here was run on a live 13.1.3.** The 503 and its `is not a jakarta.servlet.Filter`
  message are from the original finding, not reproduced by me. Everything about 13.1.3 in this
  document comes from its jars and files. *Since run: the conformance rig boots 13.1.3 with every
  module (step 6).*
- **What a booted 13.1.3 does with the migrated modules.** Static analysis cannot show: that Jetty
  ee9's annotation scan picks up the 13 `@WebServlet`s from `WEB-INF/lib`; that the three filters run
  in the mapped order; that `HttpServletRequestWrapper` injection in `ClientAttestationAuthFilter`
  still reaches PingFederate's client authentication; that the webapp-to-engine request-attribute
  channel survives; that `SsfAuditLogSource` still finds the audit `LoggerContext`. These are step 6,
  and the conformance rig's suite (49 passed / 0 failed on 13.0.3) is the natural regression test.
  *Partly settled by the 13.1.3 runs: the SSF and federation servlets serve, so the annotation scan
  maps them, and the FAPI 2.0 plan passes through `Fapi2ProfileFilter`. Not exercised there: the
  attestation filter's wrapped request and the webapp-to-engine channel (the rig runs attestation
  inert), and `SsfAuditLogSource`.*
- **The symptom of a javax `@WebServlet` on ee9.** The handler's key is verified; the consequence is
  inference: with no handler, the servlet should simply never be mapped - a 404, not an error. If so,
  the 503 was the *loud* half of the failure, produced by the filters because `web.xml` names them,
  and a partly-migrated build would lose servlets quietly. The guard covers every staged jar for
  that reason.
- **Whether a throwing OGNL criterion denies or permits.** On 13.1.3 the un-migrated
  `ClientAttestationUtils` throws `ClassCastException` on its first line. `idp-agentic-demo` runs
  that criterion as its only gate on the token endpoint. Find out which way it fails before anyone
  bumps that repo's `FROM` line - and do not bump it without re-vendoring.
- **The demo's PingOne MFA integration kit on 13.1.** It is an SDK plugin, so it should ride the
  same bridged seam as this repo's plugin. Not tested.
- **Rollback.** A 13.0.3 archive imports into 13.1.3 (observed in the original finding). The reverse
  is untested, and the tracked overlay sets `ForceUnsupportedImport=true`, so a 13.0.3 image would
  at least *attempt* to import a 13.1.3 archive. Keep the last 13.0.3-exported archive per
  environment as the rollback artifact, and do not re-export over it.
- **`RegistrationService` against 13.1's client model.** Its tests pass against the real 13.1.3
  `Client` class. They do not exercise persistence through PingFederate's client manager, and 13.1
  adds a multi-auth model (`isUseClientAuthenticationModel`, `getClientAuthenticationTypes`) beside
  the single `setClientAuthnType` this repo calls.
- **The four skipped tests** are the Testcontainers ones that do not run on this machine. They are
  skipped identically on both sides; CI runs them.
- **`age` on Alpine 3.24.** The community repository is enabled in the image. I did not run `apk`.
  *Settled 2026-09-26: an image built from this repo's Dockerfile on 13.1.3 (alpine 3.24.1) has `age`
  1.3.1.*
- **The image digests** are what `docker image inspect` printed for the local copies. *From v0.3.0 the
  13.1.3 image is pinned by digest in `build/pf-version.env`.*

---

## Reproducing the evidence

The commands work in both bash and zsh. They exclude `worktrees` because the main checkout nests
other worktrees under `.claude/`; without that the inventory counts every one of them as well, and
the totals come out several times too high.

Extraction - containers are created, never started:

```bash
for v in 130:13.0.3-alpine_3.23.4-al21-latest 131:13.1.3-alpine_3.24.1-al21-latest; do
  k="${v%%:*}"; id=$(docker create "pingidentity/pingfederate:${v#*:}")
  docker export "$id" | tar -tvf - > "pf$k-filelist.txt"
  docker cp "$id:/opt/server" "pf$k"; docker cp "$id:/opt/staging" "pf$k-staging"; docker rm "$id"
done
```

Inventory:

```bash
X=(--include='*.java' --exclude-dir=target --exclude-dir=worktrees)
grep -rE  'javax\.servlet' "${X[@]}" . | wc -l                                  # 184 lines
grep -rlE 'javax\.servlet' "${X[@]}" . | wc -l                                  # 48 files
grep -rnE 'javax\.servlet' "${X[@]}" . \
  | grep -vE ':[0-9]+:import (static )?javax\.servlet[a-zA-Z.]*;'                # the one non-import line
grep -rhoE 'javax\.servlet(\.[A-Za-z]+)+' "${X[@]}" . | sort | uniq -c          # 14 types, plus one `.class` literal
grep -rE 'javax\.net\.ssl' "${X[@]}" . | wc -l; grep -rE 'javax\.sql' "${X[@]}" . | wc -l    # 20, 23
find . \( -path '*/target/classes/*' -o -path '*/target/test-classes/*' \) -name '*.class' \
  -not -path '*/worktrees/*' -print0 \
  | xargs -0 cat | LC_ALL=C grep -aoE 'javax/servlet/[A-Za-z/]+' | sort -u       # the 16 types actually linked
```

API comparison, for each PingFederate class this repo imports:

```bash
pfcp() { find "$1/server/default/lib" "$1/lib" -name '*.jar' | tr '\n' ':'; }
javap -protected -cp "$(pfcp pf130)" org.sourceid.oauth20.issuer.OAuthIssuerUtils > a
javap -protected -cp "$(pfcp pf131)" org.sourceid.oauth20.issuer.OAuthIssuerUtils > b; diff a b
javap -v -p -cp "$(pfcp pf131)" com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext \
  | grep -A12 'getRequest();'                                                     # the forRemoval marker
javap -c -p -cp "$(pfcp pf131)" com.pingidentity.commons.jakarta.bridge.ee8.JavaxHttpServletRequestAdapter
```

Linkage, control first:

```bash
mvn -q -DskipTests package
tools/pf-linkcheck.py --pf pf130 --reactor .      # must print: TOTAL unresolved: 0
tools/pf-linkcheck.py --pf pf131 --reactor .      # the one member, in 4 artifacts; exits 1
```

The scratch build - in a copy, with a scratch Maven repository whose reads fall through to `~/.m2`
and whose writes do not (`sed -i ''` is the macOS form):

```bash
rsync -a --exclude target/ --exclude .git --exclude .claude/ ./ /tmp/spike/ && cd /tmp/spike
grep -rlE 'javax\.servlet' --include='*.java' . | grep -v plugins/rar-paz-plugin \
  | xargs sed -i '' 's/javax\.servlet/jakarta.servlet/g'                          # 46 files
# then steps 2 and 3, and five install:install-file calls from pf131 - protocol engine, the SDK
# under both groupIds, the jakarta servlet jar, the bridge - with:
M=(-Dmaven.repo.local=/tmp/spike-m2 -Dmaven.repo.local.tail="$HOME/.m2/repository")
mvn "${M[@]}" clean verify
```

Run a single module there with `-pl <module> -am`. Without `-am`, Maven takes sibling modules from
`~/.m2`, where an older build may be installed under the same `0.1.3`.

The BOM experiment. A BOM whose managed servlet coordinate is a set of properties, overridden by one
profile activated by id and one activated by property; a consumer that imports it and has a profile
of the same id:

```xml
<!-- bom/pom.xml, inside <project> -->
<properties><servlet.g>javax.servlet</servlet.g><servlet.a>javax.servlet-api</servlet.a><servlet.v>4.0.0</servlet.v></properties>
<dependencyManagement><dependencies>
  <dependency><groupId>${servlet.g}</groupId><artifactId>${servlet.a}</artifactId><version>${servlet.v}</version></dependency>
</dependencies></dependencyManagement>
<profiles>
  <profile><id>pf131</id><properties><!-- the three jakarta values --></properties></profile>
  <profile><id>by-property</id><activation><property><name>pf.line</name><value>13.1</value></property></activation>
    <properties><!-- the same three --></properties></profile>
</profiles>
```

| `mvn help:effective-pom …` | BOM-managed servlet dependency | consumer's own `pf131` profile |
|---|---|---|
| (no flags) | `javax.servlet:javax.servlet-api:4.0.0` | inactive |
| `-Ppf131` | `javax.servlet:javax.servlet-api:4.0.0` | **active** |
| `-Dpf.line=13.1` | `jakarta.servlet:jakarta.servlet-api:5.0.0` | inactive |
