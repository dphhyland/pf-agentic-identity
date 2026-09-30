# war-assembler

Builds `pf-runtime.war` for the PingFederate image: the stock war from the base image, the module jars
`stage-modules.sh` staged, and the filters [`build/pingfederate/filters.xml`](../pingfederate/filters.xml)
declares, registered over PingFederate's own endpoints in the war's `WEB-INF/web.xml`. It is a build tool, not a
module PingFederate loads: JDK only (`java.xml` for the DOM, `java.util.zip` for the war), compiled for 17 and run
by the image's own Java 21. Plan item R-I5.

[`build/pingfederate/assemble-pf-runtime-war.sh`](../pingfederate/assemble-pf-runtime-war.sh) is its command line
and keeps the one it always had:

```sh
build/pingfederate/assemble-pf-runtime-war.sh STOCK_WAR MODULES JOSE4J_JAR OUT_WAR [PROFILE]
# which runs
java -jar assembler/war-assembler.jar --filters filters.xml STOCK_WAR MODULES JOSE4J_JAR OUT_WAR [PROFILE]
```

Exit 0 with `OUT_WAR` written; 2 for a usage error, with nothing touched (`STOCK_WAR` and `OUT_WAR` the same file
is one); 1 for a refusal, and then `OUT_WAR` does not exist, whether or not it did before. The wrapper removes it
too when the JVM itself fails - a Java older than 17, or an `Error` - and the assembler removes it in a `finally`. The war is written to a temporary file beside `OUT_WAR`, read back
and checked there, and moved into place only when every check passed, with the stock war's permissions less
group and other write (0640 in the image, as the shell script's `cp` left it).

## What it refuses

In the order it checks:

| Check | Refused when |
|---|---|
| The declaration | `filters.xml` has an element, attribute value or url-pattern it does not know, a name twice, or an order rule naming an undeclared filter or giving no reason |
| `MANIFEST` v2 | `MODULES` is a directory and its `MANIFEST` is missing or not v2, was staged for the other profile, names a jar that is missing or has another digest, or misses a jar that is there. The shell script's check, moved here unchanged, with its messages |
| The descriptor | the stock war has no `WEB-INF/web.xml`, or it has a DOCTYPE, is not well-formed, is not a `<web-app>`, or its root is prefixed (`<j:web-app>`), so that unprefixed elements inserted into it would fall outside its namespace. Elements in another namespace are not counted as the descriptor's |
| The namespace guard | the descriptor's namespace is neither Jakarta EE's (13.1.x) nor Java EE's (13.0.x), or a staged jar's class files reference the other one's `servlet` package |
| `metadata-complete` | the root says `true` (or `1`): the container would scan no annotation, and the modules' `@WebServlet` servlets would never be mapped |
| Mapped paths | a declared path is one no `<servlet-mapping>` in the stock descriptor serves - the default servlet (`/`) does not count - and no `<path-exception>` says why that is right. See [what the mapped-path check cannot see](#what-the-mapped-path-check-cannot-see) |
| Existing registrations | the stock descriptor already has a declared name, but not exactly as declared (another class, other paths, a second mapping, a servlet-name or dispatcher) |
| Classes | a declared filter's or listener's class is in no jar the war will hold: PingFederate would fail the whole war at boot |
| The result, read back | a declared name without exactly one `<filter>` and one `<filter-mapping>` with exactly its url-patterns; an `<order>` pair not holding in document order; a declared listener not registered exactly once |

It then prints each declared path's effective filter chain: the servlet that serves it, and every filter that
runs, PingFederate's own included, in the order the Servlet specification gives - url-pattern mappings in
document order, then servlet-name mappings. Only what `web.xml` declares is shown; a filter a jar registers by
annotation is not in it.

## What the mapped-path check cannot see

PingFederate 13.1.3's stock `web.xml` maps its protocol endpoints by extension (`*.oauth2`, `*.openid`, `*.ciba`),
not by name, and every path `filters.xml` declares today is served that way. So for those paths the check proves
only that the extension is still PingFederate's: a misspelt or moved endpoint with the same extension
(`/as/introspekt.oauth2`) passes it, and its filter would silently never run. The check catches a changed
extension and a path under no mapping at all. The assembler says which paths this applies to, on a line beginning
`web.xml: served only by a wildcard <servlet-mapping>`, and U-0186 records the gap: only a request to each
endpoint on a booted PingFederate (the conformance rig), or the endpoint inventory plan item D-3 builds, can tell a
real endpoint from a misspelt one.

## How it edits `web.xml`

The DOM decides and the text is edited in one place. Every check reads the parsed descriptor, but the merged file
is the stock file's own bytes with the new elements inserted before `</web-app>`, in the order `filters.xml`
lists them and in the layout the shell script used. PingFederate's descriptor is not re-serialised, so its
comments, attribute order and whitespace stay as they were. A descriptor that already registers every declared
name exactly as declared is written back unchanged, which is why the assembler run on its own output writes the
same war byte for byte.

## `filters.xml`

```xml
<war-filters version="1">
  <filter name="OidfAutoRegistration" class="com.pingidentity.ps.oidf.servlet.clientregistration.TokenEndpointAutoRegistrationFilter">
    <url-pattern>/as/token.oauth2</url-pattern>
  </filter>
  <order filter="OidfAutoRegistration" before="ClientAttestationAuth">why, printed when it does not hold</order>
  <path-exception path="/some/path" reason="why no servlet mapping in the stock web.xml serves it"/>
  <listener class="a.b.SomeListener"/>
</war-filters>
```

It declares the seven filters the shell script registered, in the same order, and its three order checks as four
pairs (the last check was two). Their paths are the shell script's but one: plan item S4d (2026-09-30) mapped
`ClientAttestationAuth` over every endpoint that authenticates a client and the authorization endpoint, and added two
pairs - `Fapi2Profile` and `OidfFrontChannelAutoRegistration` before it. It also declares one listener, plan item F-2's
`LifecycleListener` from platform-pf, which the assembler registers after the filters and checks is there once.

## How it reaches the image, and a consumer

The reactor builds `target/war-assembler-<version>.jar`, and `stage-modules.sh` copies it to
`assembler/war-assembler.jar` beside the `modules/` it stages (so `STAGE_DEST` moves both). The Dockerfile copies
the script, `filters.xml` and that jar into the image and runs the script, so `docker build build/pingfederate`
needs nothing outside its context. `conformance/compose-context.sh` copies `filters.xml` and `assembler/` too.

A jar rather than the single-file source launcher (`java WarAssembler.java`): the jar is the bytes the tests and
the coverage gate ran against, it needs no compiler at image build, and on 17 the launcher takes one source file,
which would put the whole assembler in one class. The `MANIFEST` and profile checks moved into it rather than
staying in the wrapper so that every refusal is in one tested place, and the wrapper has no `grep` left to be
wrong under `pipefail`.

A consumer that composes its own context (pf-oidf-modules does, from a sibling checkout) runs `mvn package` and
`stage-modules.sh` as before, and copies `filters.xml` and `assembler/` beside the script. Without them `docker
build` stops at the `COPY` with `"/assembler/war-assembler.jar": not found`; a caller that runs the script outside
Docker also needs Java 17 or later (`JAVA_HOME` or the `PATH`), and without the jar or Java the script refuses
with exit 1 and no output war. `WAR_ASSEMBLER_JAR` and `WAR_FILTERS_XML` point it elsewhere.

## Verified

2026-09-28, against 13.1.3's stock war (the image `build/pf-version.env` pins by digest):

- the shell script (as of `276bcd6`) and this assembler wrote the same `WEB-INF/web.xml`, byte for byte (sha256
  `b0674250…`), for the production and the conformance stage, and wars with the same entries and sizes;
  `StockWarGoldenTest` checks it when given the stock war, on JDK 17 and 20 here;
- assembling the output again wrote the same war byte for byte;
- `docker build` of the production image and, through `compose-context.sh`, the conformance image ran the
  assembler on the image's Java 21: the same seven filters in the same order, the descriptor's sha256 the same as
  the shell script's, 11 and 12 jars in the war and in `server/default/deploy`, the war `0640` and owned by
  PingFederate's user; a production stage built as conformance was refused, and a context without `assembler/`
  stopped at the `COPY`.

The tests use descriptors written for them in the stock one's shape, never a copy of Ping's file; the golden
result is recorded as its digest and the block of our own text the shell script inserted
(`src/test/resources/golden/shell-assembler-additions.txt`); the comparisons put `ClientAttestationAuth`'s wider mapping
in place of the shell's two patterns and take F-2's listener out, and compare the rest.
