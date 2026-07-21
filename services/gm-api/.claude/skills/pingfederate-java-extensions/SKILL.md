---
name: pingfederate-java-extensions
description: >-
  Build, deploy, and debug PingFederate Java extensions — SDK plugins
  (AuthorizationDetailProcessor, IdP adapters, PCVs, token processors) and REST servlets
  deployed as WARs. Covers the SDK-jar-from-container build, PF-INF plugin discovery,
  classloader isolation, in-process SDK accessors, and the traps that fail silently.
  Fires when adding Java to PingFederate: a plugin, a servlet/WAR, a /gm-api or custom
  endpoint, "PF-INF", "AccessGrantManagerAccessor", "JwksEndpointKeyAccessor", or a
  PingFederate context that deploys but does not serve.
---

# PingFederate Java extensions (SDK plugins + servlets)

Two kinds of Java go into `server/default/deploy`, and both are here because the plugin
SDK has **no extension point for adding a REST endpoint**:

- **SDK plugins** — implement an interface (`AuthorizationDetailProcessor`,
  `IdpAuthnAdapter`, `PasswordCredentialValidator`, …). Extend a point *within* PF's flows.
- **Servlets (WARs)** — `PFWebAppProvider` deploys any WAR from `server/default/deploy` and
  makes the **WAR name the context path** (`gm-api.war` → `/gm-api`). This is how PF's own
  `pf-ws.war` serves `/pf-ws/...`. It is the only way to add a REST surface.

What a servlet buys over a sidecar: **in-process SDK accessors**, no network hop, no
service account, no TLS trust, no JWKS fetch. See "In-process accessors" below.

## The build (both kinds)

The SDK is Ping-licensed, not on Maven Central. Copy jars **out of the running container**;
gitignore `lib/*.jar`.

```bash
PF=<container>
for j in pingfederate-sdk jose4j commons-logging commons-lang3 \
         jackson-core jackson-databind jackson-annotations; do
  src=$(docker exec $PF sh -c "find /opt/out/instance/server/default/lib /opt/out/instance/lib -iname '${j}*.jar' | head -1")
  docker cp "$PF:$src" lib/
done
docker cp $PF:/opt/out/instance/lib/jetty-servlet-api-4.0.9.jar lib/   # servlets only
chmod u+w lib/*.jar
```

**Install under LOCAL coordinates with a generated POM.** The real jars carry POMs that
reference parents which do not resolve offline — installing them verbatim breaks the build:

```bash
mvn install:install-file -Dfile=lib/pingfederate-sdk.jar \
  -DgroupId=local.pingfederate -DartifactId=pingfederate-sdk -Dversion=13.0.3 \
  -Dpackaging=jar -DgeneratePom=true
# repeat per jar (servlet-api, jose4j, commons-*, jackson-*)
```

Everything is `<scope>provided</scope>`. **Bundle nothing.**

### Which runtime deps the SDK drags in

You do not find these from the compiler — you find them from `NoClassDefFoundError` at
first test/run, one at a time. Constructing a `PluginDescriptor` alone needs
commons-logging → commons-lang3 → jackson-core/databind. Pull them all up front.

### Classloader isolation — the shade decision

**PF gives each deploy-dir artifact its own classloader.** A jar that references a bare
Jackson would fail to link, and a second copy of a PF class is *not* the same class. So:
- Anything PF provides (SDK, jackson, commons-*, jose4j) → `provided`, never bundled.
- Anything PF does *not* provide that you need → **shade + relocate** it (as pf-rar-paz-plugin
  shades Jackson into its own package). For a servlet using only PF-provided libs, bundle
  nothing and the WAR is tiny.

## Plugin discovery: `PF-INF/<type>` — fails SILENTLY

**A plugin jar is invisible without a `PF-INF/<plugin-type>` file** listing the FQCN, one
per line. It is PF's convention, NOT `META-INF/services`. Without it: no error, no warning,
nothing in the log at any level — the plugin just never appears in `/descriptors`. A
correct class (right interface, public no-arg ctor, right bytecode) tells you nothing.

```
src/main/resources/PF-INF/authorization-detail-processors   # one FQCN per line
```

Find the type name (it is a string constant, not documented) in the manager class:

```bash
docker exec $PF sh -c 'cd /tmp && unzip -o -q \
  /opt/out/instance/server/default/lib/pf-protocolengine.jar "org/sourceid/**/*PluginManagerImpl*" \
  && strings org/sourceid/saml20/domain/mgmt/impl/<Type>PluginManagerImpl.class | grep -B2 -A2 PF-INF'
```

To watch discovery, set `DEBUG` on `org.sourceid.saml20.domain.mgmt.impl.PluginManagementSupport`
in `server/default/conf/log4j2.xml` — it logs `Configuring plugins (PF-INF/<type>)` per type.
(Servlets do NOT use PF-INF; they are declared in `web.xml`.)

Known types: `idp-authn-adapters`, `sp-authn-adapters`, `token-processors`,
`token-generators`, `password-credential-validators`, `oob-auth-plugins`,
`captcha-providers`, `notification-sender`, `bearer-access-token-management-plugins`,
`authentication-selectors`, `custom-drivers`, `authorization-detail-processors`.

## In-process accessors (servlets)

`com.pingidentity.access.*` is a servlet's way into PF without leaving the JVM:

- `AccessGrantManagerAccessor.getAccessGrantManager()` → grants: `getByGuid(id)`,
  `getByUserKey`, `revokeGrant`, `getGrantAttributes`. `AccessGrant.getAuthorizationDetails()`
  is **typed** RAR — no JSON-in-a-string to unpick like the REST API forces.
- `JwksEndpointKeyAccessor.newInstance().getSigningJsonWebKeySet()` → PF's own signing keys.
  Verify inbound tokens against these with jose4j: no JWKS URL, no TLS trust, no issuer
  config (a token this server signed came from this server). **Do** still check `aud` — one
  server mints for many audiences.
- `ClientAccessor`, `BaseUrlAccessor`, `KeyAccessor`, `SecretManagerAccessor`, others.

**Caveat: PF SDK domain objects are NOT value objects.** Constructing an `AccessGrant`
reaches into the server's service locator and throws `No Impl found for AccessGrantService`
outside a running PF. So anything touching one is untestable off-server. Isolate the PF
types behind a plain record (`GrantView.from(accessGrant)`) and keep the decision logic on
the record, so it unit-tests without PF.

## Traps that waste an afternoon

- **`--` (double hyphen) is illegal inside an XML comment.** A `web.xml` with one fails to
  parse; Jetty logs `Unable to parse .../web.xml`, marks the context `a=UNAVAILABLE`, and the
  endpoint 404s — looking exactly like a bad deploy. (Cost me this twice.) Check
  `a=AVAILABLE` in the startup log.
- **`getPathInfo()` has the context AND servlet path stripped.** Mapped at `/grants/*`, a
  request to `/gm-api/grants/{id}/evaluate` yields pathInfo `/{id}/evaluate` — not the full
  path. Getting this wrong 404s every well-formed request.
- **Match the container's servlet spec.** PF 13's WARs declare Servlet 3.1 with the
  `javax.servlet` namespace (jetty-servlet-api 4.0.9), not jakarta. Copy the version from
  `pf-ws.war`'s own `web.xml`.
- **Compile to the container's bytecode or lower.** `maven.compiler.release` ≤ the
  container JDK (PF 13.0.3 runs Java 21; release 17 is safe).

## Deploy loop

```bash
mvn -o package                     # -> target/<name>.{jar,war}
docker cp target/<name>.jar $PF:/opt/out/instance/server/default/deploy/
docker restart $PF                 # deploy-dir scan is at boot
# wait healthy, then confirm:
#   plugin: GET /pf-admin-api/v1/oauth/authorizationDetailProcessors/descriptors
#   servlet: grep 'a=AVAILABLE' the startup log; hit the endpoint
```

The jar/war in the *image* wins on restart if the container rebuilds `/opt/out/instance`
from a baked layer — for a persistent demo, `docker cp` after each restart or bake it in.

## Reference

- SDK javadoc surface (inspect live): `javap -cp pingfederate-sdk.jar <fqcn>`.
- Worked examples in this repo: `servlet/` (GrantsServlet, McpServlet, GrantView,
  PfTokenVerifier), and pf-rar-paz-plugin for a processor plugin with Jackson shading.
- Config side (clients, ATMs, mappings, RAR types via admin API): the
  pingfederate-config-as-code skill.