# PingFederate integration

Everything needed to run `pf-rar-paz-plugin` in a PingFederate deployment. Three moving parts: **the
jar** (build + drop into PF), **the JVM flag** (TLS to an internal PDP), and **the config** (a processor
instance + per-client enablement). Optionally the branded **consent template**.

Note: the monorepo's own `deploy/pingfederate/` image is the OIDF-only AS and deliberately does not
include this plugin. Baking it is your image's job — that is what the fragment below is for.

## 1. Build and bake the jar

```bash
# from the repo root
mvn -pl plugins/rar-paz-plugin -am package       # → plugins/rar-paz-plugin/target/pf.plugins.pf-rar-paz-plugin.jar
```

The jar is a self-contained uber-jar: the PF SDK is `provided`, jackson is **shaded and relocated** into
`com.pingidentity.ps.oidf.rar.shaded.jackson`, and it carries `PF-INF/authorization-detail-processors`
(the plugin marker — a `META-INF/services` entry does not work). This matters: PF isolates each
deploy-dir jar on its own classloader, so a plugin that referenced a bare jackson jar would fail to
link. See the shade config in [`../pom.xml`](../pom.xml).

Copy it into your PF image with [`Dockerfile.fragment`](./Dockerfile.fragment). That fragment also
handles:

- the **consent template** (optional) —
  [`consent-template/oauth.approval.page.template.html`](./consent-template/oauth.approval.page.template.html),
  self-contained (inline CSS, native submit buttons) so it renders even when PF's runtime base URL is
  internal and its default assets cannot load; renders the `authorization_details` as the hero;
- the **TLS hostname JVM flag** (`-Djdk.internal.httpclient.disableHostnameVerification=true`), needed
  only when the PDP is reached on a hostname outside its certificate SAN. The JDK HttpClient enforces a
  TLS-1.3 in-handshake hostname check that a trust-all `SSLContext` cannot disable. It must be `sed`'d
  into `run.sh` after PF's own `--add-opens` line, not set via `ENV JAVA_OPTS` (Ping's entrypoint
  clears that).

## 2. SDK prerequisite (build blocker)

The PF SDK jars (`pingfederate:pf-protocolengine`, `com.pingidentity.pingfederate:pingfederate-sdk`,
`13.0.0.3` per the repo BOM's `version.pingfederate`) are not on Maven Central. CI extracts them from
the public `pingidentity/pingfederate` image and `install:install-file`s them — copy those lines from
`.github/workflows/build.yml`, or from a PF install:

```bash
mvn install:install-file -Dfile=<PF_HOME>/server/default/lib/pf-protocolengine.jar \
  -DgroupId=pingfederate -DartifactId=pf-protocolengine -Dversion=13.0.0.3 -Dpackaging=jar
mvn install:install-file -Dfile=<PF_HOME>/sdk/lib/pf-sdk.jar \
  -DgroupId=com.pingidentity.pingfederate -DartifactId=pingfederate-sdk -Dversion=13.0.0.3 -Dpackaging=jar
```

A different PF version means bumping `version.pingfederate` in `bom/pom.xml`, not this pom.

## 3. Configure PingFederate

The processor **instance** + per-client enablement are the only runtime config. Two ways:

**a. config-as-code (recommended)** — [`config-as-code/`](./config-as-code/), against the admin API of a
running PF:

```bash
export ADMIN=https://localhost:9999 PF_USER=administrator PF_PASS=…
# create the "Attestation-aware RAR to PingAuthorize" instance:
PDP_URL=https://<pingauthorize-host>:1443/governance-engine PDP_SECRET=… \
  config-as-code/create-processor-instance.sh
# enable RAR on the client that initiates payments (GET-merge-PUT; also forces the approval page):
CLIENT_ID=<your-webapp-client> RAR_TYPES='["payment_initiation"]' \
  config-as-code/enable-on-client.sh
```

The instance's fields are exactly the plugin's GUI descriptor fields (see the table in the
[top-level README](../README.md)). `create-processor-instance.sh` leaves **PDP Dialect** at its
`governance-engine` default — add `{"name":"PDP Dialect","value":"authzen"}` and point `PDP_URL` at
`/access/v1/evaluation` for an AuthZEN PDP. The RAR **types** are declared by the plugin in code
(`SUPPORTED_TYPES`), so you only enable them per client. Admin-API paths and client field names vary
by PF version — check `$ADMIN/pf-admin-api/api-docs` on a 404.

**b. config archive** — if you manage PF as a baked `data.zip`, configure the instance once in the
console, then export + bake. Survives volumeless redeploys.

## 4. The PDP side

Governance-engine dialect: the Trust Framework + policy (PERMIT within the attested entitlement, DENY
beyond it) are authored in [`../paz/`](../paz/) via the PAP REST API — read its README first, the
compose there is author-local. Confirm the wire + shared secret with
[`../probe-decision.sh`](../probe-decision.sh). AuthZEN dialect: any AuthZEN 1.0 PDP.

## 5. Railway deploy gotchas (learned the hard way)

```bash
railway up <pf-image-dir> --path-as-root --service <svc> --no-gitignore --detach
```

- `--path-as-root`: `railway up` archives from the git root by default, so a Dockerfile in a subdir is
  not found and Railway falls back to Railpack (`could not determine how to build`).
- `--no-gitignore`: includes gitignored secrets the Dockerfile COPYs (PF master key, licence), else the
  COPY fails the build.
