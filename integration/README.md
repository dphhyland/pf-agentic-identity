# PingFederate integration

Everything needed to run `pf-rar-paz-plugin` in a PingFederate deployment. Three moving
parts: **the jar** (build + drop into PF), **the JVM flag** (TLS), and **the config** (a
processor instance + per-client enablement). Optionally the branded **consent template**.

## 1. Build & bake the jar

```bash
mvn -q package                       # → target/pf.plugins.pf-rar-paz-plugin.jar
```

The jar is a self-contained uber-jar: PF SDK is `provided`, Jackson is **shaded + relocated**
into `com.pingidentity.ps.oidf.rar.shaded.jackson`, and it carries
`PF-INF/authorization-detail-processors` (the plugin marker). This matters — PF isolates
each deploy-dir jar on its own classloader, so a plugin that referenced a bare Jackson jar
would fail to link. See [`../pom.xml`](../pom.xml) shade config.

Copy it into your PF image with [`Dockerfile.fragment`](./Dockerfile.fragment). That fragment
also handles:

- the **consent template** (optional) — [`consent-template/oauth.approval.page.template.html`](./consent-template/oauth.approval.page.template.html);
- the **TLS hostname JVM flag** (`-Djdk.internal.httpclient.disableHostnameVerification=true`),
  required when the PDP is reached on a hostname outside its cert SAN. It must be sed'd into
  `run.sh`, not set via `ENV JAVA_OPTS` (Ping's entrypoint clears that).

## 2. SDK prerequisite (build blocker)

The PF SDK (`pingfederate/pf-protocolengine`, `com.pingidentity.pingfederate/pingfederate-sdk`,
version `13.0.0.3` by default) is **not on Maven Central**. Resolve it into `~/.m2` from a PF
install:

```bash
# from a PingFederate <PF_HOME>:
mvn install:install-file -Dfile=<PF_HOME>/server/default/lib/pf-protocolengine.jar \
  -DgroupId=pingfederate -DartifactId=pf-protocolengine -Dversion=13.0.0.3 -Dpackaging=jar
mvn install:install-file -Dfile=<PF_HOME>/sdk/lib/pf-sdk.jar \
  -DgroupId=com.pingidentity.pingfederate -DartifactId=pingfederate-sdk -Dversion=13.0.0.3 -Dpackaging=jar
```

Match `<version.server-sdk>` in the pom to your PF version.

## 3. Configure PingFederate

The processor **instance** + per-client enablement are the only runtime config. Two ways:

**a. config-as-code (recommended, reusable)** — [`config-as-code/`](./config-as-code/):

```bash
export ADMIN=https://localhost:9999 PF_USER=administrator PF_PASS=…
# create the "Attestation-aware RAR to PingAuthorize" instance:
PDP_URL=https://<pingauthorize-host>:1443/governance-engine PDP_SECRET=… \
  config-as-code/create-processor-instance.sh
# enable RAR on the client that initiates payments:
CLIENT_ID=<your-webapp-client> RAR_TYPES='["payment_initiation"]' \
  config-as-code/enable-on-client.sh
```

The instance's config fields are exactly the plugin's GUI descriptor fields (PDP URL,
domain/attribute prefixes, shared-secret header/value, deny-unless-PERMIT, fail-open,
insecure-TLS, timeout). The RAR **types** are declared by the plugin in code
(`SUPPORTED_TYPES`), so you only enable them per client.

**b. config archive** — if you manage PF config as a baked `data.zip` (imported via
`/pf-admin-api/v1/configArchive/import`), configure the instance once in the admin console,
then export + bake the archive. Survives volumeless redeploys.

## 4. The PDP side (PingAuthorize)

The plugin POSTs each `authorization_details` entry to a PingAuthorize **governance-engine**
decision (native JSON API). The Trust Framework + policy that make that decision (PERMIT
payment_initiation, DENY over-limit, `requested ⊆ attested` containment) are authored in
[`../paz/`](../paz/) via the PAP REST API. Wire contract is in the [top-level README](../README.md).

## 5. Deploy gotchas (Railway, learned the hard way)

If you deploy the PF image with the Railway CLI:

```bash
railway up <pf-image-dir> --path-as-root --service <svc> --no-gitignore --detach
```

- **`--path-as-root`**: `railway up` archives from the git root by default, so a Dockerfile
  in a subdir isn't found → Railway falls back to Railpack → `could not determine how to
  build`. `--path-as-root` makes the image dir the archive root.
- **`--no-gitignore`**: includes gitignored secrets the Dockerfile COPYs (PF master key,
  license), else the COPY fails the build.
