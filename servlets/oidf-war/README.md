# oidf-war

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Added 2026-07-24 when the war assembly moved out of `pf-integration`; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

Assembles **`oidf.war`** - the loose-war packaging of the OIDF servlet modules for PingFederate. No Java
of its own: a `web.xml`, an assembly descriptor, and dependencies on `pf-integration` +
`attestation-issuer`. `finalName` is `oidf`, so PF's drop-in deployer serves it at the `/oidf` context.

## Why a separate module

`attestation-issuer` depends on `pf-integration` (client store, `FederationWalletProviderKeyResolver`,
`PfJwksSigningKeyProvider`). If `pf-integration` also built the war it would have to depend on
`attestation-issuer` - a reactor cycle. So `pf-integration` produces only `oidf.jar`, and this
aggregation module sits downstream of every servlet module and packs them together. It exists because
before it did, `/federation/attestation` was in no built war at all (commit `1ac888b`).

## What goes in

`src/assembly/war.xml` copies every runtime-scope dependency into `WEB-INF/lib`. The current war carries:

| Jar | Brings |
|---|---|
| `pf-integration-0.1.0.jar` | federation entity servlet, §12 registration, OGNL hooks, the token-endpoint filters (note: the artifact name, not `oidf.jar`) |
| `attestation-issuer-0.1.0.jar` | `/federation/attestation`, attester discovery, CAS metadata |
| `client-attestation-0.1.0.jar` | the verifier - and `ClientAttestationChallengeServlet` (`/federation/attestation-challenge`), which rides along from the lib |
| `openid-federation`, `oidf-jose`, `agent-registry` | trust-chain validation, JOSE, `agent_id` minting |
| `jackson-core/databind/annotations` | bundled - `jackson-databind` is a direct dependency of this pom, deliberately not excluded |

**Not** in the war: `ssf` (it is not a dependency here - it ships only via the `pf-runtime.war` merge, see
below), the PF SDK jars and servlet API (`provided`), `slf4j-api`, `commons-logging`, and **`jose4j`**.

`WEB-INF/web.xml` is `metadata-complete="false"` and otherwise empty: PF's Jetty scans the jars for
`@WebServlet` annotations, so adding an endpoint is adding an annotated class to a module - the war
does not change.

## The jose4j exclusion

Every deployment that runs this war also has `jose4j-0.9.6.jar` on PF's server classpath. Bundling a
second copy in `WEB-INF/lib` produced `LinkageError: loader constraint violation` on
`org.jose4j.jwk.JsonWebKey` the moment a servlet passed a jose4j type across the war's classloader
boundary (found via `OpenIdFederationServlet`; the old static-mock-attester path never crossed it). Two
classloaders defining the "same" class are not the same class to the JVM. Marking `jose4j` `provided`
on this pom is not enough - it is a compile-scope transitive of every module - so the assembly
descriptor excludes `org.bitbucket.b_c:jose4j` explicitly. `commons-logging` and `slf4j-api` are
excluded alongside it as container-provided logging.

## Which war reaches production

Two packagings of the same jars exist; this module is one of them.

- **`oidf.war`** (this module) - own webapp classloader, `/oidf` context. Built by `mvn package` and
  uploaded as a CI artifact (`.github/workflows/build.yml`).
- **`pf-runtime.war` merge** - what `deploy/pingfederate/` actually ships. `build/stage-modules.sh`
  stages seven reactor jars (`oidf.jar`, `attestation-issuer`, `ssf`, `oidf-jose`, `client-attestation`,
  `openid-federation`, `agent-registry`) into `deploy/pingfederate/modules/`; the Dockerfile runs
  `build/assemble-pf-runtime-war.sh` to inject them into the stock `pf-runtime.war` (root context, no
  `/oidf` prefix, one classloader) and register the three filters over PF's own endpoints, then also
  copies the jars to `server/default/deploy/` so the engine classloader can resolve the OGNL hook classes.

The merge is what lets a filter run over `/as/token.oauth2` and `/idp/init_logout.openid` - a servlet
filter in a separate war can only see its own context. Both packagings carry the same module set bar
`ssf`, which only the merge ships.

## Build

```bash
mvn package                              # from the root; the war lands in servlets/oidf-war/target/oidf.war
mvn -pl servlets/oidf-war -am package    # this module and everything it depends on
```

Dependency versions come from the repo BOM (`bom/pom.xml`, `scope=import`); there is no parent pom. The
`provided` PF jars (`pf-protocolengine`, `pingfederate-sdk`) must be in `~/.m2` - see the root README.
