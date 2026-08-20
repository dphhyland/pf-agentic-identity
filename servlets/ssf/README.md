# ssf

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Extracted with history from `pf-oidf-modules` 2026-07-21; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

**Shared Signals Framework 1.0 (CAEP/RISC) transmitter + receiver** for PingFederate. Plain
`@WebServlet` classes plus one `Filter`, on the webapp classloader (not a PF-INF plugin). Depends on
[`pf-integration`](../pf-integration) for `PfJwksSigningKeyProvider` (SETs are signed with PF's own
active JWKS key; `jwks_uri` is `<issuer>/pf/JWKS`) and on the `provided` PF SDK for grant revocation
and PF-managed data sources. `com.pingidentity.ps.oidf.ssf` is the core; `…servlet.ssf` the PF-facing edge.

- **Transmitter** - `SetMinter`, stream management (`StreamManagementService`), poll (`SsfPollServlet`,
  RFC 8936) + push (`PushDeliveryService`, RFC 8935, background retry loop), event sourcing from PF's
  native security-audit log (`SsfAuditLogSource`, a log4j2 appender attached programmatically to PF's
  five audit loggers - no `log4j2.xml` edit) plus `LogoutEventFilter`. `SsfEventBridge` is the seam PF
  events call into; it de-duplicates the same (type, subject) across overlapping sources.
- **Receiver** - `SsfReceiverServlet` verifies inbound SETs (`SetVerifier`, against the configured
  transmitter's JWKS) and dispatches to handlers; `PollReceiverClient` pulls from a remote poll endpoint;
  `PfReceiverActions` revokes the subject's grants through `AccessGrantManagerAccessor`.
- **Stores** - `InMemorySsfStore` (per node, not durable), `JdbcSsfStore` (own tables, DDL applied at
  boot), `LdmSsfStore` (Identity Object Model `idm.entry` schema, never creates tables). `PfJdbcStoreFactory`
  picks: direct `jdbcUrl` (dev) beats a PF-managed `dataStoreId` (production, PF's own pool).
- **Kafka** - `KafkaSetPublisher` is reflection-only: no compile-time dependency, no Kafka class loaded
  unless `kafkaEnabled`.
- **Auth** - every management/poll/SCIM call carries a receiver bearer, validated by PF's own RFC 7662
  introspection (`PfIntrospectionReceiverAuthenticator`) and required to hold `receiverScope`.

Events: `SsfEventTypes` / `CaepRiscEvents` - CAEP session-revoked, credential-change,
assurance-level-change, token-claims-change, device-compliance-change, session-established; RISC
account-disabled/enabled/purged, credential-change-required, identifier-changed/recycled; verification.
Default stream event types: session-revoked, credential-change, account-disabled, account-enabled.

## Endpoints

| Path | Class | What |
|---|---|---|
| `GET /.well-known/ssf-configuration`, `/ssf/.well-known/ssf-configuration` | `SsfConfigurationServlet` (`loadOnStartup=1`) | Transmitter metadata; also the servlet that bootstraps `SsfSupport` at boot so the logout filter can emit immediately. |
| `POST/GET/PATCH/DELETE /ssf/streams`, `/ssf/status`, `/ssf/subjects:add`, `/ssf/subjects:remove`, `/ssf/verify` | `SsfStreamManagementServlet` | Stream Management API; starts the push-delivery loop. |
| `POST /ssf/poll?stream_id=` | `SsfPollServlet` | RFC 8936 poll: `maxEvents`, `returnImmediately`, `ack`. |
| `POST/GET /ssf/receiver/events` | `SsfReceiverServlet` | RFC 8935 receiver (`application/secevent+jwt`; 202 on accept, 400 with `err` on failure). Active only when `receiverExpectedIssuer` is set. |
| `POST/PUT/PATCH/DELETE /ssf/scim/v2/Users[/*]` | `SsfScimSubjectServlet` | SCIM 2.0 `/Users` mapping provisioning to stream membership (`urn:ietf:params:scim:schemas:extension:ssf:2.0:Subject`); `active:false`/`DELETE` emits RISC account-disabled. |
| filter `SsfLogoutSignal` over `/idp/init_logout.openid` | `LogoutEventFilter` | Emits CAEP session-revoked after PF processes an OIDC logout. Not annotated - registered in `pf-runtime.war`'s `web.xml` by `build/pingfederate/assemble-pf-runtime-war.sh`. Fail-open, fail-quiet: logout always proceeds. |

Caveat: `LogoutEventFilter` takes the subject from an unverified `id_token_hint`/`logout_token`, or a bare
`sub` request parameter - unauthenticated input, so anyone who can reach the logout endpoint can trigger a
session-revoked SET for an arbitrary subject. Known finding, not yet closed.

Every servlet calls `SsfHttp.bootstrap` in `init()`: fail-soft. No issuer means the SSF endpoints stay
disabled and PF boots regardless - SSF must never take the runtime web application down.

## Configuration

Every `SsfConfiguration` setting resolves init-param → sysprop `oidf.ssf.<name>` (PF loads `run.properties`
as system properties) → env `OIDF_SSF_<UPPER_SNAKE>`, so an image-baked PF needs no `web.xml`. Only
`issuer` is required (`OIDF_SSF_ISSUER` - the SET `iss` and the base of `jwks_uri`, so it must be the
external base receivers use).

| Group | Settings (defaults) |
|---|---|
| Transmitter | `signingAlgorithm` (RS256/PS256), `basePath` (`/ssf`), `setTtlSeconds` (7 days), `defaultEventTypes`, `verificationEventEnabled` (true), `pollMaxEvents` (100), `pushRetryMaxAttempts` (5), `pushRetryBackoffSeconds` (5) |
| Store | `dataStoreId` (PF JDBC data store id) or `jdbcUrl`+`jdbcUsername`+`jdbcPassword`; `storeDialect` (`tables` \| `ldm`); blank = in-memory |
| Receiver auth | `receiverScope` (`ssf.manage`), `introspectionEndpoint` (`<issuer>/as/introspect.oauth2`), `introspectionClientId`/`introspectionClientSecret` (deployed as secrets), `introspectionInsecureTls` |
| Receiver | `receiverExpectedIssuer`, `receiverJwksUrl`, `receiverAudience`, `receiverEndpointAuthToken`, `receiverJwksCacheSeconds` (300), `receiverInsecureTls`, `receiverPollUrl`/`receiverPollToken`/`receiverPollIntervalSeconds` (10), `receiverActionsEnabled` (true) |
| Sources | `auditEventsEnabled` (true), `auditEventMap` |
| Kafka | `kafkaEnabled` (false), `kafkaBootstrapServers`, `kafkaTopic` (`sse-events`), `kafkaSecurityProtocol` (`PLAINTEXT`), `kafkaSaslMechanism`/`kafkaSaslUsername`/`kafkaSaslPassword` |

## Build and deploy

```bash
mvn -pl servlets/ssf -am package     # → target/ssf-0.1.0.jar (tests on)
```

Versions from `bom/pom.xml`. **Not part of `oidf.war`** - `oidf-war` does not depend on this module.
It reaches production only through the `pf-runtime.war` merge: `build/pingfederate/stage-modules.sh`
stages `ssf-0.1.0.jar` with the other six jars, the Dockerfile injects them into the stock war (root
context, single classloader - the only place a filter can sit over PF's own `/idp/init_logout.openid`) and
copies them to the engine deploy dir. The deploying repo's [`vars.<env>.env`](https://github.com/dphhyland/pf-oidf-modules/blob/main/deploy/pingfederate) sets `OIDF_SSF_ISSUER`.
