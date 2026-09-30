# ssf

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Extracted with history from `pf-oidf-modules` 2026-07-21; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

**Shared Signals Framework 1.0 (CAEP/RISC) transmitter + receiver** for PingFederate. Plain
`@WebServlet` classes plus one `Filter`, on the webapp classloader (not a PF-INF plugin). Depends on
[`pf-integration`](../pf-integration) for `PfJwksSigningKeyProvider` (SETs are signed with PF's own
active JWKS key; `jwks_uri` is `<issuer>/pf/JWKS`) and on the `provided` PF SDK for grant revocation
and PF-managed data sources. `com.pingidentity.ps.oidf.ssf` is the core; `…servlet.ssf` the PF-facing edge.

Since 0.5.0 the PingFederate-free parts live in [`libs/shared-signals`](../../libs/shared-signals) (package
`com.pingidentity.ps.oidf.signals`): `SecurityEventToken`, `SetMinter`, `SetVerifier`, `ReceivedSet`, `SubjectId`,
`CaepRiscEvents` and the event URIs. This module adds what needs PingFederate or the network: `PfSetSigningKeys`
(PingFederate's key, resolved on first use), `JwksHttpSource` (the receiver's JWKS fetch) and `SsfSubjects`, which
keeps the subjects accepted from outside - stream subjects, the emit API, SCIM ids, an inbound `sub_id` - to the five
formats it has always handled (`iss_sub`, `email`, `phone_number`, `opaque`, `account`) until plan item H-SSF-1
(Phase 3) stores, matches and acts on the others.

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
- **Auth** - every management/poll call carries a receiver bearer, validated by PF's own RFC 7662
  introspection and required to hold `receiverScope`. The scope
  gets a client to the endpoints, not to every stream behind them: a stream is its creator's
  ([Stream ownership](#stream-ownership)). SCIM takes a different scope, `provisionerScope`, and the
  receiver scope never opens it ([What the transmitter signs](#what-the-transmitter-signs)).
  `PfIntrospectionReceiverAuthenticator` is a thin adapter over libs/platform's `TokenIntrospector` (from 0.6.0, plan
  item S8b): the call is bounded (1 s to connect, 2.5 s in all, 64 KiB; no answer is a 503), the answer is read
  strictly (`scope` a space-separated string, as RFC 7662 §2.2 has it), and an active token must also be within its
  `exp` and `nbf`, carry a `client_id`, and - when it carries an `aud` - name `issuer` in it. A token bound to a key or
  a certificate (`cnf`, which PingFederate 13.1.3's introspection returns for a DPoP-bound token) is refused: these
  endpoints take `Bearer` tokens only, and RFC 9449 §7.2 says a resource that takes both schemes "MUST reject a
  DPoP-bound access token received as a bearer token". The receivers this repository knows - the conformance suite's
  and pf-oidf-modules' `probe-ssf.sh` - send bearer tokens (checked 2026-09-30), so SSF's receivers stay on bearer
  tokens: they are the transmitter's clients, not operators, and the operator APIs' DPoP rule is not theirs. No SSF
  path is an operator route (`SsfRoutes`; `SsfRoutesTest` fails on an SSF path it does not class).

Events: `SsfEventTypes` / `CaepRiscEvents` - CAEP session-revoked, credential-change,
assurance-level-change, token-claims-change, device-compliance-change, session-established; RISC
account-disabled/enabled/purged, credential-change-required, identifier-changed/recycled; verification.
Default stream event types: session-revoked, credential-change, device-compliance-change, account-disabled,
account-enabled - the first three are the CAEP Interop Profile's (see [CAEP Interop](#caep-interop)). A CAEP
`reason_admin` is an object keyed by language tag, never a bare string: `CaepRiscEvents` tags a sentence
`en`, and a caller with translations passes the object.

## Endpoints

| Path | Class | What |
|---|---|---|
| `GET /.well-known/ssf-configuration`, `/ssf/.well-known/ssf-configuration` | `SsfConfigurationServlet` (`loadOnStartup=1`) | Transmitter metadata; also the servlet that starts the transmitter at deploy ([Start-up](#start-up)), so the logout filter can emit immediately and the [push loop](#push-delivery) runs before any request arrives. |
| `POST/GET/PATCH/PUT/DELETE /ssf/streams`, `/ssf/status`, `/ssf/subjects:add`, `/ssf/subjects:remove`, `/ssf/verify` | `SsfStreamManagementServlet` | Stream Management API. `aud` is assigned from the caller's `client_id` when the create names none; `GET` without `stream_id` returns a bare array; PATCH and PUT take `stream_id` in the body (PATCH still reads the query parameter); PUT cannot change `delivery.method`; add-subject answers 200, remove-subject and verify 204. Every operation is scoped to the caller's own streams; another receiver's stream is a 404, and a create from a token naming no client a 403. A create with no `delivery` is a poll stream; one past `maxStreamsPerClient` is a 409, and a verification sooner than the stream's `min_verification_interval` a 429 with `Retry-After` ([Stream management](#stream-management)). |
| `POST /ssf/poll?stream_id=` | `SsfPollServlet` | RFC 8936 poll: `maxEvents` (0 = acknowledge only; capped at `pollMaxEventsCap`), `returnImmediately` (absent is `false`, a long poll), `ack`, `setErrs`. A stream that is not enabled returns nothing. Only the stream's owner can poll it; anyone else gets a 404 and acknowledges nothing. See [Poll delivery](#poll-delivery). |
| `POST/GET /ssf/receiver/events` | `SsfReceiverServlet` | RFC 8935 receiver (`application/secevent+jwt`; 202 on accept, 400 with `err`, `description` and `Content-Language` on failure - a SET carrying `exp` or `sub` among them). Active only when `receiverExpectedIssuer` is set. See [The receiver](#the-receiver). |
| `GET/POST/PUT/PATCH/DELETE /ssf/scim/v2/Users[/*]` | `SsfScimSubjectServlet` | SCIM 2.0 `/Users` mapping provisioning to stream membership (`urn:ietf:params:scim:schemas:extension:ssf:2.0:Subject`): `GET` by id or with a `filter`, `PUT` replaces, `active:false`/`DELETE` emits RISC account-disabled and `active` back to true account-enabled; errors in the SCIM error schema ([SCIM](#scim)). Bearer must hold `provisionerScope` (unset by default = 403 for everyone; the receiver scope is refused). A provisioner acts across every receiver's streams. |
| `POST /ssf/events:emit` | `SsfEventEmitServlet` | Raise an event the transmitter did not observe itself: `{"event_type", "subject", "event"?, "stream_id"?}` (`EmitRequest`). Bearer must hold `provisionerScope`, like SCIM and for the same reason - the transmitter signs a SET about a subject of the caller's choosing to every receiver. It admits nothing the emitter does not: a stream still has to subscribe (`SsfEventEmitter.subscribes`), and `stream_id` only narrows the fan-out (404 if absent). For the three interop events the subject is `email` or `iss_sub`, `reason_admin` is supplied if absent, and `credential_type`/`change_type`/`previous_status`/`current_status` take only their defined values (400 otherwise). Answers `{"event_type", "emitted":[{stream_id, jti, delivery}], "count"}`; a count of 0 is nothing subscribed, not an error. |
| filter `SsfLogoutSignal` over `/idp/init_logout.openid` | `LogoutEventFilter` | Emits CAEP session-revoked after PF processes an OIDC logout. Not annotated - registered in `pf-runtime.war`'s `web.xml` by `build/pingfederate/assemble-pf-runtime-war.sh`. Fail-open, fail-quiet: logout always proceeds. |

`LogoutEventFilter` takes the subject from an `id_token_hint`/`logout_token`, verified (`PfIdTokenVerifier`)
against this PF's own signing keys (asymmetric algorithms only; expiry is deliberately not enforced - a hint
presented at logout is routinely expired, and its age says nothing about who it names). A bare `sub` request
parameter is accepted only when a deployment opts in (`OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM=true`, for a dev rig
with no real id tokens to hand); it is refused by default, closing the earlier unauthenticated-subject finding.

The transmitter starts once, as the `SSF` component's part, from `SsfConfigurationServlet`'s `init`
(`loadOnStartup=1`), and the receiver's part registers from `SsfReceiverServlet`'s (`loadOnStartup=2`), so both
are in the health detail and the start-up audit from deploy ([Start-up](#start-up)). No `init` throws: SSF must
never take the runtime web application down. The other SSF servlets start nothing and answer through the
transmitter's part: 503 while it is starting, failed or refused, 404 while it is off.

## Configuration

Every setting is read through the `ssf-transmitter` catalogue ([docs/configuration/ssf-transmitter.md](../../docs/configuration/ssf-transmitter.md),
generated from it) with platform's `Settings`: the servlet's init-param, then the system property
`oidf.ssf.<init-param>` (PF loads `run.properties` as system properties), then `OIDF_SSF_<UPPER_SNAKE>` - the
order `SsfConfiguration.param` used before 0.6.0, and all 43 names of each are catalogued, so an image-baked PF
needs no `web.xml` (only `SsfConfigurationServlet`'s init-params count; the other servlets read none). Each of the
five secrets may be given as a file, through its `_FILE` variant in any source (`OIDF_SSF_JDBC_PASSWORD_FILE`,
`oidf.ssf.jdbcPassword.file` or the init-param `jdbcPasswordFile`). Only `issuer` is required (`OIDF_SSF_ISSUER` - the
SET `iss` and the base of `jwks_uri`, so it must be the external base receivers use). `OIDF_SSF_ENABLED` and
`OIDF_SSF_RECEIVER_ENABLED` switch the two components ([docs/operator/components.md](../../docs/operator/components.md)).

Every value is parsed strictly, and a wrong one names its setting: a switch is `true` or `false` in any case, a
number a whole number, a choice one of its choices in any case, a URL an http or https URL with a host. The
development profile reads a switch's legacy spelling (`yes`, `no`, `1`, `0`, `on`, `off`) as `false`, as
`Boolean.parseBoolean` did, with a WARN naming the strict spelling; production refuses it.

| Group | Settings (defaults) |
|---|---|
| Transmitter | `signingAlgorithm` (RS256/PS256), `setTtlSeconds` (7 days), `defaultEventTypes`, `defaultSubjects` (`NONE`; `ALL` = every enabled stream hears every subject without an add-subject, SSF §7.1.1, and is what [CAEP Interop](#caep-interop) needs), `verificationEventEnabled` (true), `pollMaxEvents` (100), `pollMaxEventsCap` (100, 1-1000), `pollLongPollWaitSeconds` (10, 0-30), `pushRetryMaxAttempts` (5), `pushRetryBackoffSeconds` (5), `maxStreamsPerClient` (10, 1-1000), `minVerificationIntervalSeconds` (30, 0-86400), `inactivityTimeoutSeconds` (0 = none, 0-31536000). `basePath` was removed in 0.6.0 ([Stream management](#stream-management)). |
| Store | `dataStoreId` (PF JDBC data store id, on PostgreSQL) or `jdbcUrl`+`jdbcUsername`+`jdbcPassword`; `storeDialect` (`tables` \| `ldm`); blank = in-memory, which production allows only with the `in-memory-state` risk accepted |
| Receiver auth | `receiverScope` (`ssf.manage`), `provisionerScope` (unset - nobody may use SCIM; suggested `ssf.provision`, must differ from `receiverScope` or SSF is `FAILED_CONFIG`), `allowedAudiences` (`clientA=aud1,aud2;clientB=aud3` - the `aud` values a client may name on create besides its own id, see [What the transmitter signs](#what-the-transmitter-signs)), `unownedStreamOwner` (unset - see [Stream ownership](#stream-ownership)), `introspectionEndpoint` (`<issuer>/as/introspect.oauth2`), `introspectionClientId`/`introspectionClientSecret` (deployed as secrets), `introspectionInsecureTls` (false; `true` trusts any certificate chain on the introspection call through libs/platform's `InsecureTls`, which warns once - the host name is still checked; refused in production) |
| Receiver | `receiverExpectedIssuer` (turns the receiver on), `receiverJwksUrl`, `receiverAudience` and `receiverEndpointAuthToken` (**both required once the receiver is on** - missing either, `SSF_RECEIVER` is `FAILED_CONFIG` and an ERROR says which),  `receiverJwksCacheSeconds` (300), `receiverInsecureTls` (false; `true` trusts any certificate chain on the JWKS fetch, the poll and the stream calls through libs/platform's `InsecureTls`, which warns once - the host name is still checked; refused in production), `receiverPollUrl`/`receiverPollIntervalSeconds` (10), `receiverPollToken` (development only; refused in production), `receiverTokenEndpoint`/`receiverClientId`/`receiverClientSecret` or `receiverClientKey`/`receiverClientScope` (the receiver's token by client credentials), `receiverTransmitterConfigurationUrl`/`receiverPushEndpointUrl`/`receiverEventsRequested` (the receiver's own stream), `receiverSubjectIssuers`, `receiverActionsEnabled` (true) - see [The receiver](#the-receiver) |
| Sources | `auditEventsEnabled` (true), `auditEventMap` |
| Kafka | `kafkaEnabled` (false), `kafkaBootstrapServers`, `kafkaTopic` (`sse-events`), `kafkaSecurityProtocol` (`PLAINTEXT`), `kafkaSaslMechanism`/`kafkaSaslUsername`/`kafkaSaslPassword` |

## Push delivery

`PushDeliveryService` is one loop on one thread for every push stream, ticking every
`pushRetryBackoffSeconds`. What one stream can cost the others is bounded there, since 0.4.0 (S10-0, the
Phase 1 stopgap for the review's B5; the leased engine that replaces the loop is S-10, Phase 4):

- **The store hands over only enabled push streams' SETs.** `SsfStore.dueForPush` is a join on the
  stream's state in all three stores, not a filter the loop applies afterwards. The batch is 500 SETs
  across every stream, oldest first, so before this the held SETs of a paused stream - or a poll stream's
  queue, or a disabled stream's - were the whole batch every tick once there were 500 of them older than
  anyone else's, and the enabled stream behind them was never read. SSF 1.0 §8.1.2.1: enabled, "The
  Transmitter MUST transmit events over the stream, according to the stream's configured delivery method";
  paused, "The Transmitter MUST NOT transmit events over the stream. The Transmitter SHOULD hold any events
  it would have transmitted while paused"; disabled, "The Transmitter MUST NOT transmit events over the
  stream". The loop reads the stream again before it posts, so a stream paused between selection and
  delivery is still held.
- **A stream that fails waits, whole.** After a retryable failure nothing more of that stream is tried in
  the tick, and in later ticks nothing of it is tried while its oldest SET is waiting out the backoff that
  failure set: its later SETs are due, but posting them would put them in front of the one that failed. So a
  receiver that is down costs one attempt per backoff step (5, 10, 20, 40 s at the defaults), not one per
  queued SET or one per tick, and when it is back the SET that failed goes first and the rest follow in the
  store's order: by `issuedAt`, and SETs issued in the same second by `jti`. `issuedAt` is in seconds and the
  `jti` is random, so within a second that is not the order the SETs were generated in (F-0095). The
  attempts are counted on the stream's first SET, and the stream dead-letters (`paused`, with the reason
  recorded) when it has failed `pushRetryMaxAttempts` times: about 75 s after the first failure at the
  defaults when the receiver refuses at once, as before, and about 100 s when every attempt runs to the 10 s
  deadline - for a burst of SETs issued in one second as for one SET. Both reads of the queue, `peek` (which
  the hold asks) and `dueForPush`, use that one order in all three stores; ordered by `issuedAt` alone,
  Postgres returned a burst in whatever order its rows lay, the retry moved from SET to SET, and five SETs of
  one second took 130 s to dead-letter (`SsfStoresOnPostgresTest`, 2026-09-27).
- **A POST ends at its deadline.** From 0.6.0 (plan item S5d) the POST goes through libs/platform's
  `OutboundHttp`: connecting, TLS included, within 2 s, and the whole exchange, body included, within 10 s - S-10's
  values (`PushDeliveryService.CONNECT_TIMEOUT`, `REQUEST_TIMEOUT`), constants here until S-10 catalogues them in
  Phase 4. Every read waits no longer than what is left of the deadline, so a receiver that sends its status line
  and then a byte every 100 ms is given up on at 10 s like one that never answers, and the socket is closed when
  the attempt ends. At most 64 KiB of an answer is read (`RESPONSE_BODY_CAP`): RFC 8935 §2.2 on the 202, "The body of
  the response MUST be empty", and §2.3 has a 400 carry a JSON object of `err` and `description`, so a larger
  answer is a failed attempt, retried, and never read past the cap; only a 400's body is used, the first 4096
  characters of it in the log line. No redirect is followed. A failed attempt is a
  retry, as before, and its WARN names the reason (`HEADER_TIMEOUT`, `DEADLINE`, `TLS`, `BODY_TOO_LARGE`,
  `CONNECT_FAILED` and the rest). An interrupt - the loop stopping - ends the wait within platform's 250 ms read
  slice and stays set, so the loop posts nothing after it (`PushDeliveryHttpTest`). The endpoint is held to the
  federation fetch rules (`OutboundUrlPolicy`, [outbound-fetch](../../docs/configuration/outbound-fetch.md)): https,
  and public addresses only, which `OIDF_FETCH_ALLOW_HTTP`, `OIDF_FETCH_HOST_ALLOWLIST` and
  `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS` widen; the host is resolved once, every address checked, and the connection
  goes to a checked address, so a name cannot resolve publicly for the check and privately for the connection. A
  refused endpoint is dropped, not retried, as before. The JVM's trust store decides the receiver's certificate,
  which must name the endpoint's host. Before 0.6.0 the POST used the JDK's `HttpClient`, whose request timeout
  stops at the headers; the exchange was waited on as a whole and cancelled at the deadline (U-0077).
- **The loop starts at boot.** `SsfSupport.start` - what the `SSF` part's start runs - starts it once
  the store is open, from `SsfConfigurationServlet`, `loadOnStartup=1`.
  Until 0.4.0 the loop started from `SsfStreamManagementServlet.init`, which is lazy: nothing was pushed
  until a receiver's first management request, and nothing at all on a node no receiver managed streams on.
  Verified 2026-09-27 on the rig (PingFederate 13.1.3, this branch's jars at `e858f9e`): `SSF push delivery
  executor started` is logged at 03:41:43,415 UTC, the runtime listener on 9031 starts at 03:41:45,160 and
  `PingFederate started` at 03:41:45,742, with nothing in `audit.log` - the loop ran before any request could
  arrive, and the annotation's `loadOnStartup` is honoured in the merged `pf-runtime.war`.

The selection and the loop are tested against the stores as they run. `SsfStoresOnPostgresTest` runs the
`tables` and `ldm` stores' `dueForPush`, three ticks of the loop over each, and a burst of one second's SETs,
against Postgres - the `ldm` store on the model repo's `0000` and `0001` migrations, vendored under
`src/test/resources/idm` - and CI's `java` job runs it against its Postgres service. Since 0.5.0 the rest of
the `SsfStore` contract runs there too: `SsfStoreContract` holds the in-memory store and, in
`JdbcSsfStoreOnPostgresTest` and `LdmSsfStoreOnPostgresTest`, both durable stores to the same streams,
owners, subjects and queue tests, each class in a database of its own (`libs/testkit`). The `ldm` store
reads a stream's `updatedAt` back as the database's time of its last write (F-0150). The `tables` store's
selection and the same three ticks were also run once on the HSQLDB 2.7.1 the PingFederate 13.1.3 image ships
(2026-09-27); from 0.5.0 a `jdbc:hsqldb:` or `jdbc:h2:` `OIDF_SSF_JDBC_URL` is refused at start-up, an
`OIDF_SSF_DATA_STORE_ID` naming an HSQLDB or H2 data store (PingFederate's bundled one included) is refused on
its first connection, and PostgreSQL is the one database the stores are tested on.

**What this does not fix** (S-10): fairness between enabled streams - a stream with more than 500 due SETs
older than another's still fills the batch, and a receiver that answers slowly but successfully holds the
loop for as long as its SETs take, up to 10 s each; one thread; no leases, so every node in a cluster runs
the loop against the shared store (F-0007, single node until v0.7.0); the order of SETs issued in the same
second (F-0095). Dead-letter keeps the SETs already queued and pauses the stream, but nothing is queued for
a stream that is not enabled, so every event raised while it is paused is lost, not held (F-0017; S10c,
S10d). Push delivery has still not been run against the conformance suite: it needs a suite PingFederate
can call back ([conformance/README.md](../../conformance/README.md)).

## The receiver

The receiver takes SETs pushed to `/ssf/receiver/events` (RFC 8935) and, with a poll URL or a stream of its own,
polls a transmitter for them (RFC 8936, `PollReceiverClient`). Each goes through `SsfReceiverService`: refused,
discarded or verified, deduplicated by `jti`, and handed to the handlers - `ReceiverActionHandler` revokes the
subject's PingFederate grants, `InstanceRegistryReceiverHandler` suspends or revokes agent instances. From 0.6.0
(plan item H-SSF-1):

- **Subjects.** An inbound `sub_id` may be any of the five formats as before, RFC 9493's `did`, `uri` and `aliases`,
  or SSF 1.0 §3.3's complex subject (`SsfSubjects.RECEIVER_FORMATS`); SSF 1.0's `jwt_id`, `saml_assertion_id` and
  `ip-addresses` name a token or an address and stay refused as `invalid_request`. `SsfSubjects` maps a subject to
  the user key or device id a handler acts on: an `iss_sub` to its `sub` only when its `iss` is the SET's issuer,
  this PingFederate's `OIDF_SSF_ISSUER` or one in `receiverSubjectIssuers` (RFC 7519 §4.1.2 scopes a subject "to be
  locally unique in the context of the issuer"); `email`, `phone_number`, `opaque`, `account`, `did` and `uri` to
  their one member; `aliases` by the first identifier that maps, in the order `iss_sub`, `email`, `account`,
  `phone_number`, `opaque`, `did`, `uri`; a complex subject by its `user` member for a user and its `device` member
  for a device, the instance registry trying the device first. A subject that maps to no one is logged with the
  reason and counted (`ssf.receiver.subject_unmapped`), and nothing is acted on.
- **`exp` and `sub` refused** (finding F-0246). SSF 1.0 §4.1.7: "The "exp" claim MUST NOT be used in SETs"; §4.1.2:
  "The JWT "sub" claim MUST NOT be present in any SET containing an SSF event". A SET carrying either is refused
  as `invalid_request` with a description naming the claim - a 400 on push, a `setErrs` entry on poll - and counted
  (`ssf.receiver.set_refused`, reason the error code). The check is the receiver's own; libs/shared-signals'
  `SetVerifier` still honours an `exp` for its other users.
- **Critical subject members.** SSF 1.0 §3.6: "An SSF Receiver MUST discard any event that contains a Subject with a
  Critical member that it is unable to process". The transmitter's `critical_subject_members`, read when the
  receiver sets up its stream, are held against the members the handlers act on (`user`, `device`): an event whose
  complex subject carries another critical member is accepted (202, acknowledged) and not acted on
  (`ssf.receiver.set_discarded`).
- **The token.** The poll and stream calls present a bearer from the transmitter's authorization server, by client
  credentials (`ClientCredentialsToken`): `receiverTokenEndpoint`, `receiverClientId`, and `receiverClientSecret`
  (`client_secret_basic`) or `receiverClientKey` (a private JWK, `private_key_jwt`), with `receiverClientScope`. It is
  kept until 30 seconds (or a tenth of its lifetime) before `expires_in` runs out, and a call answered 401 fetches a
  new one and is made once more. `receiverPollToken`, a static token, stays for development and is refused in
  production: it never expires or rotates, and a transmitter that stops taking it cannot be answered with another.
- **Its own stream.** With `receiverTransmitterConfigurationUrl` (the transmitter's `/.well-known/ssf-configuration`)
  the receiver manages its stream there (`ReceiverStream`, `ReceiverStreamClient.ensure`): at start-up it reads the
  metadata, finds its stream in the configuration endpoint's list - a push stream to `receiverPushEndpointUrl`, or its
  poll stream when that is unset - or creates one, and brings its `events_requested` (and a push stream's delivery
  and `authorization_header`, the receiver's endpoint token) into step with `receiverEventsRequested` (the five the
  handlers act on, by default). It checks what SSF 1.0 has a receiver check - §7.2.4, the metadata's `issuer` is the
  one the receiver expects, and §8.1.1.1-§8.1.1.3, the stream's `iss` - and that the stream's `aud` holds
  `receiverAudience`; a stream it created and cannot accept it deletes again. A poll stream is polled at the
  `endpoint_url` the transmitter gave it, so `receiverPollUrl` is refused beside this. The receiver's token goes only
  to https URLs the transmitter names: a `configuration_endpoint` or poll `endpoint_url` that is not https is
  `FAILED_CONFIG` (SSF 1.0 §7.1: "If present, this URL MUST use HTTP over TLS [RFC9110]"; RFC 8936 §3: "based upon
  HTTP over TLS [RFC2818]"), unless the configuration URL is itself http, which only the development profile allows;
  production refuses an http `receiverTokenEndpoint`, `receiverTransmitterConfigurationUrl` or
  `receiverPushEndpointUrl`.

- **Its outbound calls.** From 0.6.0 (plan item S5d) the poll, the stream management calls, the token request and
  the JWKS fetch go through libs/platform's `OutboundHttp`, each within a deadline on the whole exchange, body
  included, and a cap:

  | Call | Connect | Whole exchange | Most read | Why |
  |---|---|---|---|---|
  | Poll (`PollReceiverClient`) | 1 s | 5 s | 4 MiB | The poll asks `returnImmediately`, so the transmitter has nothing to wait for; 4 MiB is the default `maxEvents` of 100 at 40 KiB a SET |
  | Stream management (`ReceiverStreamClient`) | 1 s | 5 s | 256 KiB | It runs in the receiver's start, which the supervisor retries; 256 KiB is platform's default, a list of streams |
  | Token (`ClientCredentialsToken`) | 1 s | 5 s | 256 KiB | As the stream calls, which it comes before; before 0.6.0 it had 10 s to connect and 10 s for the headers, and no bound on the body |
  | JWKS (`JwksHttpSource`) | 1 s | 2.5 s | 64 KiB | It runs while a pushed SET waits to be verified; a key set is small |

  A poll that fails - its token request included - is logged at WARN with its reason first (`HEADER_TIMEOUT`,
  `DEADLINE`, `TLS`, `BODY_TOO_LARGE` and the rest) and asked again next tick with the same acknowledgements; a
  stream or token call that fails in the receiver's start leaves `SSF_RECEIVER` in `FAILED_DEPENDENCY`, retried; a JWKS fetch that fails is logged with its reason and the SET is
  refused, as one with no key is. The transmitter is the one the operator named and may be internal by design, so
  these calls may reach any address - still resolved once, every address checked for the URL rules, and the
  connection pinned to one of them - and no setting is needed to reach one; the scheme is the settings' to govern
  (above). `receiverInsecureTls` (`OIDF_SSF_RECEIVER_INSECURE_TLS`, forbidden in production) trusts any certificate
  chain through platform's `TlsTrust.insecureIf`; otherwise the JVM's trust store decides. Either way the certificate
  must name the host the URL names.

Where `SSF_RECEIVER` stands while it sets its stream up is under [Start-up](#start-up).

## Poll delivery

`POST /ssf/poll?stream_id=` is the transmitter's RFC 8936 endpoint. From 0.6.0 (plan item H-SSF-2):

- **`maxEvents` is capped** at `pollMaxEventsCap` (100 by default, 1-1000); unset, it is `pollMaxEvents`, under the
  same cap. RFC 8936 §2.2 has the transmitter "SHOULD NOT send more SETs than the specified maximum" and lets it pick
  which come first; `moreAvailable` says there are more. `maxEvents: 0` acknowledges only.
- **`setErrs` is recorded.** Each entry (RFC 8936 §2.2: "the "jti" values of invalid SETs received", each with `err`
  and `description`) is logged at WARN with the receiver's description (made log-safe), counted as
  `ssf.poll.set_error` under its RFC 8935 error code (`other` for any code the registry does not have), and the SET
  released - removed from the queue like an acknowledged one, since redelivering a SET its receiver cannot validate
  cannot succeed. Nothing records it once released; a dead-letter record is S-10's (Phase 4). A `setErrs` that is not
  an object of objects is a 400.
- **A stream that is not enabled returns nothing.** SSF 1.0 §8.1.2.1: `paused` - "The Transmitter MUST NOT transmit
  events over the stream" (the SETs already queued stay and are returned once it is enabled, but nothing new is
  queued while it is paused - see F-0017 above); `disabled` - "The Transmitter MUST
  NOT transmit events over the stream and will not hold any events for later transmission". The poll still
  acknowledges and records `setErrs`, and answers `{"sets": {}, "moreAvailable": false}` at once.
- **Long polling.** RFC 8936 §2.2: `returnImmediately` "The default value is "false", which indicates the request is
  to be treated as an HTTP long poll"; §2.5: the transmitter "SHALL delay responding until a SET is available or the
  timeout interval has elapsed". A poll that is not `returnImmediately: true`, asks for SETs and finds none is held
  for up to `pollLongPollWaitSeconds` (10 by default, 0-30; 0 answers at once) - in async mode, so no request thread
  waits: one managed executor (`oidf-ssf-long-poll-1`) checks every held poll each 250 ms with a one-row read of the
  store, answers it with a fresh poll when a SET is queued - on any node, since it reads the shared store - and with
  no SETs when the wait runs out. Async needs every filter in front of the servlet to allow it; where one does not,
  the poll is answered at once and an INFO line says so once. Before 0.6.0 an absent `returnImmediately` was read as
  `true`.

## Start-up

`SsfConfigurationServlet.init` registers the `SSF` part and hands `SsfComponents.transmitter` to
`Part.start` (plan item S-9), which never throws. The part applies `OIDF_SSF_ENABLED` first: `false` is `DISABLED`
and nothing runs; unset in production with `OIDF_SSF_ISSUER`, `OIDF_SSF_JDBC_URL` or `OIDF_SSF_DATA_STORE_ID` set
is `FAILED_CONFIG` naming the switch. Then:

| What it finds | The `SSF` part | The log |
|---|---|---|
| No `OIDF_SSF_ISSUER` | `DISABLED`; `FAILED_CONFIG` with `OIDF_SSF_ENABLED=true` | INFO "not configured" in development only; ERROR when switched on |
| A setting that does not parse, or a combination refused (Kafka on with no bootstrap servers, the provisioner scope equal to the receiver scope, an allowed-audiences entry that is not `clientId=aud[,aud]`) | `FAILED_CONFIG`, the reason naming the setting | ERROR `SSF transmitter NOT started: <the setting and why>` |
| The store in memory in production without `in-memory-state` in `OIDF_ACCEPTED_RISKS`; a `jdbcUrl` that is not `jdbc:postgresql:` in production; a database whose driver does not report `PostgreSQL` in production | `REFUSED` | ERROR from `ProfileRefusals`, listed in the start-up audit |
| A database that cannot be reached, or a DDL refused | `FAILED_DEPENDENCY`; the supervisor runs the start again after a wait of up to 5 s doubling to 300 s | ERROR `SSF transmitter NOT started: <the cause chain>` each time, the stack trace with the first only |
| Everything built | `READY` | INFO naming the store |

Everything the transmitter shares - the configuration, the store, the minter, the services, the receiver and the
receiver authenticator - is built first and published in one write (`SsfSupport.State`), so a request sees all of it
or none (finding F-0040). Only after that are the servlet layer's wiring (the receiver's PingFederate actions and
polling, the audit source) and the push loop started. The store is checked on one connection before it is used
(`PfJdbcStoreFactory.checkDatabase`): a database that is down fails at start-up for either dialect, and the product
name the JDBC driver reports (`DatabaseMetaData.getDatabaseProductName()`, `PostgreSQL` for PostgreSQL's driver) says
what a data store id points at, which no URL shows. H2 and HSQLDB are refused in every profile, as since 0.5.0. The
`ldm` dialect is the Identity Object Model's PostgreSQL schema, so it is held to the same rule.

While SSF is not `READY` every transmitter servlet answers 503 `temporarily_unavailable` (404 while it is off),
through the part's gate, and PingFederate's own endpoints are untouched. The events PingFederate raises in that
window are lost, not queued: a logout's SET is skipped with a WARN (`SSF session-revoked emission skipped`), the
audit source is attached only once the store opens, and SCIM answers 503 (F-0017; S10d). The ERROR line names the
cause chain with the `jdbcUrl` replaced by `<jdbcUrl>` - a JDBC URL can carry a password, and the driver's messages
repeat it - and the part's reason is the same line; the stack trace goes with the first failure only, and never for
a `jdbcUrl` store. A store failure that is the configuration's (a missing driver class, H2) is `FAILED_CONFIG` and
not retried.

The receiver runs inside the transmitter. `SsfReceiverServlet` loads after it and its part says what became of the
receiver: `FAILED_DEPENDENCY` while the transmitter is starting or failed on a dependency (the supervisor asks again),
`DISABLED` when the transmitter is off or no `OIDF_SSF_RECEIVER_EXPECTED_ISSUER` is set (or `FAILED_CONFIG` with
`OIDF_SSF_RECEIVER_ENABLED=true`), `FAILED_CONFIG` when the transmitter failed on its configuration or was refused,
or the receiver's audience or endpoint token is missing. `OIDF_SSF_RECEIVER_ENABLED=false` keeps the transmitter
from building the receiver at all. A receiver that manages its own stream ([The receiver](#the-receiver)) is not
ready until the stream is set up: a transmitter that cannot be reached or refuses a call leaves it
`FAILED_DEPENDENCY`, with a WARN naming the cause, and the supervisor runs the start again; metadata or a stream whose
issuer or audience is not the receiver's is `FAILED_CONFIG`, with an ERROR. Its poll loop polls nothing until the
stream is set up. The receiver's JWKS is fetched on the first SET, not at start-up, so a JWKS that
is down is not a start-up failure: each SET is refused until it answers.

Until 0.6.0 SSF kept its own boot retry (every 30 s) and every SSF servlet's `init` started the transmitter, a
setting that did not parse turned SSF off with an INFO line that blamed the issuer (findings F-0191, F-0237), and the
shared state was published one member at a time.

Seen on the rig on 2026-09-27, with the 0.4.0 boot retry (PingFederate 13.1.3, the branch's jars at `e858f9e`), with a
`tables` store on a `jdbcUrl` whose database was started about two seconds after PingFederate: the ERROR at 03:42:28,675 UTC,
`PingFederate started` at 03:42:31,105, the SSF endpoints answering 500 while discovery, the heartbeat and the
federation endpoints answered 200, and at 03:42:58,677 - the try 30 s after the ERROR - the store opened, the
audit source attached and the push loop started; `/.well-known/ssf-configuration` answered 200 from then on.

Until 0.4.0 the exception escaped `SsfConfigurationServlet.init`, which loads at start-up ("Found while
designing" 11), and Jetty fails the whole merged `pf-runtime.war` on a load-on-startup servlet whose init
throws. On the same rig, with `OpenIdFederationServlet`'s init made to throw (no trust anchor named), Jetty
logged `Failed startup of context` for `pf-runtime.war` and every runtime endpoint on 9031 answered 503 -
discovery, the token endpoint, the heartbeat, SSF - while the admin console answered (U-0076). And a
`configure` that failed had already assigned its configuration, so every later servlet found it "configured"
with no store behind it.

## SET expiry

An undelivered SET is kept for `setTtlSeconds` and then deleted - on poll and push streams alike, and
whatever state the stream is in (paused, disabled, [unowned](#stream-ownership)). Two things enforce it:

- The background loop evicts on every tick (`pushRetryBackoffSeconds`), before it reads the push queue. It
  is the push executor's loop, but it starts with the transmitter and runs with no push stream
  configured, so a poll-only deployment expires its SETs too. A tick that cannot evict delivers nothing.
- A poll evicts before it reads, so a SET past its TTL is never handed over because the loop had not got
  to it yet.

`setTtlSeconds` of 0 or less means no expiry, and those SETs are never evicted. The expiry is stamped on a
SET when it is minted, so changing the setting does not move SETs that are already queued.

This is a retention setting, not a rule of the specs. RFC 8936 §2 permits it - "Transmitters may also
discard undelivered SETs under deployment-specific conditions, such as if they have not been polled for
over too long a period of time or if an excessive amount of storage is needed to retain them" - and
nothing requires it. A SET has no expiry of its own to honour either: SSF 1.0 §4.1.7, "The "exp" claim
MUST NOT be used in SETs". It also means nothing tells a receiver what it missed. One that has been away
longer than the TTL gets the SETs still inside it and no sign that older ones existed, and should
re-read the state it cares about rather than trust the stream to have caught it up.

**Upgrading.** Until this change the expiry was stamped and never enforced, so a store can hold SETs
long past it. The first tick after the upgrade deletes all of them in one statement - for a poll stream
whose receiver stopped polling, that is its whole backlog.

## Stream ownership

A stream belongs to the OAuth client that created it - the `client_id` PF's introspection returns for the
token on the create. That client is the only one the management, poll and SCIM endpoints admit to it.
`GET /ssf/streams` lists the caller's streams (SSF 1.0 §8.1.1.2, "available to this Receiver"), and every
other operation on a stream that is someone else's answers exactly as it does for an id nobody has: the
same 404, the same body. SSF words that error as no stream with that id "for this Event Receiver". It also
offers a 403 for a receiver that is "not allowed" - not used here, because it confirms the id is real.

Before this, `receiverScope` was the whole check. Any client holding it could list every stream, read or
repoint another receiver's push endpoint, delete its stream, and poll - which acknowledges, so it consumed
the other receiver's SETs rather than merely reading them.

The owner is not `aud`. A receiver may still send its own `aud` on create, so that value is whatever the
creator typed. The owner comes from the token and is written once: no update, status change or executor
pause can move or clear it, in any of the three stores. A token that is active and scoped but names no
client (`client_id` is OPTIONAL in RFC 7662) owns nothing, sees nothing, and gets a 403 on create.

The owner is the client id and nothing more. A client deleted and registered again under the same id is the
same owner, streams and queued SETs included. Ids are compared exactly - `Receiver-A` is not `receiver-a`.

The event emitter and the push executor are not scoped - they act for the transmitter, across every
receiver's streams. So does the SCIM endpoint, for a provisioner: it is not a receiver and owns no
streams (below).

**What ownership does not settle.** It decides who may manage and drain a stream, not what the stream's
SETs say. That is the next section.

## Stream management

From 0.6.0 (plan item H-SSF-3; SSF 1.0 final, 29 August 2025):

- **The optional stream members** of SSF 1.0 §8.1.1 are stored, returned and checked. `description` is the
  receiver's ("Receiver-Supplied, OPTIONAL. A string that describes the properties of the stream"): any string,
  cut at 1,024 characters (the section allows it: "The transmitter MAY truncate the string beyond an allowed max
  length"); PATCH changes it, and a PUT without it deletes it. `min_verification_interval` and
  `inactivity_timeout` are "Transmitter-Supplied": a stream is given `minVerificationIntervalSeconds` and
  `inactivityTimeoutSeconds` when it is created (0 gives it none), a receiver cannot set them, and one it echoes
  back on PATCH or PUT must match or is a 400. A stream stored before 0.6.0 reports, and is held to, the current
  settings, and so does every stream on the `ldm` store, which keeps none of the three and refuses a `description`
  with a 400 until the model declares them ([SCIM](#scim), "The `ldm` store"). `inactivity_timeout` is recorded and
  reported only: nothing pauses or deletes an inactive stream on this release (S-10's, Phase 4).
- **429 on verification.** A verification request sooner than the stream's `min_verification_interval` after the
  last one accepted is answered 429 with `Retry-After` (the seconds left, rounded up), and nothing is signed. §8.1.1:
  "If an Event Receiver submits verification requests more frequently than this, the Event Transmitter MAY respond
  with a 429 status code. An Event Transmitter SHOULD NOT respond with a 429 status code if an Event Receiver is not
  exceeding this frequency." The time of the last one is kept per node, in memory: on n nodes a receiver can have
  up to n verifications signed per interval.
- **A cap on streams per receiver**, `maxStreamsPerClient` (10). One more create is a 409: §8.1.1.1 answers "409
  Conflict" when "the Transmitter does not allow multiple streams with the same Receiver", and a cap is that rule
  with a larger number - the receiver reuses, replaces or deletes a stream, and waiting does not help, which a 429
  would suggest. The count is read before the insert, so two creates racing can leave a receiver one over.
- **The metadata** carries every member §7.1 defines, under its own name, except `critical_subject_members`: this
  transmitter names none, and §7.2.3 says "Claims with zero elements MUST be omitted from the response". None was
  missing before 0.6.0; `events_supported` and `all_events_supported` are this transmitter's own (§7.2.3: "Other
  Claims MAY also be returned").
- **An https issuer.** §7.1 has the `issuer` "URL using the https scheme with no query or fragment component", and
  every endpoint the metadata lists is the issuer and a path, each of which "MUST use HTTP over TLS". An http
  `OIDF_SSF_ISSUER` is `FAILED_CONFIG` in production; the development profile starts it with a WARN. One with a
  query, a fragment or no host is `FAILED_CONFIG` in either profile.
- **`basePath` is removed.** It changed the URLs the transmitter advertised and not the paths its servlets answer -
  their `@WebServlet` paths are fixed when the module is built - so anything but `/ssf` sent receivers to endpoints
  nothing served. Every URL the transmitter builds (the metadata's endpoints, a poll stream's `endpoint_url`, a SCIM
  user's `meta.location`) is the issuer and a path in `SsfPaths`, each held to a mapped pattern by a test. Set by any
  of its names (`OIDF_SSF_BASE_PATH`, `oidf.ssf.basePath`, the init-param `basePath`), SSF is `FAILED_CONFIG`
  naming it.

## SCIM

`/ssf/scim/v2/Users` from 0.6.0 (plan item H-SSF-4; RFC 7644):

- **The resource.** The SCIM `id` is the subject's canonical key (`email:alice@example.com`); the subject comes from
  the user's primary or first e-mail, else `userName` (as `iss_sub` under the issuer), else `externalId`. A user
  exists when this endpoint keeps a record of it - its `userName`, `externalId`, `active`, and the streams a
  deactivation took it off - or when any stream holds its subject, whoever put it there. An active user's `streams`
  (in the extension) are the streams holding its subject; an inactive user's are the ones a reactivation restores.
  The JDBC store keeps the records in `ssf_scim_users`; the `ldm` store keeps none yet (below).
- **`GET /Users/{id}`**, and **`GET /Users`** with `filter`, `startIndex` and `count` (at most 200 a page), answering
  a ListResponse ordered by id. The filter subset: the attributes `id`, `userName`, `externalId`, `active`,
  `emails.value` (or `emails`) and the extension's `streams`, with or without their schema URN; the operators `eq`,
  `ne`, `co`, `sw`, `ew` and `pr` (on `active`, `eq`, `ne` and `pr`); `and`, `or`, `not ( )` and brackets.
  Everything else - `gt`, `ge`, `lt`, `le`, a value path such as `emails[type eq "work"]`, another attribute - is 400
  `invalidFilter`. `userName` and e-mail addresses compare ignoring case, `id`, `externalId` and stream ids exactly
  (RFC 7643's `caseExact`).
- **`POST`** creates, adding the subject to the streams named; a user already recorded is 409 `uniqueness` (RFC 7644
  §3.3). **`PUT` replaces** (§3.5.1): an attribute the body leaves out is removed - no `userName` clears it, no SSF
  extension takes the subject off every stream - and a PUT to an id that does not exist is 404, since "HTTP PUT MUST
  NOT be used to create new resources", unless it sets `active` false (below). The body's subject must be the path's (400 `mutability`). **`PATCH`**
  applies `add`, `replace` and `remove` to `active`, `userName`, `externalId` and `streams`, and ignores attributes
  this endpoint does not keep. **`DELETE`** deactivates an active user and forgets it (204).
- **Deactivation and reactivation.** `active` true to false emits RISC `account-disabled` to the streams holding the
  subject, then takes it off them and keeps them to restore; a user already inactive emits nothing again. `active`
  false to true puts the subject back on the streams named, or those it was taken off (less any since deleted),
  and then emits `account-enabled` (RISC 1.0 §2.4: "Account Enabled signals that the account identified by the
  subject has been enabled"), so those streams hear it. A deactivation is never lost for want of a record: a
  subject with no record, on a stream or not, counts as an active user, as every `active:false` did before 0.6.0. So
  a PATCH or PUT setting `active` false, or a DELETE, for a user with no record on no stream - one provisioned before
  0.6.0 and heard about through `OIDF_SSF_DEFAULT_SUBJECTS=ALL` - emits `account-disabled`, and the PATCH or PUT
  leaves an inactive record so that a reactivation emits `account-enabled`. Any other request for such an id is 404.
- **Errors** are in the RFC 7644 §3.12 schema - `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status":"400","scimType":"invalidFilter","detail":"..."}` - as `application/scim+json`, the 401, 403 and 503 of
  token validation included (their `WWW-Authenticate` kept). The component gate's 503 and 404, the same on every SSF
  surface, are not rewritten.
- **The `ldm` store.** The Identity Object Model has no class for a SCIM user record and no attributes for the
  optional stream members, and this repo does not change the model, so the store keeps neither
  (`keepsOptionalStreamMembers` and `keepsScimUsers` are false). A stream there reports the transmitter's
  `minVerificationIntervalSeconds` and `inactivityTimeoutSeconds` - both "Transmitter-Supplied, OPTIONAL" in SSF 1.0
  §8.1.1 - and a `description` is refused with a 400, since SSF lets a transmitter truncate one ("The transmitter MAY
  truncate the string beyond an allowed max length") and not drop it. The SCIM endpoint keeps no records there: a
  user is the subject the streams hold, a deactivated user is forgotten, a second POST adds to its streams, and
  reactivating a forgotten user is a POST, which emits no `account-enabled`. The model repo (idp-scim-service) is
  asked to declare the MAY attributes and a class for the records (F-0387).

## CAEP Interop

The [CAEP Interoperability Profile 1.0](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html)
is the SSF profile the OpenID Foundation certifies against (its plan: `openid-ssf-transmitter-caep-test-plan`).
It asks three things of a transmitter beyond SSF itself, and each is a setting or an endpoint here:

- **Subjects are implicit** (§2.4.4: the receiver "MUST assume that all subjects are implicitly included in
  a Stream, without any Add Subject method invocations"). Set `OIDF_SSF_DEFAULT_SUBJECTS=ALL`. It is
  advertised as `default_subjects` and applied by the one fan-out rule, `SsfEventEmitter.subscribes`:
  enabled, delivers the type, and (member or ALL). Ownership is untouched - who manages and drains a
  stream is one question, what it hears is another.
- **Three events, with their fields** (§3): session-revoked, credential-change with `credential_type` and
  `change_type`, device-compliance-change with `previous_status` and `current_status`; `reason_admin` a
  non-empty object. `events_supported` names all three by default; PingFederate observes the first (logout,
  audit) and never the third, so the suite's run - which waits for an operator to "trigger these events on
  the transmitter now" - raises them through `POST /ssf/events:emit` with a provisioner token. The rig that
  does this, and its results, are in `pf-oidf-modules/deploy/conformance`.
- **Subjects are `email` or `iss_sub`** (§2.5; `opaque` for the verification event only), SETs RS256 with
  one event each (§2.6, §2.8.1), and a short-lived management token (§2.7.1, 60 minutes) - the last is the
  authorization server's token lifetime, not this module's.

## What the transmitter signs

Ownership left two things a receiver could still do. Together they let any holder of `ssf.manage` knock
out a user's grants at any other receiver of this transmitter that verified the signature and nothing
else: create a stream naming that receiver's `aud`, put a subject on it, deprovision the subject over SCIM
so the transmitter signs an account-disabled to that `aud`, poll it, and hand the JWS on (or point a push
stream straight at the other receiver). Three changes close it, on both sides.

**`aud` is Transmitter-Supplied.** SSF 1.0 §8.1.1: "`aud` - Transmitter-Supplied, REQUIRED. A string or an
array of strings ... that identifies the Event Receiver(s) for the Event Stream." A create that sends none
gets the caller's client id. One that sends `aud` gets it only where it is that client id, or an audience
the operator has agreed for that client in `allowedAudiences` (§8.1.1.1: "A Transmitter and Receiver MAY
agree upon the audience value out of band") - anything else, an array or a blank included, is a 400.
Every SET on a stream is signed to its `aud`, so a receiver free to pick one could have SETs minted that
another receiver accepts as its own. `ReceiverStreamClient` now sends `aud` only when given one and
refuses a stream created under a different one; pass `null` to take the transmitter's choice.

**Raising an event is a provisioner's, never a receiver's.** `/ssf/scim/v2/Users` requires
`provisionerScope`, which is unset by default - the endpoint then refuses everyone - and may not equal
`receiverScope`. A provisioner is not a receiver: it owns no streams and its assignments and deprovisions
reach every receiver's, which is what a provisioning client needs and what ownership had taken from it.
A receiver holding only `ssf.manage` gets 403 on every SCIM call, its own streams included: the
account-disabled it used to be able to raise was a signed SET about a subject of its choosing.

**A receiver runs with an audience and an endpoint token, or does not run.** `receiverAudience` and
`receiverEndpointAuthToken` were optional and unset meant unchecked - a SET was accepted on the
transmitter's signature alone, whoever it was minted for and whoever delivered it, and grants were
revoked on it. With `receiverExpectedIssuer` set and either missing, the receiver does not start (its
endpoint is 404, nothing is polled, the transmitter is unaffected) and an ERROR names the setting. The
push endpoint itself no longer has an open state: no configured token, no delivery accepted.

### Upgrading to 0.6.0

- **Strict settings**: a switch is `true` or `false`, a number a whole number, a URL an http or https URL. A value
  that does not parse makes SSF `FAILED_CONFIG` (503 on its endpoints, ERROR naming the setting) where it used to
  turn SSF off at INFO or be read as `false`. The development profile still reads `yes`/`no`/`1`/`0`/`on`/`off` for
  a switch, as `false`, with a warning.
- **`OIDF_SSF_ENABLED`, `OIDF_SSF_RECEIVER_ENABLED`**: set them in production; unset beside SSF's settings is
  `FAILED_CONFIG` naming the switch ([docs/operator/components.md](../../docs/operator/components.md)).
- **The store in production**: a PostgreSQL data store (`OIDF_SSF_DATA_STORE_ID`), or `in-memory-state` in
  `OIDF_ACCEPTED_RISKS` for the in-memory store; anything else is `REFUSED`.
- **An https issuer** in production, **a cap on streams per receiver** (10), **`OIDF_SSF_BASE_PATH` removed** and
  **SCIM `PUT` replaces** (a provisioner that sent part of a user must send all of it): [Stream management](#stream-management)
  and [SCIM](#scim).
- The whole list, with how to tell and the development escape, is in the 0.6.0 release notes (packages ST5C and
  HSSF2).

### Upgrading to this

- **Provisioning clients**: add a PF scope (`ssf.provision`), grant it to the provisioning client and to
  no receiver, and set `OIDF_SSF_PROVISIONER_SCOPE=ssf.provision`. Until then every SCIM call is 403. A
  client that drove SCIM with its `ssf.manage` token will fail. The repo's own PF configuration
  ([conformance/](../../conformance/)) carries both the scope and a provisioner client.
- **Receivers that send `aud`**: stop, or have the operator list it:
  `OIDF_SSF_ALLOWED_AUDIENCES=<client_id>=<the aud it sends>`.
- **Every deployed receiver**: set `OIDF_SSF_RECEIVER_AUDIENCE` (what it expects in `aud` - on this
  transmitter, its own client id unless agreed otherwise) and `OIDF_SSF_RECEIVER_ENDPOINT_AUTH_TOKEN`
  (and give the transmitter the same token in the stream's `authorization_header`). No known deployment
  enables the receiver today, so nothing live is affected; one that enables it without both will not start.

### Upgrading to 0.4.0

Nothing to configure. What changes on the first boot after the upgrade:

- The push loop starts with PingFederate rather than with the first management request, so a node that
  no receiver has ever managed a stream on starts delivering, and expiring, at boot.
- Held SETs on a paused or disabled stream are no longer read for push. They were never delivered before
  either; they still expire after `setTtlSeconds`, and deliver when the stream is enabled.
- A receiver that takes longer than 10 s to answer a POST, or 2 s to accept the connection, is a retryable
  failure now, and its stream dead-letters when its oldest SET has failed `pushRetryMaxAttempts` times
  (about 100 s at the defaults). Before, the loop waited for it, and for nothing else.
- A stream whose delivery fails sends nothing more until the SET that failed is due again, and then sends
  that SET first. Until 0.4.0 the SETs behind it were tried in the meantime, and could arrive first. SETs
  issued in the same second go in `jti` order, not the order they were generated in (F-0095).
- A data store that is down when PingFederate boots no longer stops `pf-runtime.war` starting - until 0.4.0
  every runtime endpoint answered 503 ([Start-up](#start-up)). Watch for `SSF transmitter NOT started` in the server
  log: the SSF endpoints answer 500 until a retry opens the store, and the logouts and audit events
  PingFederate serves in the meantime send no SET.

### Upgrading

| Store | What changes |
|---|---|
| `tables` | `owner_client_id` is added to an existing `ssf_streams` at boot - one nullable column, checked for first, so it is safe on every boot and on two nodes booting together. If it cannot be added the store does not come up, and since 0.4.0 that is a logged retry rather than a failed boot ([Start-up](#start-up)). |
| `ldm` | Nothing to apply. The owner is the `ownerClientId` attribute in `attrs`, and the entry trigger enforces MUST attributes only. The model repo should declare it a MAY attribute of `ssfStream` so `validate_entry` stops reporting it undeclared - **never a MUST**: the trigger runs on UPDATE, and the streams already there have none. It is deliberately not `clientId`, which `idm.entry` turns into its indexed `client_id` column. |
| in-memory | Nothing. Streams do not survive a restart. |

Upgrade every node that shares a store together. A node still on the old version writes streams with no
owner (`tables`) or, because it replaces `attrs` whole, strips the owner from any stream it updates
(`ldm`) - its push executor pausing one is enough.

**Streams that are already there have no owner, and by default nobody is admitted to them.** The
transmitter never recorded who created them, and every guess open to it - the `aud`, or whoever asks
first - is one a second receiver can make as well. What that means in practice:

- A **poll** stream starts answering its receiver's polls with 404. Its SETs go on queuing and are
  delivered once the stream has an owner - but only the ones younger than `setTtlSeconds` (7 days by
  default). Nothing drains the queue until then, and [SET expiry](#set-expiry) empties it from the old
  end: an event raised more than a TTL before the owner is assigned is gone, and the receiver is not
  told. Do not leave a poll stream unowned.
- A **push** stream keeps delivering. Its endpoint was set before this change and nothing new can touch
  it, but nobody can manage it either.

The transmitter counts them at boot and logs a WARN saying how many there are and who, if anyone, is
admitted to them.

**One receiver** - the usual case. Name it, and its streams carry on as they were, for that client only:

```
OIDF_SSF_UNOWNED_STREAM_OWNER=<client_id>      # or oidf.ssf.unownedStreamOwner / init-param unownedStreamOwner
```

That client is admitted to every stream with no owner, as well as to its own. It gains nothing on a stream
that has another owner, and nobody else gains anything. It is a client id and not a switch on purpose: a
switch could only put those streams back where every holder of the scope manages them. Nothing is written
to the stream, so unsetting it withdraws the access - to make it permanent, set the owner in the store
(below) and then unset it.

**Several receivers.** Do not name one of them, or it manages the others' streams. Set each stream's owner
in the store instead:

```sql
-- tables: what has no owner, and where it delivers
SELECT stream_id, audience, delivery_method, push_endpoint_url FROM ssf_streams WHERE owner_client_id IS NULL;
UPDATE ssf_streams SET owner_client_id = '<client_id>' WHERE stream_id = '<stream_id>';

-- ldm
SELECT entry_uuid, attrs->>'audience' AS audience, attrs->>'pushEndpointUrl' AS push_endpoint_url
  FROM idm.entry WHERE 'ssfStream' = ANY (object_classes) AND NOT (attrs ? 'ownerClientId');
UPDATE idm.entry SET attrs = attrs || jsonb_build_object('ownerClientId', '<client_id>')
 WHERE entry_uuid = '<stream_id>'::uuid AND 'ssfStream' = ANY (object_classes);
```

Read what that first query returns before trusting it. Until this change any receiver could repoint
another's push stream, so an unowned stream's `push_endpoint_url` is only as good as every client that has
ever held the scope.

A receiver can also just create its stream again, but that alone is not a fix: the old stream is still
there collecting events, and a push stream is still delivering them, so the receiver hears everything
twice. Remove the old one as well:

```sql
-- tables
DELETE FROM ssf_pending_sets WHERE stream_id = '<stream_id>';
DELETE FROM ssf_stream_subjects WHERE stream_id = '<stream_id>';
DELETE FROM ssf_streams WHERE stream_id = '<stream_id>';
-- ldm: its subjects and pending SETs go with it
DELETE FROM idm.entry WHERE entry_uuid = '<stream_id>'::uuid AND 'ssfStream' = ANY (object_classes);
```

## Build and deploy

```bash
mvn -pl servlets/ssf -am package     # → target/ssf-<version>.jar (tests on)
```

Versions from `bom/pom.xml`. **Not part of `oidf.war`** - `oidf-war` does not depend on this module.
It reaches production only through the `pf-runtime.war` merge: `build/pingfederate/stage-modules.sh`
stages `ssf-<version>.jar` with the other jars of its profile (its `MANIFEST` names them all), the Dockerfile injects them into the stock war (root
context, single classloader - the only place a filter can sit over PF's own `/idp/init_logout.openid`) and
copies them to the engine deploy dir. `OIDF_SSF_ISSUER` is set in the environment the PF runs with - locally, [conformance/vars.env](../../conformance/vars.env).
