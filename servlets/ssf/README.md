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
- **Auth** - every management/poll call carries a receiver bearer, validated by PF's own RFC 7662
  introspection (`PfIntrospectionReceiverAuthenticator`) and required to hold `receiverScope`. The scope
  gets a client to the endpoints, not to every stream behind them: a stream is its creator's
  ([Stream ownership](#stream-ownership)). SCIM takes a different scope, `provisionerScope`, and the
  receiver scope never opens it ([What the transmitter signs](#what-the-transmitter-signs)).

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
| `GET /.well-known/ssf-configuration`, `/ssf/.well-known/ssf-configuration` | `SsfConfigurationServlet` (`loadOnStartup=1`) | Transmitter metadata; also the servlet that bootstraps `SsfSupport` at boot, so the logout filter can emit immediately and the [push loop](#push-delivery) runs before any request arrives. |
| `POST/GET/PATCH/PUT/DELETE /ssf/streams`, `/ssf/status`, `/ssf/subjects:add`, `/ssf/subjects:remove`, `/ssf/verify` | `SsfStreamManagementServlet` | Stream Management API. `aud` is assigned from the caller's `client_id` when the create names none; `GET` without `stream_id` returns a bare array; PATCH and PUT take `stream_id` in the body (PATCH still reads the query parameter); PUT cannot change `delivery.method`; add-subject answers 200, remove-subject and verify 204. Every operation is scoped to the caller's own streams; another receiver's stream is a 404, and a create from a token naming no client a 403. |
| `POST /ssf/poll?stream_id=` | `SsfPollServlet` | RFC 8936 poll: `maxEvents` (0 = acknowledge only), `returnImmediately`, `ack`. Only the stream's owner can poll it; anyone else gets a 404 and acknowledges nothing. |
| `POST/GET /ssf/receiver/events` | `SsfReceiverServlet` | RFC 8935 receiver (`application/secevent+jwt`; 202 on accept, 400 with `err` on failure). Active only when `receiverExpectedIssuer` is set. |
| `POST/PUT/PATCH/DELETE /ssf/scim/v2/Users[/*]` | `SsfScimSubjectServlet` | SCIM 2.0 `/Users` mapping provisioning to stream membership (`urn:ietf:params:scim:schemas:extension:ssf:2.0:Subject`); `active:false`/`DELETE` emits RISC account-disabled. Bearer must hold `provisionerScope` (unset by default = 403 for everyone; the receiver scope is refused). A provisioner acts across every receiver's streams. |
| `POST /ssf/events:emit` | `SsfEventEmitServlet` | Raise an event the transmitter did not observe itself: `{"event_type", "subject", "event"?, "stream_id"?}` (`EmitRequest`). Bearer must hold `provisionerScope`, like SCIM and for the same reason - the transmitter signs a SET about a subject of the caller's choosing to every receiver. It admits nothing the emitter does not: a stream still has to subscribe (`SsfEventEmitter.subscribes`), and `stream_id` only narrows the fan-out (404 if absent). For the three interop events the subject is `email` or `iss_sub`, `reason_admin` is supplied if absent, and `credential_type`/`change_type`/`previous_status`/`current_status` take only their defined values (400 otherwise). Answers `{"event_type", "emitted":[{stream_id, jti, delivery}], "count"}`; a count of 0 is nothing subscribed, not an error. |
| filter `SsfLogoutSignal` over `/idp/init_logout.openid` | `LogoutEventFilter` | Emits CAEP session-revoked after PF processes an OIDC logout. Not annotated - registered in `pf-runtime.war`'s `web.xml` by `build/pingfederate/assemble-pf-runtime-war.sh`. Fail-open, fail-quiet: logout always proceeds. |

`LogoutEventFilter` takes the subject from an `id_token_hint`/`logout_token`, verified (`PfIdTokenVerifier`)
against this PF's own signing keys (asymmetric algorithms only; expiry is deliberately not enforced - a hint
presented at logout is routinely expired, and its age says nothing about who it names). A bare `sub` request
parameter is accepted only when a deployment opts in (`OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM=true`, for a dev rig
with no real id tokens to hand); it is refused by default, closing the earlier unauthenticated-subject finding.

Every servlet calls `SsfHttp.bootstrap` in `init()`: fail-soft. No issuer means the SSF endpoints stay
disabled and PF boots regardless - SSF must never take the runtime web application down. A store that
cannot be opened at boot is the same promise kept ([Boot](#boot)).

## Configuration

Every `SsfConfiguration` setting resolves init-param → sysprop `oidf.ssf.<name>` (PF loads `run.properties`
as system properties) → env `OIDF_SSF_<UPPER_SNAKE>`, so an image-baked PF needs no `web.xml`. Only
`issuer` is required (`OIDF_SSF_ISSUER` - the SET `iss` and the base of `jwks_uri`, so it must be the
external base receivers use).

| Group | Settings (defaults) |
|---|---|
| Transmitter | `signingAlgorithm` (RS256/PS256), `basePath` (`/ssf`), `setTtlSeconds` (7 days), `defaultEventTypes`, `defaultSubjects` (`NONE`; `ALL` = every enabled stream hears every subject without an add-subject, SSF §7.1.1, and is what [CAEP Interop](#caep-interop) needs), `verificationEventEnabled` (true), `pollMaxEvents` (100), `pushRetryMaxAttempts` (5), `pushRetryBackoffSeconds` (5) |
| Store | `dataStoreId` (PF JDBC data store id) or `jdbcUrl`+`jdbcUsername`+`jdbcPassword`; `storeDialect` (`tables` \| `ldm`); blank = in-memory |
| Receiver auth | `receiverScope` (`ssf.manage`), `provisionerScope` (unset - nobody may use SCIM; suggested `ssf.provision`, must differ from `receiverScope` or boot fails), `allowedAudiences` (`clientA=aud1,aud2;clientB=aud3` - the `aud` values a client may name on create besides its own id, see [What the transmitter signs](#what-the-transmitter-signs)), `unownedStreamOwner` (unset - see [Stream ownership](#stream-ownership)), `introspectionEndpoint` (`<issuer>/as/introspect.oauth2`), `introspectionClientId`/`introspectionClientSecret` (deployed as secrets), `introspectionInsecureTls` (false; `true` trusts any certificate chain on the introspection call through libs/platform's `InsecureTls`, which warns once - the host name is still checked) |
| Receiver | `receiverExpectedIssuer` (turns the receiver on), `receiverJwksUrl`, `receiverAudience` and `receiverEndpointAuthToken` (**both required once the receiver is on** - missing either, the receiver does not start and an ERROR says which),  `receiverJwksCacheSeconds` (300), `receiverInsecureTls` (false; `true` trusts any certificate chain on the JWKS fetch, the poll and the stream calls through libs/platform's `InsecureTls`, which warns once - the host name is still checked), `receiverPollUrl`/`receiverPollToken`/`receiverPollIntervalSeconds` (10), `receiverActionsEnabled` (true) |
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
- **A POST ends at its deadline.** Connect 2 s; 10 s for the whole exchange, body included; at most 4 KiB
  of a response body read (only a 400's body is used, for the log line). `HttpRequest.timeout` alone bounds
  the wait for the headers and nothing after them, so the exchange is waited on as a whole and cancelled
  when the deadline passes. These are constants (`PushDeliveryService.CONNECT_TIMEOUT`, `REQUEST_TIMEOUT`,
  `RESPONSE_BODY_CAP`) until S-5 makes them settings. Before this, `HttpClient.newHttpClient()` had no
  timeout at all: a receiver that accepted the connection and never answered held the thread, and every
  stream's delivery, for as long as it kept the socket open. The cancel closes the connection too, so a
  receiver that stalls every body keeps none of ours: `PushDeliveryHttpTest` has one send its status line
  and part of a body and see the socket close at the deadline, and by hand on JDK 17, 20 and 21.0.12.1 (the
  runtime of the PingFederate 13.1.3 image) the socket stayed open without the cancel and closed with it
  (2026-09-27).
- **The loop starts at boot.** `SsfSupport.start` - what every servlet's `bootstrap` runs - starts it once
  the store is open, and the first servlet to run it is `SsfConfigurationServlet`, `loadOnStartup=1`.
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

## Boot

`SsfSupport.start` never throws. It configures the transmitter (which, for the `tables` store, applies the
DDL), runs the servlet layer's wiring (the receiver's PingFederate actions and polling, the audit source),
and starts the push loop. A store that cannot be opened - the data store down at boot, the DDL refused - is
one ERROR line naming the cause, SSF endpoints that fail, and another try every 30 s
(`SsfSupport.bootRetrySeconds`, a constant until S-5) until the store opens; the loops start on the try that
succeeds. While it is down the SSF endpoints throw `IllegalStateException` on use (the container's 500, with
`SsfSupport.NOT_CONFIGURED` in the log), the same as a transmitter with no issuer, and PingFederate's own
endpoints are untouched. The events PingFederate raises in that window are lost, not queued: a logout's SET
is skipped with a WARN (`SSF session-revoked emission skipped`), the audit source is attached only once the
store opens, and a SCIM change answers 500 (F-0017; S10d). The ERROR line names the cause chain, with the
`jdbcUrl` replaced by `<jdbcUrl>` - a JDBC URL can carry a password, and the driver's messages repeat it.
The stack trace goes with the first failure only, and never for a `jdbcUrl` store. A failure no retry can
cure, such as a missing JDBC driver, is still retried: the line says what it is.

Seen on the rig on 2026-09-27 (PingFederate 13.1.3, the branch's jars at `e858f9e`), with a `tables` store on a
`jdbcUrl` whose database was started about two seconds after PingFederate: the ERROR at 03:42:28,675 UTC,
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
  every runtime endpoint answered 503 ([Boot](#boot)). Watch for `SSF transmitter NOT started` in the server
  log: the SSF endpoints answer 500 until a retry opens the store, and the logouts and audit events
  PingFederate serves in the meantime send no SET.

### Upgrading

| Store | What changes |
|---|---|
| `tables` | `owner_client_id` is added to an existing `ssf_streams` at boot - one nullable column, checked for first, so it is safe on every boot and on two nodes booting together. If it cannot be added the store does not come up, and since 0.4.0 that is a logged retry rather than a failed boot ([Boot](#boot)). |
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
