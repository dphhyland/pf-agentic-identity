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
| `GET /.well-known/ssf-configuration`, `/ssf/.well-known/ssf-configuration` | `SsfConfigurationServlet` (`loadOnStartup=1`) | Transmitter metadata; also the servlet that bootstraps `SsfSupport` at boot so the logout filter can emit immediately. |
| `POST/GET/PATCH/PUT/DELETE /ssf/streams`, `/ssf/status`, `/ssf/subjects:add`, `/ssf/subjects:remove`, `/ssf/verify` | `SsfStreamManagementServlet` | Stream Management API; starts the push-delivery loop. `aud` is assigned from the caller's `client_id` when the create names none; `GET` without `stream_id` returns a bare array; PATCH and PUT take `stream_id` in the body (PATCH still reads the query parameter); PUT cannot change `delivery.method`; add-subject answers 200, remove-subject and verify 204. Every operation is scoped to the caller's own streams; another receiver's stream is a 404, and a create from a token naming no client a 403. |
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
disabled and PF boots regardless - SSF must never take the runtime web application down.

## Configuration

Every `SsfConfiguration` setting resolves init-param → sysprop `oidf.ssf.<name>` (PF loads `run.properties`
as system properties) → env `OIDF_SSF_<UPPER_SNAKE>`, so an image-baked PF needs no `web.xml`. Only
`issuer` is required (`OIDF_SSF_ISSUER` - the SET `iss` and the base of `jwks_uri`, so it must be the
external base receivers use).

| Group | Settings (defaults) |
|---|---|
| Transmitter | `signingAlgorithm` (RS256/PS256), `basePath` (`/ssf`), `setTtlSeconds` (7 days), `defaultEventTypes`, `defaultSubjects` (`NONE`; `ALL` = every enabled stream hears every subject without an add-subject, SSF §7.1.1, and is what [CAEP Interop](#caep-interop) needs), `verificationEventEnabled` (true), `pollMaxEvents` (100), `pushRetryMaxAttempts` (5), `pushRetryBackoffSeconds` (5) |
| Store | `dataStoreId` (PF JDBC data store id) or `jdbcUrl`+`jdbcUsername`+`jdbcPassword`; `storeDialect` (`tables` \| `ldm`); blank = in-memory |
| Receiver auth | `receiverScope` (`ssf.manage`), `provisionerScope` (unset - nobody may use SCIM; suggested `ssf.provision`, must differ from `receiverScope` or boot fails), `allowedAudiences` (`clientA=aud1,aud2;clientB=aud3` - the `aud` values a client may name on create besides its own id, see [What the transmitter signs](#what-the-transmitter-signs)), `unownedStreamOwner` (unset - see [Stream ownership](#stream-ownership)), `introspectionEndpoint` (`<issuer>/as/introspect.oauth2`), `introspectionClientId`/`introspectionClientSecret` (deployed as secrets), `introspectionInsecureTls` |
| Receiver | `receiverExpectedIssuer` (turns the receiver on), `receiverJwksUrl`, `receiverAudience` and `receiverEndpointAuthToken` (**both required once the receiver is on** - missing either, the receiver does not start and an ERROR says which),  `receiverJwksCacheSeconds` (300), `receiverInsecureTls`, `receiverPollUrl`/`receiverPollToken`/`receiverPollIntervalSeconds` (10), `receiverActionsEnabled` (true) |
| Sources | `auditEventsEnabled` (true), `auditEventMap` |
| Kafka | `kafkaEnabled` (false), `kafkaBootstrapServers`, `kafkaTopic` (`sse-events`), `kafkaSecurityProtocol` (`PLAINTEXT`), `kafkaSaslMechanism`/`kafkaSaslUsername`/`kafkaSaslPassword` |

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

### Upgrading

| Store | What changes |
|---|---|
| `tables` | `owner_client_id` is added to an existing `ssf_streams` at boot - one nullable column, checked for first, so it is safe on every boot and on two nodes booting together. If it cannot be added the store does not come up. |
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
stages `ssf-<version>.jar` with the other eight jars, the Dockerfile injects them into the stock war (root
context, single classloader - the only place a filter can sit over PF's own `/idp/init_logout.openid`) and
copies them to the engine deploy dir. `OIDF_SSF_ISSUER` is set in the environment the PF runs with - locally, [conformance/vars.env](../../conformance/vars.env).
