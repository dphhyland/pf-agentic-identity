# openid-federation

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Absorbed with history from [`dphhyland/openid-federation`](https://github.com/dphhyland/openid-federation) (its `draft-10-pop-methods` branch) on 2026-07-21; that repo is backports-only and its copy still uses the pre-split `.common` package. See [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

**OpenID Federation 1.0** building blocks: trust-chain resolution and validation with `metadata_policy`
applied, the federation entity/statement service, a trust-controller gateway, the AS-side federation
client-authorisation decision, and — in the `authority` package — the hosted-entity registry a Domain
Authority publishes federation metadata from on behalf of entities that cannot host their own.
Packages `com.pingidentity.ps.oidf.federation` and `com.pingidentity.ps.oidf.authority`. Depends on
`oidf-jose` and the servlet API (provided); the JDBC driver is provided by the deployment. No
PingFederate — the PF signer, the `OpenIdFederationServlet` transport and the OGNL hooks live in
`servlets/pf-integration`.

## `federation` — resolving and serving

- **`TrustAnchor`** — the anchor a validator is built with: its entity identifier plus its public
  Federation Entity Keys, supplied out of band (§4). Public keys only, each with a unique `kid`
  (§3.1.1); a private or symmetric key is refused. There is no constructor that takes an identifier
  alone - an anchor without pinned keys is whoever answers HTTPS at that URL.
- **`TrustAnchorSet`** — the anchors a validator trusts, in preference order, each with its own pinned
  keys. A caller may ask for particular anchors (the resolve endpoint's `trust_anchor`) but can never add
  one the deployment does not trust.
- **`TrustChainValidator`** — establishes trust in an entity (§10): collects the statements linking it to
  one of the configured anchors, starting from any it was handed, then validates the chain and resolves
  the entity's metadata. The search tries the configured anchors first, follows at most ten
  `authority_hints` per entity, never revisits an entity on the path, and spends one resolution budget - a
  wall clock and a number of requests, below - across the whole validation (§18.1). A request can spend less
  than that budget: `ValidationRequest.maxFetches(0)`
  validates the statements it was handed and nothing else, which is how a chain someone other than its subject
  presents is checked without letting them choose what gets fetched. Every statement passes the §3.2 checks (`EntityStatementChecks`: claims,
  `crit`, which claims may appear where, key sets, `aud`, chain headers) and is verified with the keys the
  statement above it asserts; the anchor's own statement with its pinned keys; the subject's configuration
  with its own keys as well. A route that fails does not end the search, so an entity in two federations
  resolves through whichever validates. Resolution applies the immediate superior's `metadata`, then every
  statement's `constraints` (`Constraints`, §6.2), then the merged `metadata_policy`. A statement's
  `metadata_policy` is checked for its shape with the other claims, but its operators are parsed only once every
  statement on the route has verified, so nothing an unverified statement says is interpreted, and a policy that does
  not parse fails the chain after the signature check, never before it (§10.2: "After the preceding validation,
  metadata MUST be resolved to the subject of the Trust Chain"). The result carries the
  chain in §4 shape, when it expires (§10.4), and the resolved metadata per entity type. Every refusal is a
  `TrustChainValidationException` naming the check and the statement, with the §8.9 error it maps to.
- **`MetadataPolicy`** — `metadata_policy` merging and application exactly as the Final text defines them:
  each operator's action, order, merge rule, allowed combinations and JSON types; `scope` as an array;
  additional operators ignored unless critical. The §6.1.5 worked example reproduces the specification's
  own results. [docs/unverified.md](../../docs/unverified.md) §11 records what an earlier version got wrong.
- **`TrustMarkValidator`** — which of an entity's Trust Marks are valid (§7.3), against the anchor its chain
  reached. A mark counts when it is a signed `trust-mark+jwt` naming its key, it is about this entity, the
  anchor's `trust_mark_issuers` accepts its issuer for its type (`[]` lets anyone, the entity included), the
  issuer's own chain reaches the same anchor, its signature verifies with the issuer's key, it is current (no
  `exp` means it does not expire, §7.1), and - where the anchor's `trust_mark_owners` names an owner for the
  type - it carries a delegation from that owner that validates (§7.2.2). Given a POST client it also asks
  the issuer's status endpoint (§8.4), and anything but `active` rejects the mark. A rejected mark never
  costs the entity its chain. The anchor's configuration comes from the end of the chain, or is resolved
  against the pinned keys when the chain stops short of it. Each issuer is resolved once per validation, at
  most eight of them, and at most sixteen marks are examined (§18.1). The whole validation spends one resolution
  budget: the caller's (`validate(chain, budget)`), or one made from the issuers' validator's options.
- **`TrustMarkPolicy`** — the marks a deployment requires before it registers an entity, by Entity Type
  (`{"*": [...], "openid_relying_party": [...]}`); every mark listed is required, and only a verified one counts.
- **`TrustControllerGateway` / `HttpTrustControllerGateway`** — fetch entity configurations, member lists
  and subordinate statements (resolving each authority's `federation_fetch_endpoint`), over a bounded LRU
  **`SubordinateStatementCache`** with expiry-buffer and max-age eviction, keyed on the two identifiers'
  `EntityId.comparable` forms so either spelling of one entity is one entry; writes are staged as `PendingWrites` and
  committed only once a chain validates, and only the validated route's: its statements and the Entity
  Configurations of the entities they name. A statement fetched on a route the search abandoned is dropped with the
  walk, so it can never answer a later resolution from the cache. The validator binds its anchors to the
  gateway, which verifies each anchor's entity configuration against that anchor's pinned keys before
  using its fetch endpoint (§10.2), and retrieves it once more before refusing on a mismatch (§11.3). Within a
  resolution each of those requests is paid for from the resolution's budget and made by its deadline.
- **`FederationService`** — this entity's statements and federation endpoints: its entity configuration
  (advertising fetch and list only when it has subordinates, resolve only when a resolver is configured,
  and the registration types it accepts), subordinate statements for `fetch` (§8.1, by `sub`, naming their
  `source_endpoint`; the subordinate's own keys — fetched and cached for a foreign subordinate, looked up
  uncached from the hosted registry so a revocation bites on the next call), `list` with its filters
  (§8.2), and `resolve` (§8.3): a signed `resolve-response+jwt` whose chain ends with the anchor's
  configuration, carrying the subject's verified Trust Marks and expiring with the first of them if that is
  sooner than the chain (§8.3.2). Its resolver answers for this entity's own statements in-process
  (`LocalFirstTrustControllerGateway`) rather than fetching its own URL. RS256/PS256 through
  `SigningKeyProvider`. Given a **`TrustMarkIssuing`** it is also a Trust Mark Issuer: the Trust Mark
  endpoint (§8.6), the status endpoint (§8.4) and the Trust Marked Entities Listing (§8.5), advertised in its
  `federation_entity` metadata, the list endpoint's `trust_marked` and `trust_mark_type` filters, and the marks it
  issues itself in its own `trust_marks`. As a trust anchor it publishes `trust_mark_issuers` (naming itself for
  the types it issues) and `trust_mark_owners`. Given **`HistoricalKeys`** it answers the historical keys endpoint (§8.7):
  a signed `jwk-set+jwt` of the keys it signed with before. Given an **`EndpointAuthPolicy`** (§8.8: each endpoint
  `none`, `optional` or `required`, published as its `_auth_methods`) it tells its caller who a request's client is:
  **`EndpointClientAuthentication`** checks a `private_key_jwt` assertion - `iss` = `sub` = the client, `aud` this
  entity and nothing else, an `exp` at most ten minutes off, a `jti` spent once and remembered until then - against the
  keys the client's Entity Configuration publishes, once its chain has validated to an anchor the resolver trusts,
  eight look-ups at a time. So client authentication needs a resolver.
- **`ResolveGuard`** - the resolve endpoint's cap and cache (below).
- **`FederationConfiguration` / `AttestationMetadataConfig`** — parsed from servlet init-params (below).
  The latter is the `openid_provider` attestation capability set the entity configuration advertises:
  auth methods, per-JWT algorithm lists, `attestation_pop_jwt` + `dpop_combined`, challenge endpoint.

### This entity's `authority_hints`

OpenID Federation 1.0 §3.1.2 (Final, February 2026) on `authority_hints`: "This Claim is REQUIRED in Entity
Configurations of the Entities that have at least one Superior above them, such as Leaf and Intermediate Entities. Its
value MUST contain the Entity Identifiers of its Immediate Superiors and MUST NOT be the empty array []. This Claim MUST
NOT be present in Entity Configurations of Trust Anchors with no Superiors."

This entity's superiors are its configured trust anchors (`OIDF_FEDERATION_TRUST_ANCHORS`). The rule, in
`FederationService.authorityHints`:

- when this entity is one of those anchors (compared with `EntityId.same`) it is a Trust Anchor, and nothing in its
  configuration names a superior of it: no `authority_hints`;
- otherwise its Entity Configuration names each configured anchor once, in the order configured;
- an entity with none configured publishes none - never `[]`.

`/.well-known/openid-federation` and the non-standard `/federation/entity?sub=<this entity>` serve the same Entity
Configuration, so the two cannot disagree (plan item H-FED-8). Before 0.6.0 the second always carried the configured
list, `[]` and this entity itself included.

### The resolve endpoint's cap and cache

§18.1 names the resolve endpoint first among the interfaces that "could be used for Denial-of-Service attacks", and
says an unauthenticated one "should only respond to unauthenticated Client requests with cached information about
Entities that have already been evaluated". Two settings of the `federation-resolution` catalogue
([its page](../../docs/configuration/federation-resolution.md)) bound it (plan item H-FED-9):

- **`OIDF_FEDERATION_RESOLUTION_RESOLVE_SUBJECTS_PER_MINUTE`** (30): one caller address is answered about at most this
  many distinct subjects in any minute. One more is `503 temporarily_unavailable` (§8.9: "unable to handle the request
  due to temporary overloading") with a `Retry-After` of the seconds until its oldest subject leaves the minute; a
  subject already counted costs nothing more - even asked with other trust anchors or entity types, each of which
  misses the cache and resolves again, so the cap bounds distinct subjects, not resolutions (F-0383). The address is the connection's (`getRemoteAddr()`), so every client
  behind one proxy shares one minute.
- **`OIDF_FEDERATION_RESOLUTION_RESOLVE_CACHE_SECONDS`** (60, at most 60; 0 keeps none): a resolve response is kept this
  long, or until its own `exp` if that is sooner, and answers the same request - subject, trust anchors, entity types
  and the client it is addressed to - without resolving again.

The resolution budget below still bounds what each resolution costs.

### The resolution budget

One trust chain resolution spends one `ResolutionBudget` (plan item S5b): a wall clock, counted from when the
resolution starts, and a number of requests, over platform's `Budget` ([libs/platform](../platform/README.md#http)).
Spending is thread-safe.

- **What spends it.** The validator pays one request for every statement it asks its gateway for, from the cache
  or not, as the fetch budget did before. `HttpTrustControllerGateway` pays one more for every further request it
  makes to answer: an authority's Entity Configuration that is neither cached nor staged, which it needs for the
  fetch endpoint, and the second retrieval of an anchor's Entity Configuration that did not verify (§11.3). One
  statement can cost three requests, and each is counted, so a resolution never makes more requests than its
  budget holds, whatever shape the chain has. A `peer_trust_chain` is resolved from a child of the same budget
  (`ResolutionBudget.child`), and `TrustMarkValidator` resolves the anchor's configuration and each issuer from
  children of its budget and spends one request on each status call.
- **The wall clock.** Every request is made by the budget's deadline: `HttpGetClient.get(url, accept, deadline)`
  and `HttpPostClient.post(..., deadline)`, which `JdkHttpClient` holds to the sooner of the deadline and its own
  15 s request timeout, the body included. A slow peer's body spends the resolution's time, not a fresh timeout.
- **Where a budget comes from.** A caller may pass one on `ValidationRequest.budget(...)` - a registration that
  wants its chain and its Trust Marks held to one budget - and the validation spends from a child of it holding
  at most the request's `maxFetches`. Otherwise the validation makes one from its `ValidatorOptions`.
  `FederationService.resolve` and the registration paths still validate a chain and then its Trust Marks on two
  budgets; S5c passes one budget through registration (finding [F-0280](../../docs/findings/F-0280.yaml)).
- **What a refusal says.** A resolution that runs out is refused as a `TrustChainValidationException` of kind
  `BUDGET`, answered as `invalid_trust_chain`, whose description says what ran out and what the budget allowed
  ("ran out of time: its wall-clock budget of 45000 ms is spent", "ran out of requests: its budget of 24 requests
  is spent") and never names what was being fetched, which a peer chose. When a caller's budget ran out rather
  than the validation's own share of it, the description names the caller's cap. The search-step bound
  (`MAX_SEARCH_STEPS`) is refused with the same kind and says so ("took more than 128 steps"). The validator logs a
  WARN naming the subject (through `LogSafe`), how long it took, how many requests it spent, the refusal's own
  description and the two settings; at DEBUG it logs each resolution that succeeds, with its time and requests.
- **A gateway that does not know budgets.** The budget travels as a trailing parameter on
  `TrustControllerGateway`'s fetch overloads, whose defaults forward to the overloads without it, so every
  existing gateway and caller compiles and behaves as before. Such a gateway is still held to one request per
  statement asked for; the requests it makes inside a call are its own to bound. `LocalFirstTrustControllerGateway`
  answers this deployment's own statements with no request and passes the budget to its delegate.
- **What the budget does not bound.** Name resolution and writing a request have no timeout in the JDK
  ([U-0195](../../docs/findings/U-0195.yaml)). A lookup is short enough: `OutboundHttp` refuses to start a request
  once its deadline has passed, and on the pinned image's java 21.0.12.1 a lookup against a resolver that never
  answers gave up after 5.05 s (2026-09-29) and 5.02 s (2026-09-30). A write is not: it waits on a peer that does
  not read once the body outgrows the connection's send buffer, which on a 1500-MTU Linux link starts at 46,080
  bytes. On 2026-09-30, between two containers on such a link, the first 1 KiB write to wait on a peer that never
  read came after 14,336 bytes when that peer shrank its receive buffer to the least it could, and a 9 KiB write
  returned at once however small the peer made it. Every request a resolution makes is a GET but one, the Trust
  Mark status call (§8.4), whose body is the mark - chosen by whoever issued it, the entity itself for a
  self-issued mark. So `TrustMarkValidator` rejects a mark larger than `MAX_STATUS_MARK_BYTES` (8192) rather than
  send it, its reason saying so, and a resolution overruns its wall clock by at most one lookup, about 5 s. Other
  `OutboundHttp` writes above about 14 KiB stay unbounded; U-0195 stays open for them.

**The settings.** `ValidatorOptions.defaults()` reads the `federation-resolution` catalogue
([docs/configuration/federation-resolution.md](../../docs/configuration/federation-resolution.md)), so every
validator built with it follows them: `OIDF_FEDERATION_RESOLUTION_WALL_CLOCK_SECONDS` (45, 1 to 300),
`OIDF_FEDERATION_RESOLUTION_MAX_REQUESTS` (24, 1 to 256), `OIDF_FEDERATION_RESOLUTION_MAX_AUTHORITY_HINTS` (10, 1 to
64), `OIDF_FEDERATION_RESOLUTION_MAX_ROUTE_ATTEMPTS` (8, 1 to 64) and `OIDF_FEDERATION_RESOLUTION_CLOCK_SKEW_SECONDS`
(60, 0 to 300). A value out of its range is refused, naming the setting, when a validator is built. These are
tuning: how much work one resolution is worth depends on the federations a deployment joins. The constants that
stay constants are safety bounds, which hold whatever the tuning says: `TrustChainValidator.MAX_ROUTE_STATEMENTS`
(16 Subordinate Statements on one route) and `MAX_SEARCH_STEPS` (128 statements added to routes, which bounds the
work presented statements cause at no request at all), and `TrustMarkValidator.MAX_MARKS_EXAMINED` (16) and
`MAX_ISSUERS_RESOLVED` (8), and `MAX_STATUS_MARK_BYTES` (8192, the largest mark sent to a status endpoint, sized
from the send-buffer measurement above). Nothing measured says they must move.

**The measurement behind the wall clock** (2026-09-29, this branch, `DEBUG` on `TrustChainValidator`). On the
conformance rig (`PF_PROFILE=federation-op`, PingFederate 13.1.3, the suite at release-v5.3.1 on the same Docker
host), the successful resolutions took 179 ms (the suite's relying party, 4 requests, cold, plan `g3wLhsJueO2zv`),
85 ms (the same relying party with the next run's keys, plan `kP63AXqiOpCZx`) and 5 ms (PingFederate's own chain,
plan `xyVeQDsQoS533`). Three times the longest is 0.54 s, which would round to 1 s. That is loopback: against a
federation on the internet, this validator, fetching from this machine (in Australia) the chains of ten entities
chosen at random from the list of the Italian public-sector anchor `https://oidc.registry.servizicie.interno.gov.it`,
spent 4.3 s to 14.5 s on each of eight before `EntityStatementChecks` refused it, every `trust_marks` entry carrying
`id` where the check looks for `trust_mark_type`; the other two stopped at 2.2 s and 9.7 s on leaves that did not
answer. A single fetch of the anchor's configuration took 1.3 s, 1.0 s of it the TLS handshake. A 1 s default would refuse every one of those chains on the network time alone, so the default is
three times the longest of them, 14.5 s, rounded: **45 s**. It is a ceiling on a request thread, not a target:
before it a resolution could hold one for up to 24 requests of 15 s each.

## `authority` — hosting entities

- **`HostedEntity`**, **`HostingMode`** (`AUTHORITY_SIGNED`: the authority holds a dedicated per-entity
  key and the entity's own runtime key never appears in federation metadata; `SELF_SIGNED`: modelled,
  not yet implemented), **`EntityStatus`** (`ACTIVE` / `SUSPENDED` / `REVOKED` — only `ACTIVE`
  resolves; revocation is permanent).
- **`HostedEntityRegistry`** — `InMemoryHostedEntityRegistry` (tests, single node) or
  **`JdbcHostedEntityRegistry`** over `db/migration/V100__hosted_entity.sql` and `V101__hosted_entity_actor.sql`:
  `hosted_entity` plus an append-only `hosted_entity_audit_log` that records who made each change, written in the
  same transaction as the change; JSON stored as text rather than as a database-specific JSON type. A status change
  applies only to the status it read (`UPDATE ... WHERE entity_id = ? AND status = ?`, the row count checked): of two
  operators suspending, reactivating or revoking one entity at once, the second to commit is refused `STALE_UPDATE`
  (409 `stale_update` at the admin API) and writes nothing, its audit line included (plan item H-FED-3). The admin
  API decides on the entity it read and passes that status in (`setStatus(id, expected, status, ...)`), so of two
  operators who both read it active and revoke it, the second is refused however far apart the two requests
  arrive. Asking for the status an entity already has changes nothing and succeeds, as before. The in-memory registry
  holds a lock from what it reads to what it writes, so its changes never overlap.
  Numbered V100 so it never collides with `agent-registry`'s V200 on the shared classpath (both land on
  `servlets/attestation-issuer`); `device-instance` uses a separate, non-Flyway IDM/SCIM migration
  scheme, so it isn't part of this numbering at all.
- **`HostedEntitySigner` / `RegistryHostedEntitySigner`** — resolves an entity's `hostingKeyRef` to an
  `OpenBaoTransitSigner` on one deployment-wide vault; **`HostedEntityConfigurationBuilder`** signs the
  entity configuration with it (60 min lifetime), with the Trust Marks this authority issues the entity.
  **`HostedEntityConfigurationCache`** keeps a signed configuration while more than three quarters of its lifetime
  remains - its first 15 minutes - for the exact registry record it was built from, and drops it when this process
  changes the entity or grants or revokes a Trust Mark to it (plan item H-FED-9). A change made on another node is
  seen at once for the entity itself (its record differs) and within those 15 minutes for its Trust Marks. The
  lifetime counted ends at the earlier of the configuration's `exp` and that of the first Trust Mark it carries to
  expire, so a configuration with a five-minute mark is renewed after 75 seconds and never serves a mark past its `exp`.
  **`AuthoritySupport`** holds the process-wide registry, signer, domain-default policy and Trust Mark lookup so
  every servlet shares one state across classloaders. Nothing is looked up before hosting is configured, so a
  request that arrives first cannot leave the in-memory fallback in place of the durable registry.

## `trustmark` — issuing Trust Marks

- **`TrustMarkType`** — a type this entity issues, parsed from the operator's JSON: its lifetime, whether it
  goes to hosted entities only (the default) or to anyone granted it, and the `delegation`, `ref` and `logo_uri`
  its marks carry.
- **`TrustMarkGrant`**, **`TrustMarkRegistry`** — who is granted which type, until when, by whom:
  `InMemoryTrustMarkRegistry` or **`JdbcTrustMarkRegistry`** over `db/migration/V102__trust_mark.sql`
  (`trust_mark_grant` plus an append-only `trust_mark_audit_log`, each change and its audit line in one
  transaction). Granting again starts a grant afresh. Revoking, and granting again, apply only to the grant read
  (its status and `granted_at` in the `WHERE`), and a first grant racing another finds the row there: the second of two
  such changes is `STALE_UPDATE` and writes nothing (plan item H-FED-3); the admin API revokes the grant it read
  (`revoke(expected, ...)`), so a revocation decided on a grant revoked or given again since is refused too. `standing(type, subject, now)` reads the
  grants of a type that stand, to one subject or to anyone, in one query. **`TrustMarkSupport`** holds the process-wide
  one.
- **`TrustMarkIssuer`** — the issuing decisions behind `FederationService`: a mark only under a grant that stands
  and, for a hosted-only type, to an active hosted entity; `exp` never past the grant's end. No mark is recorded:
  its status is its signature plus its grant - revoked, or granted again since it was minted, is `revoked`; past
  its `exp` or its grant's end, `expired`; no grant, unknown (404). `marked` (§8.5) is one registry query for a type
  and a subject, or a whole type; for a hosted-only type each subject it returns is then checked to be an active hosted
  entity.
- **`TrustMarkClaims`** — the claims an operator has this entity publish (`trust_marks` it carries from other
  issuers, `trust_mark_issuers`, `trust_mark_owners`), held to the shape a receiving entity's statement checks
  demand.

## `keyhistory` — the keys this entity signed with before

- **`HistoricalKey`** — a retired key: its public JWK, when it began to be used, its `exp`, and when and why it was revoked
  (§8.7.3's `unspecified`, `compromised`, `superseded`), rendered as §8.7.2 wants it.
- **`KeyHistoryStore`** — the key in use and the retired ones: `InMemoryKeyHistoryStore` or **`JdbcKeyHistoryStore`** over
  `db/migration/V103__federation_key_history.sql`. A rotation - the old key retired, the new one recorded - is one step;
  a retired key that signs again is no longer history, and a revoked one is refused. A revocation applies only to a key
  still unrevoked when read (`WHERE revoked_at IS NULL`): of two at once, the second is `STALE_UPDATE` and the first's
  reason stands (plan item H-FED-3). `KeyHistory.revoke` returns a key already revoked as it is, announcing nothing,
  and revokes one it read unrevoked only while it still is (`revokeUnrevoked`). **`KeyHistorySupport`** holds the process-wide store.
- **`KeyHistory`** — what the endpoint publishes, the rotation check made at start-up (a retired key stays valid for a
  grace period, so what it signed can be checked until it expires), and revocation.

This entity publishes its history; it does not read other entities'. A chain this validator checks is live, and a
statement signed with a key since rotated is fetched again rather than checked against a historical key.

## `federation.policy` — asking a policy decision point

The federation says who an entity is and what its superiors allow it. Whether this deployment wants it is a
question for a policy engine, and this package is how one is asked - with no PingFederate in it.

- **`FederationPolicyDecisionPoint`** — `decide(PolicyDecisionRequest)` returns a **`PolicyDecision`**: permitted or not,
  the reasons (`reason_admin` for the logs, `reason_user` fit to show the caller), and what a permit narrows. It throws
  **`PolicyDecisionException`** only when no decision could be had - never as a denial.
- **`PolicyDecisionRequest`** — one question, rendered as an AuthZEN 1.0 Access Evaluation request: the subject is always
  the `federation_entity` the request is about, never a user; the action is the **`DecisionPoint`**'s
  (`federation.register.explicit`, `federation.register.automatic`, `federation.hosted_entity.enrol`). A `request`
  member of its context holds what belongs to one request only, and is left out of the cache key.
- **`NarrowingObligations`** — what a permit may do to a registration: keep only some of the scopes, grant types and
  response types it asked for, end it sooner, require Trust Marks. Applied to a **`ClientDraft`** - the registration
  with every default already in - so it can only take away. Two sets of obligations combine by intersection.
- **`AuthZenFederationPolicyDecisionPoint`** — the AuthZEN client: POST JSON with `X-Request-ID`; only a 200 with a
  boolean `decision` is a decision (§10.1.2); the evaluation endpoint at the default path, configured outright, or read
  from the PDP's `/.well-known/authzen-configuration` with the §9.2.3 identifier check - read again once ten minutes
  have passed, so a PDP that moves its endpoint is followed; a read that fails is no decision, and the next request
  tries again (plan item H-FED-9). Context it doesn't understand
  is listed as ignored, or refuses the permit when the deployment says so (§5.5).
- **`LocalFederationPolicyDecisionPoint`** (an allow-list of scopes), **`CompositePolicyDecisionPoint`** (local first; a
  local refusal is final, and both permits' obligations apply), **`CachingPolicyDecisionPoint`** (permits and denials
  for a while, keyed on a hash of the request; failures never).

## `federation.event` - the event codes

`FederationEvents` names the federation's event codes, and `META-INF/oidf-events/federation.json` in this module
catalogues them: what each records, whether it belongs in the audit log, its outcomes, its level and the fields it may
carry, each field with one PII class (plan item O-1). Events themselves now live in `libs/platform`'s
`platform.events` ([its README](../platform/README.md#events)); `FederationEvent`, `FederationEvents`,
`FederationEventSink`, `LoggingEventSink` and `LogSafe` here are façades over it, kept so the emitters compile
unchanged, deprecated for removal when plan item O-2 (Phase 3) moves them. A field an emitter adds that the
catalogue does not declare for its code is dropped before any sink sees it, so a new field means a catalogue
entry: `EventsCataloguedTest` in `servlets/pf-integration` scans every emitter in the reactor and fails on an
uncatalogued code or field, and on a catalogued code nothing emits unless the catalogue marks it `declaredOnly`
(eleven are). What an operator sees is in
[docs/federation/operations.md](../../docs/federation/operations.md#reading-the-logs).

## Configuration

The anchors' pinned keys are not a `FederationConfiguration` setting: they are passed to
`TrustChainValidator` as a `TrustAnchorSet`, which `servlets/pf-integration` and `servlets/attestation-issuer` both
build from `OIDF_FEDERATION_TRUST_ANCHOR_JWKS` (`OIDF_TRUST_ANCHOR_JWKS` is its superseded name).
`tools/pin-trust-anchor.py` captures them. Every setting the federation reads, with its default and what happens
when it's wrong, is in [docs/federation/configuration.md](../../docs/federation/configuration.md).

`FederationConfiguration.fromServletConfig` reads each setting through its entry in the `federation-entity` settings
catalogue ([docs/configuration/federation-entity.md](../../docs/configuration/federation-entity.md), plan item ST-5):
the init-param first, then the environment variable, every value parsed strictly - a switch that is not `true` or
`false`, a number past an `int`, a list of nothing or a choice not listed stops the servlet starting (FEDERATION
`FAILED_CONFIG`), naming the setting; under development a legacy spelling such as `yes` is read as the reader before
0.6.0 read it, with a warning. The settings: `trustAnchorIssuers` / `OIDF_FEDERATION_TRUST_ANCHORS` (required; each
an Entity Identifier, an https URL with a host and no query, fragment or user info, or the servlet does not start;
an issuer is matched to one with or without a trailing slash and whatever the case of its scheme and host),
`subordinates` / `OIDF_FEDERATION_SUBORDINATES`, `ignoreSslErrors` / `OIDF_FEDERATION_IGNORE_SSL_ERRORS` (one setting
for every reader: the init-param, then the system property `oidf.federation.ignore.ssl.errors`, the environment
variable and the superseded `OIDF_TRUST_CONTROLLER_IGNORE_SSL` - `FederationRuntimeConfig` in pf-integration reads
the same entry, without the init-param, so the two cannot disagree; F-0197), `signingAlgorithm` /
`OIDF_FEDERATION_SIGNING_ALG` (RS256 or PS256, in any case), `attesterJwks` / `OIDF_FEDERATION_ATTESTER_JWKS` (public keys only - it is published, so anything else is
refused), `organizationName` /
`OIDF_FEDERATION_ORGANIZATION_NAME`, `clientRegistrationTypes` / `OIDF_FEDERATION_CLIENT_REGISTRATION_TYPES`
(what `client_registration_types_supported` advertises; default `automatic,explicit`, `none` for neither),
`resolveDiscovery` /
`OIDF_FEDERATION_RESOLVE_DISCOVERY` (`known`, the default: resolve only this entity, its subordinates and
the entities it hosts, as §18.1 advises for an unauthenticated resolver; `any`: discover on demand).
Init-param only: CORS (`corsEnabled`,
`corsAllowOrigin`, `corsAllowMethods`, `corsAllowHeaders`, `corsMaxAge`) and the
`AttestationMetadataConfig` lists (`tokenEndpointAuthMethodsSupported`,
`clientAttestationSigningAlgValuesSupported`, `clientAttestationPopSigningAlgValuesSupported`,
`dpopSigningAlgValuesSupported`, `clientAttestationPopMethodsSupported`, `attestationChallengeEndpointEnabled`).
`clientAttestationFormatsSupported` is read and has no effect. `trustControllerHost` was read and had none either (the
controller is `FederationRuntimeConfig`'s); from 0.6.0 it is a removed name, and the servlet does not start while it
is set.

`RegistryHostedEntitySigner.fromEnvironment()` reads the vault through the `hosted-entity-signing` entries
`OIDF_OPENBAO_URL` and `OIDF_OPENBAO_TOKEN` - the system property (`oidf.openbao.url`, `oidf.openbao.token`), then
the environment variable, then the superseded `OPENBAO_ADDR` / `BAO_ADDR` / `VAULT_ADDR` and `OPENBAO_TOKEN` /
`BAO_TOKEN` / `VAULT_TOKEN` with a warning; a superseded name that holds another value is refused, and the token may
come from the file `OIDF_OPENBAO_TOKEN_FILE` names. `attestation-issuer` reads the same two entries, so one vault
serves both.

## Build

```sh
mvn -pl libs/openid-federation -am package     # or `mvn package` at the repo root; tests run with the build
```

The JDBC tests run the federation family's shipped migrations (V100-V103) on PostgreSQL, in a database of
their own (`libs/testkit`; see [CONTRIBUTING.md](../../CONTRIBUTING.md#tests-that-need-postgres)). `LiveChainValidationTest` is
skipped unless a captured chain is present at `/tmp/live-chain`. Versions come from `bom/pom.xml`.
Consumers, by pom: `servlets/pf-integration`, `servlets/attestation-issuer`. Ships into PingFederate via
`build/pingfederate/stage-modules.sh` (pf-runtime.war merge) and inside `oidf.war`
(`servlets/oidf-war`).
