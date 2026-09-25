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
  `authority_hints` per entity, never revisits an entity on the path, and spends one fetch budget across
  the whole validation (§18.1). A request can spend less than that budget: `ValidationRequest.maxFetches(0)`
  validates the statements it was handed and nothing else, which is how a chain someone other than its subject
  presents is checked without letting them choose what gets fetched. Every statement passes the §3.2 checks (`EntityStatementChecks`: claims,
  `crit`, which claims may appear where, key sets, `aud`, chain headers) and is verified with the keys the
  statement above it asserts; the anchor's own statement with its pinned keys; the subject's configuration
  with its own keys as well. A route that fails does not end the search, so an entity in two federations
  resolves through whichever validates. Resolution applies the immediate superior's `metadata`, then every
  statement's `constraints` (`Constraints`, §6.2), then the merged `metadata_policy`. The result carries the
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
  most eight of them, and at most sixteen marks are examined (§18.1).
- **`TrustMarkPolicy`** — the marks a deployment requires before it registers an entity, by Entity Type
  (`{"*": [...], "openid_relying_party": [...]}`); every mark listed is required, and only a verified one counts.
- **`TrustControllerGateway` / `HttpTrustControllerGateway`** — fetch entity configurations, member lists
  and subordinate statements (resolving each authority's `federation_fetch_endpoint`), over a bounded LRU
  **`SubordinateStatementCache`** with expiry-buffer and max-age eviction; writes are staged as
  `PendingWrites` and committed only once a chain validates. The validator binds its anchors to the
  gateway, which verifies each anchor's entity configuration against that anchor's pinned keys before
  using its fetch endpoint (§10.2), and retrieves it once more before refusing on a mismatch (§11.3).
- **`ClientEntityAuthorizer`** — the pure AS-side decision for a client that is itself a federation
  entity: member (chain resolves), status active, `oauth_client` metadata within registration policy,
  requested scopes within registered scopes. No I/O.
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
- **`FederationConfiguration` / `AttestationMetadataConfig`** — parsed from servlet init-params (below).
  The latter is the `openid_provider` attestation capability set the entity configuration advertises:
  auth methods, per-JWT algorithm lists, `attestation_pop_jwt` + `dpop_combined`, challenge endpoint.

## `authority` — hosting entities

- **`HostedEntity`**, **`HostingMode`** (`AUTHORITY_SIGNED`: the authority holds a dedicated per-entity
  key and the entity's own runtime key never appears in federation metadata; `SELF_SIGNED`: modelled,
  not yet implemented), **`EntityStatus`** (`ACTIVE` / `SUSPENDED` / `REVOKED` — only `ACTIVE`
  resolves; revocation is permanent).
- **`HostedEntityRegistry`** — `InMemoryHostedEntityRegistry` (tests, single node) or
  **`JdbcHostedEntityRegistry`** over `db/migration/V100__hosted_entity.sql` and `V101__hosted_entity_actor.sql`:
  `hosted_entity` plus an append-only `hosted_entity_audit_log` that records who made each change, written in the
  same transaction as the change; JSON stored as text so Postgres and H2 run identical SQL.
  Numbered V100 so it never collides with `agent-registry`'s V200 on the shared classpath (both land on
  `servlets/attestation-issuer`); `device-instance` uses a separate, non-Flyway IDM/SCIM migration
  scheme, so it isn't part of this numbering at all.
- **`HostedEntitySigner` / `RegistryHostedEntitySigner`** — resolves an entity's `hostingKeyRef` to an
  `OpenBaoTransitSigner` on one deployment-wide vault; **`HostedEntityConfigurationBuilder`** signs the
  entity configuration with it (60 min lifetime), with the Trust Marks this authority issues the entity.
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
  transaction). Granting again starts a grant afresh. **`TrustMarkSupport`** holds the process-wide one.
- **`TrustMarkIssuer`** — the issuing decisions behind `FederationService`: a mark only under a grant that stands
  and, for a hosted-only type, to an active hosted entity; `exp` never past the grant's end. No mark is recorded:
  its status is its signature plus its grant - revoked, or granted again since it was minted, is `revoked`; past
  its `exp` or its grant's end, `expired`; no grant, unknown (404).
- **`TrustMarkClaims`** — the claims an operator has this entity publish (`trust_marks` it carries from other
  issuers, `trust_mark_issuers`, `trust_mark_owners`), held to the shape a receiving entity's statement checks
  demand.

## `keyhistory` — the keys this entity signed with before

- **`HistoricalKey`** — a retired key: its public JWK, when it began to be used, its `exp`, and when and why it was revoked
  (§8.7.3's `unspecified`, `compromised`, `superseded`), rendered as §8.7.2 wants it.
- **`KeyHistoryStore`** — the key in use and the retired ones: `InMemoryKeyHistoryStore` or **`JdbcKeyHistoryStore`** over
  `db/migration/V103__federation_key_history.sql`. A rotation - the old key retired, the new one recorded - is one step;
  a retired key that signs again is no longer history, and a revoked one is refused. **`KeyHistorySupport`** holds the
  process-wide store.
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
  from the PDP's `/.well-known/authzen-configuration` with the §9.2.3 identifier check. Context it doesn't understand
  is listed as ignored, or refuses the permit when the deployment says so (§5.5).
- **`LocalFederationPolicyDecisionPoint`** (an allow-list of scopes), **`CompositePolicyDecisionPoint`** (local first; a
  local refusal is final, and both permits' obligations apply), **`CachingPolicyDecisionPoint`** (permits and denials
  for a while, keyed on a hash of the request; failures never).

## Configuration

The anchors' pinned keys are not a `FederationConfiguration` setting: they are passed to
`TrustChainValidator` as a `TrustAnchorSet`, which `servlets/pf-integration` and `servlets/attestation-issuer` both
build from `OIDF_FEDERATION_TRUST_ANCHOR_JWKS` (`OIDF_TRUST_ANCHOR_JWKS` is its superseded name).
`tools/pin-trust-anchor.py` captures them. Every setting the federation reads, with its default and what happens
when it's wrong, is in [docs/federation/configuration.md](../../docs/federation/configuration.md).

`FederationConfiguration.fromServletConfig` reads init-params with env fallbacks: `trustAnchorIssuers` /
`OIDF_FEDERATION_TRUST_ANCHORS` (required), `subordinates` / `OIDF_FEDERATION_SUBORDINATES`,
`ignoreSslErrors` / `OIDF_FEDERATION_IGNORE_SSL_ERRORS`, `signingAlgorithm` / `OIDF_FEDERATION_SIGNING_ALG` (RS256 or
PS256), `attesterJwks` / `OIDF_FEDERATION_ATTESTER_JWKS` (public keys only - it is published, so anything else is
refused), `organizationName` /
`OIDF_FEDERATION_ORGANIZATION_NAME`, `clientRegistrationTypes` / `OIDF_FEDERATION_CLIENT_REGISTRATION_TYPES`
(what `client_registration_types_supported` advertises; default `automatic,explicit`), `resolveDiscovery` /
`OIDF_FEDERATION_RESOLVE_DISCOVERY` (`known`, the default: resolve only this entity, its subordinates and
the entities it hosts, as §18.1 advises for an unauthenticated resolver; `any`: discover on demand).
Init-param only: CORS (`corsEnabled`,
`corsAllowOrigin`, `corsAllowMethods`, `corsAllowHeaders`, `corsMaxAge`) and the
`AttestationMetadataConfig` lists (`tokenEndpointAuthMethodsSupported`,
`clientAttestationSigningAlgValuesSupported`, `clientAttestationPopSigningAlgValuesSupported`,
`dpopSigningAlgValuesSupported`, `clientAttestationPopMethodsSupported`, `attestationChallengeEndpointEnabled`).
Two more are read and have no effect: `trustControllerHost` (the controller is `FederationRuntimeConfig`'s) and
`clientAttestationFormatsSupported`.

`RegistryHostedEntitySigner.fromEnvironment()` resolves the vault from `oidf.openbao.url` /
`OIDF_OPENBAO_URL` / `OPENBAO_ADDR` / `BAO_ADDR` / `VAULT_ADDR` and `oidf.openbao.token` /
`OIDF_OPENBAO_TOKEN` / `OPENBAO_TOKEN` / `BAO_TOKEN` / `VAULT_TOKEN` — system property first, then env,
in that order; the same names `attestation-issuer` uses, so one vault serves both.

## Build

```sh
mvn -pl libs/openid-federation -am package     # or `mvn package` at the repo root; tests run with the build
```

JDBC tests run the shipped migration against H2 in PostgreSQL mode. `LiveChainValidationTest` is
skipped unless a captured chain is present at `/tmp/live-chain`. Versions come from `bom/pom.xml`.
Consumers, by pom: `servlets/pf-integration`, `servlets/attestation-issuer`. Ships into PingFederate via
`build/pingfederate/stage-modules.sh` (pf-runtime.war merge) and inside `oidf.war`
(`servlets/oidf-war`).
