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
  `SigningKeyProvider`.
- **`FederationConfiguration` / `AttestationMetadataConfig`** — parsed from servlet init-params (below).
  The latter is the `openid_provider` attestation capability set the entity configuration advertises:
  auth methods, per-JWT algorithm lists, `attestation_pop_jwt` + `dpop_combined`, challenge endpoint.

## `authority` — hosting entities

- **`HostedEntity`**, **`HostingMode`** (`AUTHORITY_SIGNED`: the authority holds a dedicated per-entity
  key and the entity's own runtime key never appears in federation metadata; `SELF_SIGNED`: modelled,
  not yet implemented), **`EntityStatus`** (`ACTIVE` / `SUSPENDED` / `REVOKED` — only `ACTIVE`
  resolves; revocation is permanent).
- **`HostedEntityRegistry`** — `InMemoryHostedEntityRegistry` (tests, single node) or
  **`JdbcHostedEntityRegistry`** over `db/migration/V100__hosted_entity.sql`: `hosted_entity` plus an
  append-only `hosted_entity_audit_log`, JSON stored as text so Postgres and H2 run identical SQL.
  Numbered V100 so it never collides with `agent-registry`'s V200 on the shared classpath (both land on
  `servlets/attestation-issuer`); `device-instance` uses a separate, non-Flyway IDM/SCIM migration
  scheme, so it isn't part of this numbering at all.
- **`HostedEntitySigner` / `RegistryHostedEntitySigner`** — resolves an entity's `hostingKeyRef` to an
  `OpenBaoTransitSigner` on one deployment-wide vault; **`HostedEntityConfigurationBuilder`** signs the
  entity configuration with it (60 min lifetime). **`AuthoritySupport`** holds the process-wide registry,
  signer and domain-default policy so every servlet shares one state across classloaders.

## Configuration

The anchor's pinned keys are not a `FederationConfiguration` setting: they are passed to
`TrustChainValidator` as a `TrustAnchor`, which `servlets/pf-integration` builds from
`OIDF_FEDERATION_TRUST_ANCHOR_JWKS` (see its README) and `servlets/attestation-issuer` from
`OIDF_TRUST_ANCHOR_JWKS`. `tools/pin-trust-anchor.py` captures them.

`FederationConfiguration.fromServletConfig` reads init-params with env fallbacks: `trustAnchorIssuers` /
`OIDF_FEDERATION_TRUST_ANCHORS` (required), `subordinates` / `OIDF_FEDERATION_SUBORDINATES`,
`trustControllerHost` / `OIDF_FEDERATION_TRUST_CONTROLLER_HOST`, `ignoreSslErrors` /
`OIDF_FEDERATION_IGNORE_SSL_ERRORS`, `signingAlgorithm` / `OIDF_FEDERATION_SIGNING_ALG` (RS256 or
PS256), `attesterJwks` / `OIDF_FEDERATION_ATTESTER_JWKS`, `organizationName` /
`OIDF_FEDERATION_ORGANIZATION_NAME`, `clientRegistrationTypes` / `OIDF_FEDERATION_CLIENT_REGISTRATION_TYPES`
(what `client_registration_types_supported` advertises; default `automatic,explicit`), `resolveDiscovery` /
`OIDF_FEDERATION_RESOLVE_DISCOVERY` (`known`, the default: resolve only this entity, its subordinates and
the entities it hosts, as §18.1 advises for an unauthenticated resolver; `any`: discover on demand).
Init-param only: CORS (`corsEnabled`,
`corsAllowOrigin`, `corsAllowMethods`, `corsAllowHeaders`, `corsMaxAge`) and the
`AttestationMetadataConfig` lists (`tokenEndpointAuthMethodsSupported`,
`clientAttestationSigningAlgValuesSupported`, `clientAttestationPopSigningAlgValuesSupported`,
`dpopSigningAlgValuesSupported`, `clientAttestationFormatsSupported`,
`clientAttestationPopMethodsSupported`, `attestationChallengeEndpointEnabled`).

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
