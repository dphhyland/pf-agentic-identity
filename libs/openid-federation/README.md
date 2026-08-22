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

- **`TrustChainValidator`** — validates a (possibly partial) `trust_chain` from a leaf to the configured
  known trust anchor: locates the leaf (fetching its entity configuration if absent), walks
  `authority_hints`, refreshes stale or expiring statements through the gateway, verifies each statement
  against its issuer's keys (optionally algorithm-constrained), then composes every superior's
  `metadata_policy` and applies it to the leaf. Returns a `TrustChainValidationResult` carrying the leaf's
  full per-entity-type `metadata` (`oauth_client`, `oauth_resource`, `openid_relying_party`, ...).
- **`MetadataPolicy`** — `metadata_policy` composition and application: `value`, `add`, `default`,
  `one_of`, `subset_of`, `superset_of`, `essential`, applied in the spec's order, with
  `metadata_policy_crit` honoured. Every ambiguous merge refuses rather than widens — the choices made
  where §6.1.4's merge table could not be read are in the class javadoc and
  [docs/unverified.md](../../docs/unverified.md) §11.
- **`TrustControllerGateway` / `HttpTrustControllerGateway`** — fetch entity configurations, member lists
  and subordinate statements (resolving each authority's `federation_fetch_endpoint`), over a bounded LRU
  **`SubordinateStatementCache`** with expiry-buffer and max-age eviction; writes are staged as
  `PendingWrites` and committed only once a chain validates.
- **`ClientEntityAuthorizer`** — the pure AS-side decision for a client that is itself a federation
  entity: member (chain resolves), status active, `oauth_client` metadata within registration policy,
  requested scopes within registered scopes. No I/O.
- **`FederationService`** — builds and signs this entity's own artefacts: entity configuration,
  subordinate statements (embedding the subordinate's own keys — fetched and cached for a foreign
  subordinate, looked up uncached from the hosted registry so a revocation bites on the next call),
  `list`, `fetch` and `resolve` responses. RS256/PS256 through `SigningKeyProvider`.
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

`FederationConfiguration.fromServletConfig` reads init-params with env fallbacks: `trustAnchorIssuers` /
`OIDF_FEDERATION_TRUST_ANCHORS` (required), `subordinates` / `OIDF_FEDERATION_SUBORDINATES`,
`trustControllerHost` / `OIDF_FEDERATION_TRUST_CONTROLLER_HOST`, `ignoreSslErrors` /
`OIDF_FEDERATION_IGNORE_SSL_ERRORS`, `signingAlgorithm` / `OIDF_FEDERATION_SIGNING_ALG` (RS256 or
PS256), `attesterJwks` / `OIDF_FEDERATION_ATTESTER_JWKS`. Init-param only: CORS (`corsEnabled`,
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
