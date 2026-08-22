# agent-registry

Mints and resolves **`agent_id`**: a random, per-running-instance identifier keyed by the natural key
`(iss, client_id, instance_format, instance_subject)`, minted lazily on first sight and stable ever
after. Package `com.pingidentity.ps.oidf.agent`. Depends only on `commons-logging`, with the JDBC driver
provided by the deployment — no jose, no servlet, no PingFederate types. Consumed by
`servlets/attestation-issuer`, whose `AttestationIssuanceServlet` resolves an `agent_id` for each
attestation it mints and whose metadata servlet advertises whether a registry is configured.

This is for runtimes with **no enrolment step of their own** — a SPIFFE workload has nothing beyond its
SPIRE entry — so the id has to be minted at first attestation and then kept. It is a sibling of, and
deliberately not coupled to, `device-instance`'s registry, which pre-registers an instance at enrolment
and already holds a stable id to carry as `agent_id`.

## What's here

- **`AgentRegistry`** — one method: `resolveOrMint(iss, clientId, instanceFormat, instanceSubject)`
  returns the `AgentIdentity` for the natural key, minting and durably recording one the first time.
  Idempotent (`agentId` and `mintedAt` never change on a later call) and race-safe by contract: two
  concurrent calls for the same key must never yield two ids. Throws `AgentRegistryException`
  (`storage_failure`, `mint_collision`) only on a genuine fault — "not seen before" mints, it never fails.
- **`AgentIdentity`** — the row: `agentId`, `iss`, `clientId`, `instanceFormat` (e.g. `spiffe_id`,
  `wallet_instance` — evidence types can add formats without a schema change), `instanceSubject` (the
  proven identifier, e.g. the SPIFFE ID), `mintedAt`. `agent_id` is unique only within its issuer, so the
  full identity is the pair `(iss, agent_id)`.
- **`AgentIdMinter`** — 256 bits of `SecureRandom`, base64url without padding. Random, not derived: an
  HMAC over the natural key would let anyone who later learns the key material de-anonymise every id ever
  minted.
- **`JdbcAgentRegistry`** — production. `INSERT … ON CONFLICT DO NOTHING` then `SELECT` on the natural
  key, so however many callers race, one row is inserted and every caller reads back the same one.
  Schema in `db/migration/V200__agent_identity.sql`: a single `agent_identity` table with a UNIQUE
  constraint on the natural key. Numbered V200 so it never collides with `openid-federation`'s V100 in
  this repo's own Postgres schema. (`device-instance`'s registry lives in a separate, external IDM/SCIM
  schema with its own non-Flyway numbering — see that module's README — so there is no shared history to
  collide with there in the first place.)
- **`InMemoryAgentRegistry`** — development and tests; `ConcurrentHashMap.computeIfAbsent` gives the
  race-safety. State does not survive a restart, and a restart would silently re-mint every `agent_id`
  in the fleet — breaking any audit trail, rate limit or revocation keyed on the old value.
- **`AgentRegistrySupport`** — the process-wide holder every servlet reads the registry through, so a
  registration in one classloader is visible to a check in another. Unlike `AuthoritySupport` in
  `openid-federation` it does **not** default to in-memory: `registry()` throws until
  `configureJdbcRegistry(dataSource)` or `configureInMemoryRegistry()` has been called (first
  configuration wins), because falling into the in-memory store by omission is exactly the failure above.

## Configuration

Nothing is read from the environment here. The consumer decides which registry to configure and
supplies the `DataSource`; the choice is deliberately explicit.

## Security posture

The `instance_subject` column is the proven identifier and is never to be logged next to `agent_id` at
INFO — that would rebuild the correlation the pseudonym exists to prevent. Ids are opaque text, not
sequences: a monotonic integer would leak enrolment order and volume and be guessable.

## Build

```sh
mvn -pl libs/agent-registry -am package     # or `mvn package` at the repo root; tests run with the build
```

Both registries are held to the same `AgentRegistryContract` suite; the JDBC tests run the shipped
migration against H2 in PostgreSQL mode. Versions come from `bom/pom.xml`. Not staged into PingFederate
by `build/pingfederate/stage-modules.sh`; it reaches `oidf.war`'s `WEB-INF/lib` only as a
transitive dependency of `attestation-issuer`.
