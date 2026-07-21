# ssf

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Extracted with history from `pf-oidf-modules` 2026-07-21; see [docs/PROVENANCE.md](https://github.com/dphhyland/pf-agentic-identity/blob/main/docs/PROVENANCE.md).

**Shared Signals Framework 1.0 (CAEP/RISC) transmitter + receiver** for PingFederate:

- **Transmitter** — SET minting (`SetMinter`, signed with PF's own JWKS via
  `PfJwksSigningKeyProvider`), stream management (`/ssf/config`, `StreamManagementService`),
  poll + push delivery (`SsfPollServlet`, `PushDeliveryService`), and event sourcing from PF's
  native security-audit log (`SsfAuditLogSource`, a log4j2 appender) plus a logout-event filter.
- **Receiver** — `SsfReceiverServlet` verifies inbound SETs (`SetVerifier`) and runs receiver
  actions; `PfReceiverActions` revokes access grants through the PF access-grant SDK
  (`AccessGrantManagerAccessor`).
- **Stores** — pluggable stream/state stores: in-memory, JDBC (`PfJdbcStoreFactory` uses PF's
  own datasource), and LDM (the Identity Object Model `idm.entry` schema).
- **Kafka** — `KafkaSetPublisher` publishes SETs reflectively: no compile-time Kafka dependency;
  it activates only when Kafka is on the runtime classpath.

Events: CAEP session-revoked / credential-change and RISC account signals (`SsfEventTypes`,
`CaepRiscEvents`). Configuration via `SsfConfiguration` (issuer, streams, delivery, store dialect).
