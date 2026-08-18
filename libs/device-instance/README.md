# device-instance

The **agent instance registry** and the **device Client Attestation minter**. The registry is the one
place an opaque instance identifier resolves to a device and to a human; the minter issues attestations
whose subject is that opaque identifier and never the user. Package `com.pingidentity.ps.oidf.device`.
No HTTP, no servlet, no PingFederate types; depends on `oidf-jose`, `jose4j`, `jackson-databind`,
`commons-logging`, with the JDBC driver provided by the deployment. Consumed by
`services/device-enrolment` (the enrolment API that populates it) and `plugins/instance-registry-datasource`
(a PingFederate `CustomDataSourceDriver` that reads it at token issuance, where revocation and the
user-verification time-box actually bite).

## What's here

- **`InstanceRegistry`** — the seam. Register instances, devices, owners and bound authenticators; look
  each up; fan out across every instance on a device; `revoke` (permanent, idempotent — a retried CAEP
  event cannot inflate the audit log), `setStatus` (suspend/resume), `recordUserVerification` (the
  server-side time-box), `recordAttestationExpiry`, `updateCompliance`, `recordAppAttestCounter` (rejects
  a counter that has not moved), and an append-only `audit` trail. Failures are a `RegistryException`
  with a stable reason: `not_found`, `duplicate`, `stale_update`, `storage_failure`.
- **`InMemoryInstanceRegistry`** — tests and single-node development. State dies with the process, so a
  revocation on one node would leave every other node issuing; it exists so the registry's semantics can
  be tested exhaustively and the JDBC implementation held to the same suite (`InstanceRegistryContract`).
- **`IomInstanceRegistry`** — production, over `javax.sql.DataSource` and plain JDBC against the
  **Identity Object Model** directory (`idm.entry`), so an agent instance is an entry beside the human
  it acts for rather than a row in a private schema of ours. Classes are registered by the model repo's
  `006-add-agent-instance-registry` migration: `agentInstance` (+`cryptoBinding`) whose
  {@link InstanceStatus} IS `record_status`, `agentDevice` (+`cryptoBinding`), `authenticatorBinding`
  (SUP `authorisationRecord`), `agentLifecycleEvent` (the append-only ledger); the owner is the existing
  `involvedParty` keyed by `pingoneUserId` — the same row the SCIM user store writes. **Postgres only**:
  every invariant is a JSONB operator, a partial unique index on an expression, or a plpgsql trigger.

  It replaced a `JdbcInstanceRegistry` over five private tables that read, decided in Java, then wrote,
  on autocommit — so two callers could both pass the same check. Here each rule is one statement the
  database evaluates atomically: status changes are `UPDATE … WHERE record_status <> 'revoked'` with the
  ledger row written by the same CTE (a losing caller writes nothing AND logs nothing), the App Attest
  counter is a compare-and-set, duplicates are unique indexes. The migration adds a backstop trigger for
  anything that bypasses the registry.
- **`AgentInstance`, `Device`, `OwnerUser`, `BoundAuthenticator`, `AuditEntry`** — records. `Device`
  data (model, OS, App Attest key id, counter, compliance) never reaches a token or a resource server;
  `BoundAuthenticator` is a reference to the passkey that proved the human, kept as a first-class record
  per NIST SP 800-63B, not a boolean.
- **`InstanceStatus`** (`ACTIVE` / `SUSPENDED` / `REVOKED`; only `ACTIVE` can obtain tokens),
  **`ComplianceState`** (`COMPLIANT` / `NOT_COMPLIANT` / `UNKNOWN` — CAEP `device-compliance-change`
  values plus an explicit unknown so an unassessed device never inherits a compliant posture),
  **`KeyStorageLevel`** (OpenID4VCI Appendix D `iso_18045_*` levels; a Secure Enclave is `MODERATE` at
  best).
- **`InstanceIdentifiers`** — 256 bits of `SecureRandom`, base64url, for instance, device and owner ids.
  Random, not derived: an HMAC over user and device would become retroactively linkable the day its key
  leaked.
- **`DeviceAttestationMinter`** — mints the Client Attestation
  (`typ: oauth-client-attestation+jwt`, draft-ietf-oauth-attestation-based-client-auth) a device-resident
  agent presents at the token endpoint: `iss` = the platform's federation entity id, `agent_id` = the
  instance id, `cnf.jwk` = the Secure Enclave public key (must match the registry's `cnfJkt`),
  `key_storage` / `user_authentication` (Appendix D vocabulary), `authenticator_ref`, `agent_build`,
  `uv_policy.reuse_seconds`; 15 minute default lifetime. `sub` is the instance id unless a
  `subjectClientId` is configured, in which case `sub` is the registered client id and the instance
  identity rides only in `agent_id` (the staged Phase 2.5 flip). Signs through any `JwsSigner`.

## Configuration

Nothing is read from the environment here. Data source, platform entity id, lifetime and the
`subjectClientId` flip are constructor inputs — `services/device-enrolment`'s `Main` wires the last from
`OIDF_ATTESTATION_SUB=client_id`.

## Security posture

- The minter has no way to accept a user identifier and emits no device data — an attestation is
  presented on every token request and travels further than a registry row.
- `KeyStorageLevel.HIGH` is refused at construction: a Secure Enclave is a keystore, not a WSCD, and
  asserting `iso_18045_high` would be a false claim a downstream policy might rely on.
- The bound key is checked against the enrolment-time thumbprint, and `cnf.jwk` must be public-only.
- Revocation is permanent and re-enrolment mints a new id; the App Attest counter is monotonic; the audit
  log is append-only — the same semantics are asserted against both registry implementations.

## Build

```sh
mvn -pl libs/device-instance -am package     # or `mvn package` at the repo root; tests run with the build
```

`IomInstanceRegistryTest` runs the full `InstanceRegistryContract` against a **real Postgres**, plus the
cases only a real one can prove: an 8-thread race where exactly one App Attest assertion may advance the
counter, the trigger refusing a revoked→active update and a ledger DELETE, and the `v_agent_instance`
resolution. It takes its database from `IDM_TEST_JDBC_URL` (+ `IDM_TEST_JDBC_USER` / `_PASSWORD`) when
set — any throwaway Postgres, for environments where the Docker API is not reachable from the build —
and otherwise starts one with Testcontainers. Skipped, not failed, when neither is available. **It drops
and rebuilds the `idm` schema**, so never point it at a database you care about.

```sh
# against a throwaway you already have
docker run -d --rm --name idm-test -e POSTGRES_PASSWORD=t -e POSTGRES_DB=idm -p 55432:5432 postgres:16-alpine
IDM_TEST_JDBC_URL=jdbc:postgresql://localhost:55432/idm IDM_TEST_JDBC_USER=postgres IDM_TEST_JDBC_PASSWORD=t \
  mvn -pl libs/device-instance test
```

The three migrations under `src/test/resources/idm/` are **copies** from
`~/Source/idp-scim-service/migrations` — refresh them when the model changes; each carries an
`ldm-checksum` header that must match its source. Versions come from `bom/pom.xml`.
Not staged into PingFederate by `deploy/pingfederate/build/stage-modules.sh` — the enrolment service and
the data-source plugin are its consumers. A sibling of, and deliberately not coupled to,
`openid-federation`'s hosted-entity registry (a publishing concern) and `agent-registry` (lazy minting
for runtimes with no enrolment step).
