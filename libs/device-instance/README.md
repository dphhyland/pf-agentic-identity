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
- **`JdbcInstanceRegistry`** — production, over `javax.sql.DataSource` and plain JDBC (PF's data-source
  driver has no ORM available, and the revocation write on the issuance path is the query that matters).
  Schema in `db/migration/V1__instance_registry.sql`: `owner_user` (the only table naming a person),
  `device`, `agent_instance`, `bound_authenticator`, `audit_log` (no UPDATE or DELETE path). Runs on
  Postgres and on H2 in PostgreSQL mode.
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

JDBC tests run the shipped migration against H2 in PostgreSQL mode. Versions come from `bom/pom.xml`.
Not staged into PingFederate by `deploy/pingfederate/build/stage-modules.sh` — the enrolment service and
the data-source plugin are its consumers. A sibling of, and deliberately not coupled to,
`openid-federation`'s hosted-entity registry (a publishing concern) and `agent-registry` (lazy minting
for runtimes with no enrolment step).
