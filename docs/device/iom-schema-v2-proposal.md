# IOM schema v2 for the device path - a proposal for idp-scim-service

A proposal, not a change: nothing here is applied by this repository. It is plan item X-A03, written
2026-09-27 for David to raise in `idp-scim-service`, the repository that owns the Identity Object Model and
its migrations. It is a diff against the model as it is, so the first section says what is there now, as
`libs/device-instance` and `servlets/ssf` write it, and every proposed attribute names the plan item that will
write or read it. The rule throughout is the model's own: an attribute a consumer adds is a MAY.

## What exists today - the base of the diff

The model is one table, `idm.entry` (migration `0000-base-schema`), with `entry_uuid`, `object_classes text[]`,
`subject_id`, `subject_type`, `parent_id` (containment, `ON DELETE CASCADE`), `record_status`, `created_at`,
`modified_at`, `expires_at`, a JSONB `attrs`, and generated columns for the hot keys (`client_id` from
`attrs.clientId`, `grant_guid`, `correlation_id` and `hashed_refresh`). `idm.object_class` declares each
class's MUST and MAY attributes. Two things read those lists: the row trigger `entry_class_check`
(`idm.check_entry_classes()`), which refuses a missing MUST on INSERT and on UPDATE and says nothing about any
other attribute; and the model repo's `validate_entry` tool, which checks a proposed entry at design time,
writes nothing, and reports an attribute no class declares. Migration `002-backfill-may-attrs` set the base
classes' MAY lists; `006-add-agent-instance-registry` registered the four device-path classes;
`0001-add-shared-signals-ssf` registered the three SSF classes. Copies of `0000`, `002` and `006` are under
[libs/device-instance/src/test/resources/idm](../../libs/device-instance/src/test/resources/idm/README.md),
and of `0000` and `0001` under
[servlets/ssf/src/test/resources/idm](../../servlets/ssf/src/test/resources/idm/README.md), each with the
model's checksum; the tables below are checked against them (2026-09-27; the copies match the model repo at
`cb90151`).

### The device-path classes, as declared by 006 and as written by `IomInstanceRegistry`

| Class (kind, id) | Row | MUST (006) | MAY (006) | Also written today |
|---|---|---|---|---|
| `agentInstance` (structural, ldm-9200, SUP `identityObject`, +`cryptoBinding`) | `subject_id` = the instance id, `subject_type` `agent`, `record_status` IS the `InstanceStatus`, `parent_id` = the device | `platformEntityId`, `cnfJkt`, `deviceRef`, `enrolledAt` | `agentBuild`, `attestationExp`, `uvLastVerifiedAt`, `statusReason` | `pqPosture`, `keyRef`, `keyKty`, `sigAlgorithm` (the `cryptoBinding` mix-in) |
| `agentDevice` (structural, ldm-9210, SUP `identityObject`, +`cryptoBinding`) | `subject_id` = the owner's `entry_uuid` (a reference, never containment) | `deviceId`, `platform`, `appAttestKeyId`, `appAttestEnvironment`, `appAttestSignCount`, `complianceState` | `model`, `osVersion`, `complianceCheckedAt` | `appAttestPublicKey` - **written, not declared** (`deviceAttrs`); the `cryptoBinding` four |
| `authenticatorBinding` (structural, ldm-9220, SUP `authorisationRecord`) | contained under the device, `subject_id` = the owner | `credentialId`, `authenticatorType` | `aaguid`, `bindingId`, `deviceRef`, `authenticationEventRef` | `eventTimestamp`, `outcome` (`granted`) - `authorisationRecord`'s |
| `agentLifecycleEvent` (structural, ldm-9230, SUP `identityObject`) | contained under the instance, or the device for a device-level event; append-only by trigger | `eventCode`, `eventTimestamp`, `auditSeq` | `detail`, `deviceRef` | - |
| `involvedParty` (existing, ldm-4200) | the owner: the same `{identity, involvedParty}` row the SCIM user store writes | - | + `pingoneUserId` (006) | `identityID`, `identityType`, `identityDescriptor`, `internalKey`, `cn` (`upsertOwner`) |

Timestamps in `attrs` are text, ISO-8601 UTC with six fractional digits (`IomInstanceRegistry.TS`), so they
sort and compare as strings. `complianceState` is the CAEP value (`compliant`, `not-compliant`) or null for
`UNKNOWN`, which CAEP has no encoding for.

Around the classes, 006 also created: the vocabularies `agentPlatform`, `appAttestEnvironment`,
`deviceComplianceState`, `authenticatorType`, `agentLifecycleEventCode`; the sequence
`idm.agent_lifecycle_event_seq`; the partial unique indexes `entry_agent_instance_subject_uq`,
`entry_agent_device_id_uq`, `entry_authenticator_binding_id_uq`, `entry_involved_party_pingone_uq` and the
ordering index `entry_agent_event_order_idx`; the trigger `entry_agent_registry_invariants` (the ledger is
append-only, revocation is permanent, `appAttestSignCount` never decreases); and the view
`idm.v_agent_instance` (instance -> device -> owner, the issuance-time resolution).

### The SSF classes, as declared by 0001 and as written by `LdmSsfStore`

| Class (kind, id) | Row | MUST (0001) | MAY (0001) | Also written today |
|---|---|---|---|---|
| `ssfStream` (structural, ldm-9100, SUP `identityObject`) | `entry_uuid` = the stream id | `audience`, `deliveryMethod` (the RFC URN), `streamStatus` | `pushEndpointUrl`, `pushAuthorizationHeader`, `eventsRequested`, `eventsDelivered`, `statusReason`, `ssfIssuer` (declared, never written) | `ownerClientId` - **written, not declared** (the [ssf README](../../servlets/ssf/README.md#upgrading) already asks for it as a MAY, never a MUST) |
| `ssfStreamSubject` (structural, ldm-9110) | `parent_id` = the stream, `subject_id` = the RFC 9493 canonical key | `subjectFormat`, `subjectJson` | - | - |
| `ssfPendingSet` (structural, ldm-9120) | `parent_id` = the stream, `subject_id` = the subject key, `expires_at` = the SET's expiry | `jti`, `setJws`, `issuedAt` | `eventType`, `subjectKey`, `deliveryAttempts`, `nextAttemptAt` | - |

0001 also indexes `ssfPendingSet` on `nextAttemptAt`, `issuedAt` and `jti` (`entry_ssf_pending_due_idx`,
`entry_ssf_pending_order_idx`, `entry_ssf_pending_jti_idx`). Since 0.4.0 the push loop's selection joins the
pending entry to its stream entry on `parent_id` and reads the stream's `deliveryMethod` and `streamStatus`
(the B5 stopgap); `SsfStoresOnPostgresTest` runs it against these two migrations.

## The rule: MAY, never MUST

The trigger checks MUST attributes on UPDATE as well as INSERT, and the rows already in a directory have none
of the attributes below. A MUST would refuse the next update of every existing row - a compliance change on a
device enrolled before the migration, a dead-letter pause on a stream created before it. That is why
`ownerClientId` had to be a MAY, and it holds for everything here. Where a consumer needs an attribute to be
present it enforces that in its own write path: X-A17 writes a device only once it holds the MDM ids, and
never a device without them.

Nothing below removes or renames an attribute, so 0.3.0 and 0.4.0 code keeps working against a directory that
has the migration, and a directory without it keeps working until a Phase 6 consumer checks for it
([start-up check](#11-a-start-up-schema-check)).

## Proposed changes

Each item: the shape, why it is a MAY, and the plan item that consumes it. Names follow the model's camelCase;
timestamps are the model's text convention unless a hot predicate needs more, noted where it does.

### 1. Declare what is already written

- `agentDevice` MAY + `appAttestPublicKey` (base64url SubjectPublicKeyInfo; `Device.appAttestPublicKey`).
  Written since the App Attest assertion work; `validate_entry` reports it undeclared for a device row shaped
  as the registry writes it. The trigger lets it through, so nothing fails today; the declaration is what makes
  the model's own tool agree with the rows.
- `ssfStream` MAY + `ownerClientId` (a client id, deliberately not `clientId`, which the table turns into
  its indexed `client_id` column).

Consumer: what runs today (`IomInstanceRegistry`, `LdmSsfStore`).

### 2. App Attest key, receipt and risk

`agentDevice` MAY:

| Attribute | Shape | Why |
|---|---|---|
| `appAttestReceipt` | base64url, the latest receipt Apple issued for the key, as issued | X-A07 validates receipts and refreshes them; the current one must be kept to refresh from |
| `appAttestReceiptRefreshedAt` | timestamp | when it was last refreshed |
| `appAttestRiskMetric` | integer, the metric a refreshed receipt carries | X-A07's optional risk-metric job; a policy can refuse a device whose metric moves |
| `appAttestRiskCheckedAt` | timestamp | when the metric was read |

What a receipt carries and how it is refreshed is X-A07's to verify from Apple's text; this proposal fixes
only where the results live. The key itself (`appAttestKeyId`, `appAttestPublicKey`, `appAttestSignCount`) is
already here. Consumers: X-A07, X-A08 (assertions on re-mint and UV refresh, with the counter compare-and-set
that 006's trigger already backs).

### 3. MDM ids

`agentDevice` MAY:

| Attribute | Shape | Why |
|---|---|---|
| `mdmProvider` | vocabulary `mdmProvider`: `intune` to begin with | which adapter the ids belong to |
| `mdmDeviceId` | the MDM's managed-device id | the key the adapter resolves compliance by |
| `entraDeviceId` | the Entra device id (the `deviceid` claim X-I01a's spike confirms) | the cross-check between the token, the managed app configuration and Graph |
| `mdmCorrelatedAt` | timestamp | when the correlation was made |

Plus a partial index `ON idm.entry ((attrs->>'mdmDeviceId')) WHERE 'agentDevice' = ANY (object_classes)`:
X-A15 resolves a complex `iss_sub` device subject through it on every compliance SET. Not unique here -
whether one MDM device may enrol twice (a wiped and re-enrolled phone keeps its Intune id) is X-A17's
decision, and a unique index that turns out wrong is harder to remove than to add. Consumers: X-A17 (the
correlation at enrolment, which removes the deadlock), X-A15, X-A16 (the adapter's resolve API).

### 4. Compliance as an event-time observation

`agentDevice` MAY:

| Attribute | Shape | Why |
|---|---|---|
| `complianceSource` | the transmitter's `iss`, or the adapter's name | which source last spoke; X-A15 is multi-transmitter |
| `complianceEventTime` | timestamp, the SET's `event_timestamp` | out-of-order signals are ignored: an older event must not overwrite a newer posture |
| `complianceEventId` | the SET's `jti` | idempotent on the source event id, so a redelivered SET is a no-op that leaves the ledger honest |

The write is one statement, `... WHERE (attrs->>'complianceEventTime') IS NULL OR attrs->>'complianceEventTime' < ?`
(text timestamps compare in order, which is what the six-digit convention is for). `complianceCheckedAt`
stays: it is when the transmitter checked, not when this directory heard. Consumers: X-A04, X-A15.

### 5. `uvExpiresAt`

`agentInstance` MAY + `uvExpiresAt` (timestamp): `uvLastVerifiedAt` plus the service's maximum age, written
when the verification is recorded. Today the consumer of the time-box has to know `UV_MAX_AGE_SECONDS` to
decide; the datasource plugin (X-A20) asks for `uv_expires_at` and a `usable` field instead, so PingFederate
never learns the service's setting and cannot disagree with it. Goes into the view (item 8). Consumers:
X-A20, X-A08, X-A21 (the rig tests of the whole path).

### 6. Status reasons

`agentInstance` MAY:

| Attribute | Shape | Why |
|---|---|---|
| `statusReasonCode` | vocabulary `agentInstanceStatusReason`: `device_not_compliant`, `session_revoked`, `credential_revoked`, `operator`, `owner` | machine-readable; `statusReason` (declared already) stays free text |
| `statusChangedAt` | timestamp | when the status last changed, without walking the ledger |

X-A15's auto-resume of a compliance-suspended instance must resume only the instances suspended *for
compliance* - an operator's suspension survives the device coming back - and today the reason is prose.
Consumers: X-A04, X-A12 (lookup and audit), X-A15.

### 7. Binding: idp, acr, authTime

`authenticatorBinding` MAY: `idpIssuer` (the PingOne issuer), `acr`, `amr` (array), `authTime` (timestamp),
`idTokenJti`. The record already names which passkey proved the human (`credentialId`, `aaguid`); these say
which IdP said so, at what assurance, when, and with which token - what a dispute asks. X-A05 binds a
single-use ID token with a nonce and an `auth_time` maximum age; the `jti` on the record is the audit trail
of that, not the replay store (which is Redis, X-A06). Consumers: X-A05, X-A04.

### 8. Lifecycle actor

`agentLifecycleEvent` MAY: `actor` (the operator token's subject, the transmitter's `iss`, or `system`),
`actorType` (vocabulary `agentLifecycleActorType`: `system`, `operator`, `transmitter`, `device`, `owner`),
`sourceEventId` (the SET `jti` behind a signal-driven change). `correlationId` is already an `identityObject`
MAY and the table indexes it. Consumers: X-A12 (revoke, suspend, resume, lookup, audit - every operator action
names who), X-A04 (the lifecycle-only ledger), X-A15.

### 9. A watch view with no PII

`idm.v_agent_instance` resolves to the owner's PingOne subject, which is right for issuance and wrong for a
dashboard. Proposed `idm.v_agent_instance_watch`: `instance_id`, `instance_status`, `status_reason_code`,
`status_changed_at`, `platform_entity_id`, `agent_build`, `enrolled_at`, `attestation_exp`, `uv_expires_at`,
`platform`, `appattest_environment`, `compliance_state`, `compliance_event_time`, `compliance_source`,
`mdm_provider` - and none of `owner_pingone_subject`, `device_id`, `model`, `os_version`, `appattest_key_id`,
the MDM ids or any key material. Consumers: X-A12, X-A11 (pseudonymised logs read the same shape), the
Phase 3 metrics.

### 10. Least-privilege roles

Four roles, granted by the model repo because the table is its:

| Role | Used by | May |
|---|---|---|
| `idm_agent_enrolment` | `services/device-enrolment` | SELECT, INSERT and UPDATE `idm.entry` rows of the four device-path classes; INSERT an `involvedParty` that carries `pingoneUserId` (the owner upsert), never UPDATE or DELETE one; USAGE on the sequence |
| `idm_agent_issuance` | the PingFederate datasource plugin (X-A20, PF-owned pool and credentials) | SELECT on `idm.v_agent_instance` only |
| `idm_agent_signals` | PingFederate's SSF receiver and the Intune adapter | UPDATE the compliance and status attributes of `agentDevice` and `agentInstance`; INSERT `agentLifecycleEvent`; SELECT the watch view; nothing on `involvedParty` |
| `idm_ssf_store` | `LdmSsfStore` | everything on the three SSF classes, nothing else |

Row-level security keyed on `object_classes` is the natural fit (`USING ('agentInstance' = ANY (object_classes) OR ...)`);
if the model repo would rather not put RLS on `idm.entry`, the fallback is `SECURITY DEFINER` functions for
the writes and the views for the reads. Either way the point is that a token-issuance credential can read one
view and a signal credential cannot read a person. Consumers: X-A19 (packaging and compose), X-A20, X-A15, X-A21.

### 11. A start-up schema check

Each consumer checks, when it starts, that the directory has what it will write and read:

- `SELECT name FROM idm.schema_migration WHERE name IN ('006-add-agent-instance-registry', '<this migration>')`
  returns both;
- `SELECT may_attrs FROM idm.object_class WHERE name = ?` contains every attribute the consumer writes.

The queries need nothing new from the model; what the migration should add is a one-row view,
`idm.v_agent_schema` (`migration`, `checksum`, `applied_at` for the latest device-path migration), so a
consumer logs one line that says which schema it found. What a consumer does on a miss is its own: the
enrolment service refuses to start (it would write undeclared attributes), the datasource plugin degrades to
"not usable" for every instance, the SSF receiver refuses signals with a 503. The check itself is Java in
`libs/device-instance`, Phase 6 (X-A04); this item only asks the model for the view. Consumers: X-A04, X-A20,
X-A15, S10f.

### 12. SSF stream leases, and the classes S-10 adds

`ssfStream` MAY: `leaseOwner` (a node id), `leaseEpoch` (integer, the fencing token), `leaseUntil`
(timestamp), `pausedBy` (`receiver`, `transmitter`, `operator`), `heldUntil` (S10c's hold). `ssfPendingSet`
MAY: `deadLetteredAt`, `lastError`. Leasing selects with `FOR UPDATE SKIP LOCKED` on the stream row and a
predicate on `leaseUntil`, so a partial index `ON idm.entry (((attrs->>'leaseUntil'))) WHERE 'ssfStream' = ANY (object_classes)`
goes with it. Two classes S-10 will need that do not exist: an emission outbox (`ssfEmission`, S10d: one row
per event raised, fanned out to streams exactly once) and a receiver inbox (`ssfInboxSet`, S10e: keyed on
`iss` and `jti`, 202 only after commit). Their shapes are S-10's to fix; this proposal reserves the names so
the `tables` and `ldm` dialects land together (S10f, "after the IOM change"). Consumers: S10a, S10c, S10d,
S10e, S10f.

## The migration, as this repository would like to consume it

- One migration in the shape of 006 - idempotent, `ON CONFLICT (name) DO UPDATE` on `idm.object_class` that
  **merges** `may_attrs` (006's `involvedParty` pattern) rather than replacing them, `CREATE INDEX IF NOT EXISTS`,
  `CREATE OR REPLACE VIEW`, roles created in a `DO` block that tolerates their existing, a checksum header.
- Applied after 002 and 006, for the reason the vendored copies' README gives: 002 sets MAY lists absolutely.
- Once it lands, the copy goes under `libs/device-instance/src/test/resources/idm/` with its checksum, and
  `IomInstanceRegistryTest` runs the contract against it. Until then the Phase 6 packages are blocked on it,
  which is why X-A03 is on Phase 1's critical path.

## Open questions for the model repo

- RLS on `idm.entry`, or functions and views (item 10).
- Whether `complianceEventTime` and `leaseUntil` stay text in `attrs` with expression indexes, or become hot
  columns like `expires_at`. The predicates work on text; the indexes are what make them cheap.
- The vocabularies in items 3, 6 and 8: the codes above are this repository's proposal, the scheme is the
  model's.
- Whether the model wants `appAttestReceipt` in `attrs` at all (a few KB per device) or in a separate
  `agentDeviceReceipt` entry contained under the device.
- `deviceComplianceState` (006) has an `unknown` code, but the registry writes `null` for a device never
  assessed (`ComplianceState.caepValue()`: CAEP has no value for it). Either the attribute takes `unknown` or
  the code goes; this repository would write `unknown` once the model says the vocabulary governs the
  attribute.
