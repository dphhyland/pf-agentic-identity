-- ldm-migration: 006-add-agent-instance-registry
-- ldm-description: Agent instance registry (pf-agentic-identity libs/device-instance) as first-class entries: agentInstance, agentDevice, authenticatorBinding, agentLifecycleEvent; the owner is the involvedParty keyed by pingoneUserId.
-- ldm-kind: custom
-- ldm-checksum: sha256:70fe5c766118f22e4511f4ed51bb379ff8d8444d340817de2b3bb8938c7db2a9
--
-- Authored by hand in the shape of 0001-add-shared-signals-ssf.sql (with the generator's
-- ON CONFLICT / IF NOT EXISTS idempotency, which that precedent lacked). Checksum stamped with
-- the same normalisation ldm-copilot's checksumOf() uses; verified re-runnable and invariant-tested
-- against Postgres 16 over pre-existing SCIM data before commit.
--
--   psql "$DSN" -v ON_ERROR_STOP=1 -f migrations/006-add-agent-instance-registry.sql
--

BEGIN;

-- The ledger records what has been applied. Created by whichever migration
-- lands first, so no migration depends on another having run before it.
CREATE SCHEMA IF NOT EXISTS idm;
CREATE TABLE IF NOT EXISTS idm.schema_migration (
  name        text PRIMARY KEY,
  checksum    text NOT NULL,
  applied_at  timestamptz NOT NULL DEFAULT now(),
  applied_by  text NOT NULL DEFAULT current_user
);

-- >>> change
-- 006-add-agent-instance-registry
--
-- The device-bound-agent attester (pf-agentic-identity: services/device-enrolment on
-- libs/device-instance) kept its registry in five private tables. Those tables duplicated things
-- this model already has: an owner is a party, a passkey binding is an authorisation record, a
-- key thumbprint is a cryptoBinding, an audit row is a lifecycle event. This migration makes the
-- registry a set of entries in the directory, beside the human the agent acts for, so a
-- pseudonymous instance id resolves here — through the same table the SCIM users, consents and
-- proofing records live in — and nowhere else.
--
-- Classes (ldm-92xx: local extension range, above SSF's 91xx; upstream-collision-free):
--
--   agentInstance         (structural, ldm-9200) — one running agent instance on one device. Its
--                          opaque id (the attestation `sub` / the delegated token's `act.sub`) is
--                          the entry's subject_id, subject_type='agent'. Its lifecycle status IS
--                          record_status: active | suspended | revoked — the enum already carries
--                          exactly these. Mixes in cryptoBinding for the Secure Enclave key
--                          (keyRef = the RFC 7638 thumbprint, cnfJkt). Contained under its device.
--   agentDevice           (structural, ldm-9210) — one enrolled device (App Attest key id, the
--                          strictly-increasing assertion counter, compliance state). Its own class,
--                          not an identityEvidence subclass: evidence is an immutable verification
--                          fact about a person; a device is a mutable standing object about an app.
--                          Mixes in cryptoBinding for the App Attest key. subject_id = the owner's
--                          entry_uuid — a REFERENCE, deliberately not containment (see below).
--   authenticatorBinding  (structural, ldm-9220, SUP authorisationRecord) — which PingOne passkey
--                          proved the human at enrolment. NIST SP 800-63B: enrolment evidence is a
--                          first-class record, not a boolean. Not an authenticationEvent: that
--                          MUSTs acr+amr, which this record does not carry, and fabricating them
--                          would put false assurance claims into the audit chain — the one thing
--                          the model exists to prevent. Contained under its device.
--   agentLifecycleEvent   (structural, ldm-9230) — the append-only ledger the old audit_log was.
--                          Not an authorisationRecord: that forces outcome ∈ granted/denied/… onto
--                          rows like instance_revoked where it means nothing. Ordered by a real
--                          sequence (attrs.auditSeq), not created_at — now() is per-transaction
--                          and can tie. Contained under its instance (or device, for device-level
--                          events). Append-only is ENFORCED by trigger below; the old schema only
--                          had "no UPDATE path in code".
--
--   involvedParty (existing, ldm-4200) gains MAY pingoneUserId. The owner is the SAME
--   {identity, involvedParty} row that proofing-directory's SCIM user store already writes with
--   that key — so a person's SCIM identity and their agent devices are one party record, and
--   the old owner_user table becomes nothing at all. The owner is NEVER a parent_id: the SCIM
--   store's reset() DELETEs identity rows, and containment would cascade-wipe every device.
--
-- Relationships: containment (parent_id) device ⊃ instance, device ⊃ authenticatorBinding,
-- instance ⊃ its lifecycle events; reference (subject_id / attrs.deviceRef) device → owner,
-- instance → device (both directions available without a join).
--
-- Invariants the class trigger cannot express move to: partial UNIQUE indexes (duplicate
-- registration), the trigger below (revoked is terminal; the App Attest counter never decreases;
-- lifecycle events are immutable), and single-statement compare-and-set SQL in the Java registry.
-- The retired JdbcInstanceRegistry did check-then-act on autocommit; this is strictly safer.


-- ---------------------------------------------------------------------------
-- Object classes
-- ---------------------------------------------------------------------------

INSERT INTO idm.object_class (name, ldap_name, kind, sup, must_attrs, may_attrs) VALUES
 ('agentInstance','ldm-9200-agent-instance','structural','identityObject',
  '{platformEntityId,cnfJkt,deviceRef,enrolledAt}',
  '{agentBuild,attestationExp,uvLastVerifiedAt,statusReason}'),
 ('agentDevice','ldm-9210-agent-device','structural','identityObject',
  '{deviceId,platform,appAttestKeyId,appAttestEnvironment,appAttestSignCount,complianceState}',
  '{model,osVersion,complianceCheckedAt}'),
 ('authenticatorBinding','ldm-9220-authenticator-binding','structural','authorisationRecord',
  '{credentialId,authenticatorType}',
  '{aaguid,bindingId,deviceRef,authenticationEventRef}'),
 ('agentLifecycleEvent','ldm-9230-agent-lifecycle-event','structural','identityObject',
  '{eventCode,eventTimestamp,auditSeq}',
  '{detail,deviceRef}')
ON CONFLICT (name) DO UPDATE SET
  ldap_name = EXCLUDED.ldap_name, kind = EXCLUDED.kind, sup = EXCLUDED.sup,
  must_attrs = EXCLUDED.must_attrs, may_attrs = EXCLUDED.may_attrs;

-- Declare the join key the SCIM user store already writes on involvedParty rows, so the
-- undeclared-attribute check (validate_entry) recognises it and this migration's unique index
-- has a declared attribute to stand on.
UPDATE idm.object_class
   SET may_attrs = (SELECT array_agg(DISTINCT a ORDER BY a) FROM unnest(may_attrs || '{pingoneUserId}'::text[]) AS a)
 WHERE name = 'involvedParty';

-- ---------------------------------------------------------------------------
-- Vocabularies (scheme-owned code lists, per the vocabulary-table pattern)
-- ---------------------------------------------------------------------------

INSERT INTO idm.vocabulary (vocab, code, label) VALUES
 ('agentPlatform','ios','Apple iOS (App Attest)'),
 ('appAttestEnvironment','appattest','Apple App Attest — production'),
 ('appAttestEnvironment','appattestdevelop','Apple App Attest — development. A development enrolment must stay distinguishable forever; never mistake it for production.'),
 ('deviceComplianceState','compliant','CAEP device-compliance-change current_status: compliant'),
 ('deviceComplianceState','not-compliant','CAEP device-compliance-change current_status: not-compliant'),
 ('deviceComplianceState','unknown','Never assessed — not the same as compliant'),
 ('authenticatorType','passkey','FIDO2 platform authenticator (PingOne)'),
 ('agentLifecycleEventCode','instance_registered','Enrolment completed; instance active'),
 ('agentLifecycleEventCode','instance_revoked','Instance permanently barred'),
 ('agentLifecycleEventCode','instance_status_changed','Suspend / resume'),
 ('agentLifecycleEventCode','user_verified','Fresh IdP authentication recorded (the server-side time-box)'),
 ('agentLifecycleEventCode','attestation_issued','A Client Attestation was minted for the instance'),
 ('agentLifecycleEventCode','compliance_changed','Device compliance state recorded')
ON CONFLICT (vocab, code, scheme) DO UPDATE SET label = EXCLUDED.label;

-- ---------------------------------------------------------------------------
-- Audit ordering
-- ---------------------------------------------------------------------------
-- A real sequence: created_at is now() (per-transaction) and can tie; a dispute is settled from
-- an unambiguous order.

CREATE SEQUENCE IF NOT EXISTS idm.agent_lifecycle_event_seq;

-- ---------------------------------------------------------------------------
-- Uniqueness + hot-path indexes (partial, class-scoped)
-- ---------------------------------------------------------------------------
-- The PingFederate datasource plugin resolves instance -> device -> owner on EVERY token issuance;
-- each hop is a single unique probe. The same unique indexes are the DUPLICATE guard for
-- register / registerDevice / bindAuthenticator (SQLSTATE 23505 -> RegistryException.DUPLICATE).

CREATE UNIQUE INDEX IF NOT EXISTS entry_agent_instance_subject_uq
    ON idm.entry (subject_id)
 WHERE 'agentInstance' = ANY (object_classes);

CREATE UNIQUE INDEX IF NOT EXISTS entry_agent_device_id_uq
    ON idm.entry ((attrs->>'deviceId'))
 WHERE 'agentDevice' = ANY (object_classes);

CREATE UNIQUE INDEX IF NOT EXISTS entry_authenticator_binding_id_uq
    ON idm.entry ((attrs->>'bindingId'))
 WHERE 'authenticatorBinding' = ANY (object_classes);

-- One party per PingOne subject. NULLs are distinct in a Postgres unique index, so SCIM users who
-- never linked a PingOne account are unaffected. If the target directory already holds two
-- involvedParty rows with the SAME pingoneUserId this index will refuse to build — that is the
-- pre-flight test_migration is for; dedupe first, do not weaken the index.
CREATE UNIQUE INDEX IF NOT EXISTS entry_involved_party_pingone_uq
    ON idm.entry ((attrs->>'pingoneUserId'))
 WHERE 'involvedParty' = ANY (object_classes);

-- auditTrail(instanceId): filter + order in one index.
CREATE INDEX IF NOT EXISTS entry_agent_event_order_idx
    ON idm.entry (subject_id, ((attrs->>'auditSeq')::bigint))
 WHERE 'agentLifecycleEvent' = ANY (object_classes);

-- ---------------------------------------------------------------------------
-- Registry invariants the class trigger cannot express
-- ---------------------------------------------------------------------------
-- BEFORE UPDATE OR DELETE only: nothing here constrains INSERT, and entry_class_check keeps
-- doing its job on INSERT/UPDATE unchanged. This trigger is a backstop; the Java registry's
-- compare-and-set statements are the primary guard, so a violation here means a bug, not a race.

CREATE OR REPLACE FUNCTION idm.check_agent_registry_invariants() RETURNS trigger AS $$
BEGIN
  -- the ledger is append-only: no UPDATE, no DELETE, ever
  IF 'agentLifecycleEvent' = ANY (OLD.object_classes) THEN
    RAISE EXCEPTION 'agentLifecycleEvent entries are append-only (% refused)', TG_OP;
  END IF;

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;

  -- revocation is permanent: a revoked identifier is never reused, never reactivated
  IF 'agentInstance' = ANY (OLD.object_classes)
     AND OLD.record_status = 'revoked' AND NEW.record_status <> 'revoked' THEN
    RAISE EXCEPTION 'agentInstance revocation is permanent (% -> % refused)', OLD.record_status, NEW.record_status;
  END IF;

  -- the App Attest assertion counter must strictly increase; a repeat or a decrease is a replay
  IF 'agentDevice' = ANY (OLD.object_classes)
     AND (NEW.attrs->>'appAttestSignCount')::bigint < (OLD.attrs->>'appAttestSignCount')::bigint THEN
    RAISE EXCEPTION 'agentDevice appAttestSignCount must not decrease (% -> %)',
      OLD.attrs->>'appAttestSignCount', NEW.attrs->>'appAttestSignCount';
  END IF;

  RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS entry_agent_registry_invariants ON idm.entry;
CREATE TRIGGER entry_agent_registry_invariants
  BEFORE UPDATE OR DELETE ON idm.entry
  FOR EACH ROW EXECUTE FUNCTION idm.check_agent_registry_invariants();

-- ---------------------------------------------------------------------------
-- The issuance-path shape, as a view (for ops, explain_query, and a one-round-trip resolve)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW idm.v_agent_instance AS
SELECT i.entry_uuid                        AS instance_entry_uuid,
       i.subject_id                        AS instance_id,
       i.record_status                     AS instance_status,
       i.attrs->>'platformEntityId'        AS platform_entity_id,
       i.attrs->>'agentBuild'              AS agent_build,
       i.attrs->>'cnfJkt'                  AS cnf_jkt,
       i.attrs->>'enrolledAt'              AS enrolled_at,
       i.attrs->>'attestationExp'          AS attestation_exp,
       i.attrs->>'uvLastVerifiedAt'        AS uv_last_verified_at,
       d.entry_uuid                        AS device_entry_uuid,
       d.attrs->>'deviceId'                AS device_id,
       d.attrs->>'platform'                AS platform,
       d.attrs->>'appAttestEnvironment'    AS appattest_environment,
       (d.attrs->>'appAttestSignCount')::bigint AS appattest_sign_count,
       d.attrs->>'complianceState'         AS compliance_state,
       d.attrs->>'complianceCheckedAt'     AS compliance_checked_at,
       o.entry_uuid                        AS owner_entry_uuid,
       o.attrs->>'pingoneUserId'           AS owner_pingone_subject
  FROM idm.entry i
  JOIN idm.entry d
    ON d.entry_uuid = i.parent_id
   AND 'agentDevice' = ANY (d.object_classes)
  LEFT JOIN idm.entry o
    ON o.entry_uuid::text = d.subject_id
   AND 'involvedParty' = ANY (o.object_classes)
 WHERE 'agentInstance' = ANY (i.object_classes);

COMMENT ON VIEW idm.v_agent_instance IS
  'instance -> device -> owner: the resolution the PingFederate datasource plugin performs at token issuance. Nothing in this view is placed in a token; instance_id is the pseudonymous subject, and the owner is reached only through the device.';
-- <<< change

INSERT INTO idm.schema_migration (name, checksum)
VALUES ('006-add-agent-instance-registry', 'sha256:70fe5c766118f22e4511f4ed51bb379ff8d8444d340817de2b3bb8938c7db2a9')
ON CONFLICT (name) DO UPDATE SET checksum = EXCLUDED.checksum, applied_at = now();

COMMIT;
