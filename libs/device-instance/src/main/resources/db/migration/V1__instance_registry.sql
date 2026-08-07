-- The agent instance registry.
--
-- This schema is the one place an opaque instance identifier resolves to a device and a human.
-- Everything downstream depends on that: the attestation carries a pseudonymous subject, the delegated
-- token carries it as act.sub, and a resource server can risk-assess on it while learning nothing else.
-- Resolution happens here and nowhere else.
--
-- Two shapes are deliberate:
--   * identifiers are opaque text, not sequences. A monotonic integer leaks enrolment order and volume,
--     and is guessable; these are 256 bits of CSPRNG, base64url.
--   * audit_log has no UPDATE or DELETE path. It is the record a dispute is settled from.

CREATE TABLE owner_user (
    id               TEXT PRIMARY KEY,
    pingone_subject  TEXT        NOT NULL UNIQUE,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL
);

COMMENT ON TABLE  owner_user IS 'The only table that identifies a person.';
COMMENT ON COLUMN owner_user.id IS
    'Registry-internal identifier, distinct from the IdP subject so the two rotate independently.';

CREATE TABLE device (
    id                     TEXT PRIMARY KEY,
    platform               TEXT        NOT NULL,
    model                  TEXT,
    os_version             TEXT,
    appattest_key_id       TEXT        NOT NULL,
    appattest_environment  TEXT        NOT NULL,
    appattest_sign_count   BIGINT      NOT NULL DEFAULT 0,
    compliance_state       TEXT        NOT NULL DEFAULT 'UNKNOWN',
    compliance_checked_at  TIMESTAMP WITH TIME ZONE,
    owner_user_id          TEXT        NOT NULL REFERENCES owner_user (id),

    CONSTRAINT device_compliance_state_valid
        CHECK (compliance_state IN ('COMPLIANT', 'NOT_COMPLIANT', 'UNKNOWN')),
    -- A device enrolled against Apple's development attestation service must stay distinguishable
    -- forever; a development enrolment silently passing as production is the failure this prevents.
    CONSTRAINT device_appattest_environment_valid
        CHECK (appattest_environment IN ('appattest', 'appattestdevelop'))
);

CREATE INDEX device_owner_idx ON device (owner_user_id);

COMMENT ON TABLE device IS 'Enrolled devices. Nothing in this table is ever placed in a token or shown to a resource server.';
COMMENT ON COLUMN device.appattest_key_id IS
    'Apple advises persisting the key id, not the attestation object.';
COMMENT ON COLUMN device.appattest_sign_count IS
    'Highest assertion counter seen. Must strictly increase; a repeat is a replay.';

CREATE TABLE agent_instance (
    id                  TEXT PRIMARY KEY,
    platform_entity_id  TEXT        NOT NULL,
    agent_build         TEXT,
    cnf_jkt             TEXT        NOT NULL,
    status              TEXT        NOT NULL DEFAULT 'ACTIVE',
    device_id           TEXT        NOT NULL REFERENCES device (id),
    enrolled_at         TIMESTAMP WITH TIME ZONE NOT NULL,
    attestation_exp     TIMESTAMP WITH TIME ZONE,
    uv_last_verified_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT agent_instance_status_valid
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED'))
);

CREATE INDEX agent_instance_device_idx ON agent_instance (device_id);
CREATE INDEX agent_instance_status_idx ON agent_instance (status);

COMMENT ON COLUMN agent_instance.id IS
    'The pseudonymous identifier: the attestation sub and the delegated token act.sub.';
COMMENT ON COLUMN agent_instance.cnf_jkt IS
    'RFC 7638 thumbprint of the Secure Enclave key bound at enrolment.';
COMMENT ON COLUMN agent_instance.uv_last_verified_at IS 'The server-side time-box: the device holds a pre-authenticated LAContext with no documented expiry, so only this timestamp bounds the window in a way an attacker on the device cannot extend.';

CREATE TABLE bound_authenticator (
    id                 TEXT PRIMARY KEY,
    device_id          TEXT        NOT NULL REFERENCES device (id),
    credential_id      TEXT        NOT NULL,
    aaguid             TEXT,
    authenticator_type TEXT        NOT NULL,
    bound_at           TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX bound_authenticator_device_idx ON bound_authenticator (device_id);

COMMENT ON TABLE bound_authenticator IS 'Which authenticator proved the human at enrolment. NIST SP 800-63B requires enrolment evidence to be a first-class record, not a boolean, because a dispute needs the provenance.';

CREATE TABLE audit_log (
    seq         BIGSERIAL PRIMARY KEY,
    instance_id TEXT,
    event_code  TEXT        NOT NULL,
    detail      TEXT,
    at          TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX audit_log_instance_idx ON audit_log (instance_id, seq);

COMMENT ON TABLE audit_log IS 'Append-only. No UPDATE or DELETE path exists by design. instance_id is nullable so device- and owner-level events have somewhere to live.';
