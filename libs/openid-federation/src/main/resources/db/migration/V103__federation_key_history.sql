-- This entity's Federation Entity Keys over time (OpenID Federation 1.0 §8.7): the one it signs with now, and the ones
-- it signed with before, published at its historical keys endpoint so statements signed before a rotation stay
-- verifiable - until they expire, or unless a key is revoked.
--
-- Plain SQL that runs unchanged on Postgres (the deployment target) and H2 in PostgreSQL-compatibility mode (the
-- test target). JWKs are stored as JSON text, like the hosted-entity metadata in V100.

CREATE TABLE federation_key_current (
    slot  TEXT                     PRIMARY KEY,
    kid   TEXT                     NOT NULL,
    jwk   TEXT                     NOT NULL,
    since TIMESTAMP WITH TIME ZONE NOT NULL,

    -- One row: the key this entity signs with now. Kept so a rotation is noticed across a restart.
    CONSTRAINT federation_key_current_one_slot CHECK (slot = 'signing')
);

CREATE TABLE federation_key_history (
    kid        TEXT                     PRIMARY KEY,
    jwk        TEXT                     NOT NULL,
    issued_at  TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    reason     TEXT,

    CONSTRAINT federation_key_history_reason_needs_revocation CHECK (reason IS NULL OR revoked_at IS NOT NULL)
);

COMMENT ON TABLE federation_key_history IS
    'Keys this entity no longer signs with. A revoked key stays revoked: it must never sign again, and nothing here un-revokes it.';
