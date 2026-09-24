-- Trust Marks this entity issues (OpenID Federation 1.0 §7): who is granted which type, and the history of each
-- grant. Nothing records the marks themselves - a mark is minted from its grant and signed with this entity's key,
-- so its status is its signature plus the grant it was minted under (see TrustMarkIssuer).
--
-- V102 follows V100 (hosted_entity); V101 is left for the hosted-entity audit actor column. Plain SQL that runs
-- unchanged on Postgres (the deployment target) and H2 in PostgreSQL-compatibility mode (the test target).

CREATE TABLE trust_mark_grant (
    trust_mark_type TEXT                     NOT NULL,
    subject         TEXT                     NOT NULL,
    status          TEXT                     NOT NULL,
    granted_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after       TIMESTAMP WITH TIME ZONE,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    reason          TEXT,
    actor           TEXT,

    PRIMARY KEY (trust_mark_type, subject),
    CONSTRAINT trust_mark_grant_status_valid CHECK (status IN ('ACTIVE', 'REVOKED')),
    -- A revoked grant says when; a standing one says nothing of revocation.
    CONSTRAINT trust_mark_grant_revocation_consistent
        CHECK ((status = 'REVOKED' AND revoked_at IS NOT NULL) OR (status = 'ACTIVE' AND revoked_at IS NULL))
);

CREATE INDEX trust_mark_grant_subject_idx ON trust_mark_grant (subject, status);
CREATE INDEX trust_mark_grant_type_idx ON trust_mark_grant (trust_mark_type, status);

COMMENT ON TABLE trust_mark_grant IS
    'One row per Trust Mark type and subject. Granting again reactivates the row with a new granted_at, which revokes every mark minted before it.';

CREATE TABLE trust_mark_audit_log (
    seq             BIGSERIAL PRIMARY KEY,
    trust_mark_type TEXT                     NOT NULL,
    subject         TEXT                     NOT NULL,
    event_code      TEXT                     NOT NULL,
    detail          TEXT,
    actor           TEXT,
    at              TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX trust_mark_audit_idx ON trust_mark_audit_log (trust_mark_type, subject, seq);

COMMENT ON TABLE trust_mark_audit_log IS
    'Append-only, written in the same transaction as the grant change it records.';
