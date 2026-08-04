-- The hosted-entity registry: federation metadata the authority publishes on behalf of entities that
-- cannot host their own (an ephemeral agent, most protected resources).
--
-- Numbered V100, not V1: libs/device-instance (not yet merged to this branch, but sharing this
-- monorepo's eventual single Flyway history) already owns V1__instance_registry.sql. Both migrations
-- may run against one schema, so table and migration-version names in this file are namespaced
-- ("hosted_entity", never bare "audit_log") to guarantee no collision regardless of merge order.
--
-- metadata and metadata_policy are stored as serialized JSON text, not a database-specific JSON type,
-- so the schema and every query against it are identical on Postgres (the deployment target) and H2 in
-- PostgreSQL-compatibility mode (the test target).

CREATE TABLE hosted_entity (
    entity_id       TEXT PRIMARY KEY,
    hosting_mode    TEXT        NOT NULL,
    hosting_key_ref TEXT,
    metadata        TEXT        NOT NULL,
    metadata_policy TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'ACTIVE',
    listable        BOOLEAN     NOT NULL DEFAULT FALSE,
    owner_ref       TEXT,
    registered_at   TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after       TIMESTAMP WITH TIME ZONE,

    CONSTRAINT hosted_entity_status_valid
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    CONSTRAINT hosted_entity_hosting_mode_valid
        CHECK (hosting_mode IN ('AUTHORITY_SIGNED', 'SELF_SIGNED')),
    -- Mirrors HostedEntity's own compact-constructor check: a database write that bypassed Java (a
    -- future migration, a manual fix) must not be able to create an AUTHORITY_SIGNED entity with no key
    -- to sign it, or a SELF_SIGNED one the authority wrongly believes it can sign.
    CONSTRAINT hosted_entity_authority_signed_has_key
        CHECK ((hosting_mode = 'AUTHORITY_SIGNED' AND hosting_key_ref IS NOT NULL)
            OR (hosting_mode = 'SELF_SIGNED' AND hosting_key_ref IS NULL))
);

CREATE INDEX hosted_entity_status_idx ON hosted_entity (status);

COMMENT ON TABLE  hosted_entity IS
    'Federation entities this authority hosts metadata for. A revoked row stops resolving on the very next lookup — no cache, no propagation delay.';
COMMENT ON COLUMN hosted_entity.entity_id IS
    'The entity''s federation identifier — an HTTPS URL under the authority''s own domain. Permanent for the life of this row; never derived from a request.';
COMMENT ON COLUMN hosted_entity.listable IS
    'Whether this entity appears in /federation/list. Agents default to FALSE: listing would publish an inventory of identifiers whose whole purpose is being uncorrelatable without this registry.';

CREATE TABLE hosted_entity_audit_log (
    seq         BIGSERIAL PRIMARY KEY,
    entity_id   TEXT        NOT NULL,
    event_code  TEXT        NOT NULL,
    detail      TEXT,
    at          TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX hosted_entity_audit_idx ON hosted_entity_audit_log (entity_id, seq);

COMMENT ON TABLE hosted_entity_audit_log IS
    'Append-only. No UPDATE or DELETE path exists by design — this is the record a resolution dispute is settled from.';
