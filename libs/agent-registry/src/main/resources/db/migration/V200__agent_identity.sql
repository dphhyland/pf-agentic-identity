-- The agent identity registry: resolves a running agent instance to its stable, pseudonymous agent_id.
--
-- Numbered V200, not V1 or V100: libs/device-instance (not yet merged to this branch) already owns
-- V1__instance_registry.sql, and libs/openid-federation owns V100__hosted_entity.sql. All three may run
-- against one eventual shared Flyway history, so version numbers and table names here are namespaced
-- to guarantee no collision regardless of merge order.
--
-- agent_id is opaque text (256 bits of CSPRNG, base64url — see AgentIdMinter), not a sequence: a
-- monotonic integer would leak enrolment order and volume, and be guessable.

CREATE TABLE agent_identity (
    agent_id          TEXT PRIMARY KEY,
    iss               TEXT        NOT NULL,
    client_id         TEXT        NOT NULL,
    instance_format   TEXT        NOT NULL,
    instance_subject  TEXT        NOT NULL,
    minted_at         TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT agent_identity_natural_key
        UNIQUE (iss, client_id, instance_format, instance_subject)
);

COMMENT ON TABLE  agent_identity IS
    'One row per running agent instance ever seen. resolveOrMint upserts on the natural key, so a row is never re-minted for the same instance, and a restart never loses the mapping.';
COMMENT ON COLUMN agent_identity.agent_id IS
    'The pseudonymous identifier: minted once, unique only within iss, never derived from the natural key.';
COMMENT ON COLUMN agent_identity.instance_subject IS
    'The proven, format-specific identifier for this instance (e.g. a SPIFFE ID) — never logged next to agent_id at INFO, which would rebuild the correlation the pseudonym exists to prevent.';
