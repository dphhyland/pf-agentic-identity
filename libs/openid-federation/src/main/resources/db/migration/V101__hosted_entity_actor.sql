-- Who made each change to a hosted entity. The audit log is the record a resolution dispute is settled from; it now
-- says who, as well as what and when: "admin:" and eight hex digits of the admin token's SHA-256, with the name the
-- caller gave itself after it when it sent one. Rows written before this migration have no actor.

ALTER TABLE hosted_entity_audit_log ADD COLUMN actor TEXT;

COMMENT ON COLUMN hosted_entity_audit_log.actor IS
    'Who made the change: admin:<first 8 hex of SHA-256(admin token)> [ (name the caller gave) ]. NULL for rows from before V101 or written by the system.';
