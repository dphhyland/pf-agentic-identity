# Vendored Identity Object Model migrations

Copies of the model repo's migrations, applied in filename order by `IomInstanceRegistryTest` to build
the schema `IomInstanceRegistry` writes to. They are **copies, not the source of truth**.

| File | Source |
|---|---|
| `0000-base-schema.sql` | `~/Source/idp-scim-service/migrations/0000-base-schema.sql` |
| `002-backfill-may-attrs.sql` | same directory |
| `006-add-agent-instance-registry.sql` | same directory — the one that registers `agentInstance`, `agentDevice`, `authenticatorBinding`, `agentLifecycleEvent` |

**Refreshing.** Copy them over when the model changes. Each carries an `-- ldm-checksum:` header; if the
header here differs from the file in the model repo, this copy is stale and the tests are proving
something about a schema that no longer exists.

**Ordering matters.** `002` sets `may_attrs` *absolutely* while `006` *appends* `pingoneUserId` to
`involvedParty` — so `002` must be applied before `006`, or `006` re-run afterwards (it is idempotent).
Applying `002` last silently drops `pingoneUserId` from the declared MAY list. Filename order gives the
correct sequence; keep it.
