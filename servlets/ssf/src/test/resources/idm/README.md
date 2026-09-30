# Vendored Identity Object Model migrations

Copies of the model repo's migrations, applied in filename order by `SsfStoresOnPostgresTest` and
`LdmSsfStoreOnPostgresTest` to build the schema `LdmSsfStore` writes to. They are **copies, not the source of truth**.

| File | Source |
|---|---|
| `0000-base-schema.sql` | `~/Source/idp-scim-service/migrations/0000-base-schema.sql`, the same file [libs/device-instance](../../../../../../libs/device-instance/src/test/resources/idm/README.md) vendors |
| `0001-add-shared-signals-ssf.sql` | same directory: the migration that registers `ssfStream`, `ssfStreamSubject` and `ssfPendingSet` |

Copied 2026-09-27 from the model repo at `cb90151`. Each carries an `-- ldm-checksum:` header; if the header here
differs from the file in the model repo, this copy is stale and the test is proving something about a schema that
no longer exists. Refresh `0000` here and in `libs/device-instance` together.

`002` to `006` are not needed: none of them touches the three SSF classes.
