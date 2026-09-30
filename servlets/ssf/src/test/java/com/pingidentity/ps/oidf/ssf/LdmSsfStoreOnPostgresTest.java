/*
 * The Identity Object Model store's whole contract on PostgreSQL, on the model repo's own migrations.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * {@link LdmSsfStore} held to {@link SsfStoreContract} on PostgreSQL - a database of this class's own
 * (libs/testkit) - on the model repo's {@code 0000} and {@code 0001} migrations, vendored under
 * {@code src/test/resources/idm/}: the schema the store writes to and never creates. Each test starts from an empty
 * {@code idm.entry}. {@code LdmSsfStoreTest} pins the SQL as text with Mockito; this is where it runs.
 */
class LdmSsfStoreOnPostgresTest extends SsfStoreContract {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    @BeforeAll
    static void modelSchema() throws Exception {
        Migrations.applyResources(POSTGRES.dataSource(), LdmSsfStoreOnPostgresTest.class,
                "/idm/0000-base-schema.sql", "/idm/0001-add-shared-signals-ssf.sql");
    }

    @Override
    protected SsfStore newStore() throws SQLException {
        try (Connection c = POSTGRES.dataSource().getConnection(); Statement s = c.createStatement()) {
            s.execute("TRUNCATE idm.entry CASCADE");
        }
        return new LdmSsfStore(POSTGRES.dataSource());
    }

    /**
     * F-0150: the store writes {@code modified_at = to_timestamp(updatedAt)}, and the model's {@code entry_class_check}
     * trigger overwrites it with {@code now()} on every INSERT and UPDATE, so a stream reads back with the database's
     * time of its last write. Nothing reads a stream's {@code updatedAt} today; this pins what it is.
     */
    @Override
    protected void assertUpdatedAt(long written, Stream read) {
        long now = System.currentTimeMillis() / 1000;
        assertTrue(Math.abs(read.updatedAt() - now) <= 60, "the database's clock, not " + written + ": " + read.updatedAt());
    }
}
