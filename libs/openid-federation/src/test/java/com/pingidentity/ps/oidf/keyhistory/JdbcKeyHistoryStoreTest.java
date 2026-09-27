package com.pingidentity.ps.oidf.keyhistory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * The JDBC history on PostgreSQL - a database of this class's own (libs/testkit) - running the federation family's
 * shipped migrations, {@code V103__federation_key_history.sql} among them. Each test starts from an empty schema
 * with the family applied.
 */
class JdbcKeyHistoryStoreTest extends KeyHistoryStoreContract {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    private DataSource dataSource;

    @Override
    protected KeyHistoryStore newStore() throws Exception {
        this.dataSource = POSTGRES.dataSource();
        POSTGRES.resetPublicSchema();
        Migrations.apply(this.dataSource, 100, 199);
        return new JdbcKeyHistoryStore(this.dataSource);
    }

    private void execute(String sql) throws SQLException {
        try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }

    /** A rotation that cannot record the retired key leaves the key in use as it was. */
    @Test
    void aRotationIsOneTransaction() throws Exception {
        KeyHistoryStore store = this.newStore();
        store.rotateTo(K1, T0, T0.plusSeconds(60));
        this.execute("DROP TABLE federation_key_history");

        assertEquals(AuthorityRegistryException.STORAGE_FAILURE, assertThrows(AuthorityRegistryException.class,
                () -> store.rotateTo(K2, T1, T1.plusSeconds(60))).reason());

        this.execute("CREATE TABLE federation_key_history (kid TEXT PRIMARY KEY, jwk TEXT NOT NULL, issued_at TIMESTAMP WITH TIME ZONE,"
                + " expires_at TIMESTAMP WITH TIME ZONE NOT NULL, revoked_at TIMESTAMP WITH TIME ZONE, reason TEXT)");
        assertEquals("k1", store.rotateTo(K2, T1, T1.plusSeconds(60)).orElseThrow().kid(), "k1 was still the key in use");
    }

    @Test
    void aDamagedRowIsAStorageFailureNotAnEmptyKey() throws Exception {
        KeyHistoryStore store = this.newStore();
        this.execute("INSERT INTO federation_key_history (kid, jwk, expires_at) VALUES ('k9', 'not json', CURRENT_TIMESTAMP)");

        assertEquals(AuthorityRegistryException.STORAGE_FAILURE, assertThrows(AuthorityRegistryException.class, store::retired).reason());
    }

    @Test
    void theSchemaHoldsOneKeyInUseAndNoReasonWithoutARevocation() throws Exception {
        this.newStore();

        assertThrows(SQLException.class, () -> this.execute("INSERT INTO federation_key_current (slot, kid, jwk, since) VALUES ('other', 'k', '{}',"
                + " CURRENT_TIMESTAMP)"));
        assertThrows(SQLException.class, () -> this.execute("INSERT INTO federation_key_history (kid, jwk, expires_at, reason) VALUES ('k', '{}',"
                + " CURRENT_TIMESTAMP, 'compromised')"));
        assertEquals(List.of(), new JdbcKeyHistoryStore(this.dataSource).retired());
    }

    /** Moved here from KeyHistoryTest, which needs no database: the shared view reaches the JDBC store once it is configured. */
    @Test
    void theSharedViewUsesWhicheverStoreIsConfigured() throws Exception {
        this.newStore();
        KeyHistorySupport.resetForTests();
        try {
            KeyHistoryStore shared = KeyHistorySupport.shared();
            KeyHistorySupport.configureJdbcStore(this.dataSource);

            shared.rotateTo(K1, T0, T0);
            shared.rotateTo(K2, T0, T0);

            assertInstanceOf(JdbcKeyHistoryStore.class, KeyHistorySupport.store());
            assertEquals("k1", shared.retired().get(0).kid());
            assertEquals("superseded", shared.revoke("k1", T0, "superseded").reason());
        } finally {
            KeyHistorySupport.resetForTests();
        }
    }
}
