package com.pingidentity.ps.oidf.keyhistory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;

/** The JDBC history against H2 in PostgreSQL mode, running the shipped {@code V103__federation_key_history.sql}. */
class JdbcKeyHistoryStoreTest extends KeyHistoryStoreContract {
    private static final AtomicInteger DB_COUNTER = new AtomicInteger();
    private DataSource dataSource;

    @Override
    protected KeyHistoryStore newStore() throws Exception {
        JdbcDataSource h2 = new JdbcDataSource();
        h2.setURL("jdbc:h2:mem:keyhistory" + DB_COUNTER.incrementAndGet() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
        h2.setUser("sa");
        this.dataSource = h2;
        try (InputStream in = JdbcKeyHistoryStoreTest.class.getResourceAsStream("/db/migration/V103__federation_key_history.sql")) {
            assertNotNull(in, "the migration must ship on the classpath");
            this.execute(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        return new JdbcKeyHistoryStore(h2);
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
}
