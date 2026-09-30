package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

/** H2 and HSQLDB were dropped in 0.5.0: an SSF store URL naming either stops the store at start-up, and says what to use. */
class PfJdbcStoreFactoryTest {

    private static SsfConfiguration withJdbcUrl(String url) {
        return new SsfConfiguration.Builder().issuer("https://op.example.com").jdbcUrl(url).build();
    }

    @Test
    void anH2OrHsqldbStoreUrlIsRefusedWithAMessageNamingPostgres() {
        for (String url : List.of("jdbc:hsqldb:mem:ssf", "jdbc:h2:mem:ssf;MODE=PostgreSQL", "Jdbc:Hsqldb:file:/opt/pf/ssf")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> new PfJdbcStoreFactory().create(withJdbcUrl(url)), url);

            assertTrue(e.getMessage().contains("PostgreSQL"), e.getMessage());
            assertTrue(e.getMessage().contains("dropped in 0.5.0"), e.getMessage());
        }
    }

    @Test
    void theRefusalDoesNotRepeatTheUrl() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PfJdbcStoreFactory.refuseDroppedDatabase("jdbc:hsqldb:hsql://db/ssf;password=hunter2"));

        assertFalse(e.getMessage().contains("hunter2"), e.getMessage());
    }

    @Test
    void aPostgresUrlIsNotRefused() {
        PfJdbcStoreFactory.refuseDroppedDatabase("jdbc:postgresql://db:5432/ssf");
        PfJdbcStoreFactory.refuseDroppedDatabase("jdbc:h2x:not-h2");
    }

    /** A connection whose database reports {@code product}, recording whether it was closed. */
    private static Connection connectionTo(String product, AtomicBoolean closed) {
        DatabaseMetaData metaData = (DatabaseMetaData) Proxy.newProxyInstance(DatabaseMetaData.class.getClassLoader(),
                new Class<?>[] {DatabaseMetaData.class}, (proxy, method, args) -> {
                    if ("getDatabaseProductName".equals(method.getName())) {
                        return product;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[] {Connection.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getMetaData":
                            return metaData;
                        case "close":
                            closed.set(true);
                            return null;
                        default:
                            throw new UnsupportedOperationException(method.getName());
                    }
                });
    }

    /** A data store id can name PingFederate's bundled HSQLDB; the names are what the image's drivers report. */
    @Test
    void aDataStoreOnH2OrHsqldbIsRefusedAndItsConnectionClosed() {
        for (String product : List.of("HSQL Database Engine", "H2")) {
            AtomicBoolean closed = new AtomicBoolean();
            SQLException e = assertThrows(SQLException.class,
                    () -> PfJdbcStoreFactory.refuseDroppedProduct(connectionTo(product, closed)), product);

            assertTrue(e.getMessage().contains("PostgreSQL"), e.getMessage());
            assertTrue(e.getMessage().contains("dropped in 0.5.0"), e.getMessage());
            assertTrue(closed.get(), product);
        }
    }

    @Test
    void aDataStoreOnPostgresIsHandedBackOpen() throws SQLException {
        AtomicBoolean closed = new AtomicBoolean();
        Connection connection = connectionTo("PostgreSQL", closed);

        assertSame(connection, PfJdbcStoreFactory.refuseDroppedProduct(connection));
        assertFalse(closed.get());
    }
}
