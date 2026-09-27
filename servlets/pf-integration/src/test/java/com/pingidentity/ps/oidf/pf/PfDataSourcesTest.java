package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

/** H2 and HSQLDB were dropped in 0.5.0: a direct URL naming either stops the component at start-up, and says what to use. */
class PfDataSourcesTest {

    @Test
    void anH2OrHsqldbUrlIsRefusedWithAMessageNamingPostgres() {
        for (String url : List.of("jdbc:h2:mem:authority;MODE=PostgreSQL", "jdbc:hsqldb:mem:authority", "JDBC:H2:file:/tmp/x",
                "jdbc:HSQLDB:hsql://localhost/pf")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> PfDataSources.direct(url, "sa", ""), url);

            assertTrue(e.getMessage().contains("PostgreSQL"), e.getMessage());
            assertTrue(e.getMessage().contains("dropped in 0.5.0"), e.getMessage());
        }
    }

    /** The rest of a JDBC URL can carry a password; the refusal names only the prefix. */
    @Test
    void theRefusalDoesNotRepeatTheUrl() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PfDataSources.direct("jdbc:h2:tcp://db/x;PASSWORD=hunter2", "sa", ""));

        assertFalse(e.getMessage().contains("hunter2"), e.getMessage());
    }

    @Test
    void anyOtherUrlIsLeftToTheDriverManager() {
        assertNotNull(PfDataSources.direct("jdbc:nowhere:authority", "u", "p"));
        assertNotNull(PfDataSources.direct("jdbc:h2x:not-h2", "u", "p"), "a prefix match, not a substring one");
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
                    () -> PfDataSources.refuseDroppedProduct(connectionTo(product, closed)), product);

            assertTrue(e.getMessage().contains("PostgreSQL"), e.getMessage());
            assertTrue(e.getMessage().contains("dropped in 0.5.0"), e.getMessage());
            assertTrue(closed.get(), product);
        }
    }

    @Test
    void aDataStoreOnPostgresIsHandedBackOpen() throws SQLException {
        AtomicBoolean closed = new AtomicBoolean();
        Connection connection = connectionTo("PostgreSQL", closed);

        assertSame(connection, PfDataSources.refuseDroppedProduct(connection));
        assertFalse(closed.get());
    }
}
