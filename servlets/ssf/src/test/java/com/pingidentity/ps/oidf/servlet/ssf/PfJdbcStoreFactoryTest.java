package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
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

    /** A data source whose one connection reports {@code product}. */
    private static DataSource dataSource(Connection connection) {
        return (DataSource) Proxy.newProxyInstance(DataSource.class.getClassLoader(), new Class<?>[] {DataSource.class},
                (proxy, method, args) -> {
                    if ("getConnection".equals(method.getName())) {
                        return connection;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    @AfterEach
    void forgetRefusals() {
        ProfileRefusals.resetForTests();
    }

    private static void profile(DeploymentProfile profile) {
        ProfileRefusals.publish(new ProfileAudit.Result(profile, List.of(), List.of()));
    }

    /**
     * A data store id can name PingFederate's bundled HSQLDB; the names are what the image's drivers report. Refused in
     * every profile, as a configuration fault (not retried), with the connection closed.
     */
    @Test
    void aDataStoreOnH2OrHsqldbIsRefusedAndItsConnectionClosed() {
        profile(DeploymentProfile.DEVELOPMENT);
        for (String product : List.of("HSQL Database Engine", "H2")) {
            AtomicBoolean closed = new AtomicBoolean();
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> PfJdbcStoreFactory.checkDatabase(dataSource(connectionTo(product, closed)), "PingFederate data store 'ds'"), product);

            assertTrue(e.getMessage().contains("PostgreSQL"), e.getMessage());
            assertTrue(e.getMessage().contains("dropped in 0.5.0"), e.getMessage());
            assertTrue(closed.get(), product);
            assertFalse(SsfComponents.dependency(e), "a configuration fault: not retried");
        }
    }

    @Test
    void aDataStoreOnPostgresIsHandedBackOpen() throws SQLException {
        AtomicBoolean closed = new AtomicBoolean();
        Connection connection = connectionTo("PostgreSQL", closed);

        assertSame(connection, PfJdbcStoreFactory.refuseDroppedProduct(connection));
        assertFalse(closed.get());
    }

    @Test
    void aPostgresDatabaseIsTakenInProductionAndItsConnectionClosed() {
        profile(DeploymentProfile.PRODUCTION);
        AtomicBoolean closed = new AtomicBoolean();

        PfJdbcStoreFactory.checkDatabase(dataSource(connectionTo("PostgreSQL", closed)), "PingFederate data store 'ds'");

        assertTrue(closed.get());
        assertEquals(List.of(), ProfileRefusals.codeRefusals());
    }

    /** Plan decision 10: the SSF store is PostgreSQL, told by the product name the driver reports. */
    @Test
    void anotherDatabaseIsRefusedInProductionNamingItAndTheStore() {
        profile(DeploymentProfile.PRODUCTION);
        AtomicBoolean closed = new AtomicBoolean();

        ProfileRefused e = assertThrows(ProfileRefused.class,
                () -> PfJdbcStoreFactory.checkDatabase(dataSource(connectionTo("MySQL", closed)), "PingFederate data store 'ds'"));

        assertTrue(e.getMessage().contains("the SSF store's database (PingFederate data store 'ds') is MySQL, not PostgreSQL"),
                e.getMessage());
        assertTrue(closed.get());
        assertEquals(1, ProfileRefusals.codeRefusals().size());
    }

    @Test
    void anotherDatabaseIsUsedInDevelopment() {
        profile(DeploymentProfile.DEVELOPMENT);

        PfJdbcStoreFactory.checkDatabase(dataSource(connectionTo("Microsoft SQL Server", new AtomicBoolean())), "OIDF_SSF_JDBC_URL");

        assertEquals(List.of(), ProfileRefusals.codeRefusals(), "a WARN, not a refusal");
    }

    @Test
    void aDatabaseThatCannotBeReachedIsADependencyFailure() {
        DataSource down = (DataSource) Proxy.newProxyInstance(DataSource.class.getClassLoader(), new Class<?>[] {DataSource.class},
                (proxy, method, args) -> {
                    throw new SQLException("Connection refused");
                });

        IllegalStateException e = assertThrows(IllegalStateException.class, () -> PfJdbcStoreFactory.checkDatabase(down, "OIDF_SSF_JDBC_URL"));

        assertTrue(e.getMessage().contains("could not be reached"), e.getMessage());
        assertTrue(SsfComponents.dependency(e));
    }

    @Test
    void aJdbcUrlIsNamedByItsSchemeOnly() {
        assertEquals("jdbc:mysql:", PfJdbcStoreFactory.scheme("jdbc:mysql://db/ssf?password=hunter2"));
        assertEquals("non-JDBC", PfJdbcStoreFactory.scheme("postgres"));
        assertEquals("non-JDBC", PfJdbcStoreFactory.scheme("jdbc"));
    }
}
