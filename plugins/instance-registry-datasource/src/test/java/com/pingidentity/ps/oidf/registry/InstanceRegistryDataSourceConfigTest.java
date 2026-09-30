package com.pingidentity.ps.oidf.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.sources.CustomDataSourceDriverException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;

/**
 * Which database the driver reads (plan item PR-3): a PingFederate data store is the production way, the JDBC URL is
 * development only and refused at configure under production, naming the field to use instead, and a data store that
 * is not PostgreSQL is refused under production at its first connection. The fields are read strictly (ST-5).
 */
class InstanceRegistryDataSourceConfigTest {

    private static final Function<String, String> PRODUCTION = name -> null;
    private static final Function<String, String> DEVELOPMENT =
            name -> DeploymentProfile.SETTING.equals(name) ? "development" : null;

    /** The driver under {@code env}, its two ways to a database answering with the fixture's registry. */
    private static final class Driver extends InstanceRegistryDataSource {
        final List<String> opened = new ArrayList<>();
        final InstanceRegistry registry;

        Driver(Function<String, String> env) throws Exception {
            super(env, TextFieldDescriptor::new);
            this.registry = InstanceRegistryDataSourceTest.InMemoryStyleFixture.withOneHealthyInstance().registry;
        }

        @Override
        protected InstanceRegistry registry(String url) {
            this.opened.add("url " + url);
            return this.registry;
        }

        @Override
        protected InstanceRegistry dataStoreRegistry(String dataStore) {
            this.opened.add("store " + dataStore);
            return this.registry;
        }
    }

    @AfterEach
    void forget() {
        ProfileRefusals.resetForTests();
    }

    private static Map<String, Object> lookUp(InstanceRegistryDataSource driver) throws Exception {
        return driver.retrieveValues(List.of(InstanceLookup.INSTANCE_ACTIVE), InstanceRegistryDataSourceTest.filterOn("agent-1"));
    }

    // ---- the fields --------------------------------------------------------------------------------------------------

    @Test
    void theDataStoreSelectorComesFirstAndTheUrlSaysItIsForDevelopment() {
        List<String> built = new ArrayList<>();
        InstanceRegistryDataSource driver = new InstanceRegistryDataSource(PRODUCTION, (name, description) -> {
            built.add(name);
            return new TextFieldDescriptor(name, description);
        });
        assertEquals(List.of(InstanceRegistryDataSource.CONFIG_DATA_STORE), built, "the data store field is the SDK's selector");
        List<FieldDescriptor> fields = driver.getSourceDescriptor().getConfigurationGuiDescriptor().getFields();
        assertEquals(List.of(InstanceRegistryDataSource.CONFIG_DATA_STORE, InstanceRegistryDataSource.CONFIG_JDBC_URL,
                InstanceRegistryDataSource.CONFIG_UV_MAX_AGE), fields.stream().map(FieldDescriptor::getName).toList());
        assertTrue(fields.get(1).getDescription().startsWith("Development only"), fields.get(1).getDescription());
    }

    @Test
    void aDataStoreIsTheProductionWay() throws Exception {
        Driver driver = new Driver(PRODUCTION);
        driver.configure(" iomDS ", null, null);
        assertNull(driver.refusal());
        assertEquals(List.of("store iomDS"), driver.opened);
        assertEquals(Boolean.TRUE, lookUp(driver).get(InstanceLookup.INSTANCE_ACTIVE));
        assertTrue(driver.testConnection());
    }

    @Test
    void theJdbcUrlIsRefusedUnderProductionNamingTheFieldToUseInstead() throws Exception {
        for (String store : new String[] {null, "iomDS"}) {
            Driver driver = new Driver(PRODUCTION);
            driver.configure(store, "jdbc:postgresql://db/iom?password=hunter2", "300");
            assertNotNull(driver.refusal(), "with the data store " + store);
            assertTrue(driver.refusal().contains("JDBC URL") && driver.refusal().contains("'PingFederate data store' instead"),
                    driver.refusal());
            assertFalse(driver.refusal().contains("hunter2"), "the URL is never repeated");
            assertEquals(List.of(), driver.opened, "nothing is opened");
            CustomDataSourceDriverException e = assertThrows(CustomDataSourceDriverException.class, () -> lookUp(driver));
            assertTrue(e.getMessage().contains("PingFederate data store"), e.getMessage());
            assertFalse(driver.testConnection());
        }
    }

    @Test
    void underDevelopmentTheJdbcUrlWorksAndTheDataStoreWinsOverIt() throws Exception {
        Driver url = new Driver(DEVELOPMENT);
        url.configure(null, "jdbc:postgresql://db/iom", null);
        assertNull(url.refusal());
        assertEquals(List.of("url jdbc:postgresql://db/iom"), url.opened);
        assertEquals(Boolean.TRUE, lookUp(url).get(InstanceLookup.INSTANCE_ACTIVE));

        Driver both = new Driver(DEVELOPMENT);
        both.configure("iomDS", "jdbc:postgresql://db/iom", null);
        assertEquals(List.of("store iomDS"), both.opened);
    }

    @Test
    void noDatabaseAtAllIsARefusalNotAGuess() throws Exception {
        Driver driver = new Driver(PRODUCTION);
        driver.configure("  ", "", null);
        assertTrue(driver.refusal().contains("no database is configured"), driver.refusal());
        assertThrows(CustomDataSourceDriverException.class, () -> lookUp(driver));
    }

    @Test
    void theUserVerificationWindowIsReadStrictly() throws Exception {
        Driver padded = new Driver(PRODUCTION);
        padded.configure("iomDS", null, " 120 ");
        assertNull(padded.refusal());

        Driver words = new Driver(PRODUCTION);
        words.configure("iomDS", null, "five minutes");
        assertTrue(words.refusal().contains(InstanceRegistryDataSource.CONFIG_UV_MAX_AGE), words.refusal());
        assertEquals(List.of(), words.opened, "a field that does not parse configures nothing - before 0.6.0 it was 300");

        Driver configuredAgain = new Driver(PRODUCTION);
        configuredAgain.configure("iomDS", null, "five minutes");
        configuredAgain.configure("iomDS", null, null);
        assertNull(configuredAgain.refusal(), "a later configure that is right clears the refusal");
    }

    // ---- the data store's database -----------------------------------------------------------------------------------

    /** A connection whose database says it is {@code product}, counting closes. */
    private static Connection connection(String product, AtomicInteger closed) {
        DatabaseMetaData metadata = (DatabaseMetaData) Proxy.newProxyInstance(DatabaseMetaData.class.getClassLoader(),
                new Class<?>[] {DatabaseMetaData.class}, (proxy, m, args) -> "getDatabaseProductName".equals(m.getName()) ? product : null);
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[] {Connection.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "getMetaData" -> metadata;
                    case "close" -> {
                        closed.incrementAndGet();
                        yield null;
                    }
                    default -> null;
                });
    }

    @Test
    void aPostgresqlDataStoreIsAskedOnceAndUsed() throws Exception {
        AtomicInteger asked = new AtomicInteger();
        AtomicInteger closed = new AtomicInteger();
        InstanceRegistryDataSource.DataStoreSource source = new InstanceRegistryDataSource.DataStoreSource("iomDS", name -> {
            asked.incrementAndGet();
            assertEquals("iomDS", name, "the data store's JNDI name, which PingFederate sets to its id");
            return connection("PostgreSQL", closed);
        });
        assertNotNull(source.getConnection());
        assertNotNull(source.getConnection("ignored", "ignored"));
        assertEquals(2, asked.get());
        assertEquals(0, closed.get());
        assertSame(source, source.unwrap(InstanceRegistryDataSource.DataStoreSource.class));
        assertTrue(source.isWrapperFor(javax.sql.DataSource.class));
        assertThrows(SQLException.class, () -> source.unwrap(String.class));
    }

    @Test
    void aDataStoreThatIsNotPostgresqlIsRefusedUnderProduction() throws Exception {
        assumeTrue(DeploymentProfile.current().isProduction(), "this JVM runs under the development profile");
        ProfileRefusals.resetForTests();
        AtomicInteger closed = new AtomicInteger();
        InstanceRegistryDataSource.DataStoreSource source =
                new InstanceRegistryDataSource.DataStoreSource("pingDS", name -> connection("HSQL Database Engine", closed));
        ProfileRefused refused = assertThrows(ProfileRefused.class, source::getConnection);
        assertTrue(refused.getMessage().contains("'pingDS' is HSQL Database Engine, not PostgreSQL"), refused.getMessage());
        assertEquals(1, closed.get(), "the connection goes back to PingFederate's pool");
        assertThrows(ProfileRefused.class, source::getConnection, "and every later one");
        assertTrue(ProfileRefusals.codeRefusals().stream().anyMatch(v -> v.components().contains(InstanceRegistryDataSource.COMPONENT)));
    }

    @Test
    void underDevelopmentAnotherDatabaseIsAWarning() throws Exception {
        ProfileRefusals.publish(ProfileAudit.Result.empty(DeploymentProfile.DEVELOPMENT));
        AtomicInteger closed = new AtomicInteger();
        InstanceRegistryDataSource.DataStoreSource source =
                new InstanceRegistryDataSource.DataStoreSource("mysqlDS", name -> connection("MySQL", closed));
        assertNotNull(source.getConnection());
        assertNotNull(source.getConnection());
        assertEquals(0, closed.get());
    }

    @Test
    void aConnectionThatCannotBeHadIsAnSqlException() {
        SQLException direct = new SQLException("pool exhausted");
        InstanceRegistryDataSource.DataStoreSource sql = new InstanceRegistryDataSource.DataStoreSource("iomDS", name -> {
            throw direct;
        });
        assertSame(direct, assertThrows(SQLException.class, sql::getConnection));
        InstanceRegistryDataSource.DataStoreSource jndi = new InstanceRegistryDataSource.DataStoreSource("nope", name -> {
            throw new javax.naming.NameNotFoundException(name);
        });
        SQLException wrapped = assertThrows(SQLException.class, jndi::getConnection);
        assertTrue(wrapped.getMessage().contains("PingFederate data store 'nope'"), wrapped.getMessage());
    }
}
