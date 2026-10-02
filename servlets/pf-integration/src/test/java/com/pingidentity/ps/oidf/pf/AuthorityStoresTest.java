/*
 * PR-2 for the federation stores: in memory needs the in-memory-state risk in production, and a database is PostgreSQL.
 */
package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.authority.AuthoritySupportTestAccess;
import com.pingidentity.ps.oidf.keyhistory.KeyHistorySupport;
import com.pingidentity.ps.oidf.keyhistory.KeyHistorySupportTestAccess;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupport;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupportTestAccess;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The authority's stores - the hosted entities, the Trust Mark grants and the key history - under the production
 * profile (Phase 3 plan, decisions 9, 10 and 15): a store in memory refuses its component unless the
 * {@code in-memory-state} risk is accepted, and a database that is not PostgreSQL refuses it; under development each is
 * a warning and the store is used.
 */
class AuthorityStoresTest {

    private static final String URL_PROPERTY = "oidf.authority.jdbc.url";

    @BeforeEach
    @AfterEach
    void reset() {
        ProfileRefusals.resetForTests();
        TrustMarkSupportTestAccess.reset();
        KeyHistorySupportTestAccess.reset();
        AuthoritySupportTestAccess.reset();
        System.clearProperty(URL_PROPERTY);
    }

    private static void profile(DeploymentProfile profile) {
        ProfileRefusals.publish(new ProfileAudit.Result(profile, List.of(), List.of()));
    }

    /** A data source whose one connection says it is {@code product}; null for one that cannot be reached. */
    private static DataSource database(String product) {
        return (DataSource) Proxy.newProxyInstance(DataSource.class.getClassLoader(), new Class<?>[] {DataSource.class}, (p, m, a) -> {
            if (!"getConnection".equals(m.getName())) {
                throw new UnsupportedOperationException(m.getName());
            }
            if (product == null) {
                throw new SQLException("connection refused");
            }
            DatabaseMetaData meta = (DatabaseMetaData) Proxy.newProxyInstance(DatabaseMetaData.class.getClassLoader(),
                    new Class<?>[] {DatabaseMetaData.class}, (p2, m2, a2) -> product);
            return Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[] {Connection.class},
                    (p3, m3, a3) -> "getMetaData".equals(m3.getName()) ? meta : null);
        });
    }

    @Test
    void aStoreInMemoryRefusesItsComponentInProductionWithoutTheRisk() {
        profile(DeploymentProfile.PRODUCTION);

        ProfileRefused marks = assertThrows(ProfileRefused.class, () -> AuthorityDataSource.trustMarkRegistry(Startup.FEDERATION));
        assertTrue(marks.getMessage().contains("the Trust Mark registry is in memory"), marks.getMessage());
        assertTrue(marks.getMessage().contains("in-memory-state"), marks.getMessage());
        ProfileRefused history = assertThrows(ProfileRefused.class, () -> AuthorityDataSource.keyHistoryStore(Startup.FEDERATION));
        assertTrue(history.getMessage().contains("the key history is in memory"), history.getMessage());
        assertEquals(List.of(Startup.FEDERATION), ProfileRefusals.codeRefusals().get(0).components(), "listed for the start-up audit");
        assertFalse(TrustMarkSupport.isConfigured());
        assertFalse(KeyHistorySupport.isConfigured());
    }

    @Test
    void underDevelopmentAStoreInMemoryIsAWarning() {
        profile(DeploymentProfile.DEVELOPMENT);

        assertDoesNotThrow(() -> AuthorityDataSource.trustMarkRegistry(Startup.FEDERATION));
        assertDoesNotThrow(() -> AuthorityDataSource.keyHistoryStore(Startup.FEDERATION));
        assertEquals(List.of(), ProfileRefusals.codeRefusals());
        assertFalse(TrustMarkSupport.isConfigured(), "the first use falls back to memory, as before");
    }

    @Test
    void aPostgreSqlStoreIsConfiguredAndAStoreAlreadyChosenIsKept() {
        profile(DeploymentProfile.PRODUCTION);

        AuthorityDataSource.trustMarkRegistry(Startup.FEDERATION, java.util.Optional.of(database("PostgreSQL")));
        AuthorityDataSource.keyHistoryStore(Startup.FEDERATION, java.util.Optional.of(database("PostgreSQL")));

        assertTrue(TrustMarkSupport.isConfigured());
        assertTrue(KeyHistorySupport.isConfigured());
        assertEquals(List.of(), ProfileRefusals.codeRefusals());
        assertDoesNotThrow(() -> AuthorityDataSource.trustMarkRegistry(Startup.FEDERATION), "configured: nothing more to choose");
        assertDoesNotThrow(() -> AuthorityDataSource.keyHistoryStore(Startup.FEDERATION));
    }

    /** A direct PostgreSQL URL is judged by its scheme without a connection. */
    @Test
    void aDirectPostgreSqlUrlIsTakenWithoutAConnection() {
        profile(DeploymentProfile.PRODUCTION);
        System.setProperty(URL_PROPERTY, "jdbc:postgresql://db.internal/idm");

        AuthorityDataSource.trustMarkRegistry(Startup.FEDERATION);

        assertTrue(TrustMarkSupport.isConfigured());
        assertEquals(List.of(), ProfileRefusals.codeRefusals());
    }

    /**
     * The scheme spelt in another case is not PostgreSQL's: PostgreSQL's driver accepts only {@code jdbc:postgresql:}, so
     * such a URL would pass a check that ignored case and then fail at first use.
     */
    @Test
    void aPostgreSqlSchemeInAnotherCaseIsRefusedInProduction() {
        profile(DeploymentProfile.PRODUCTION);
        System.setProperty(URL_PROPERTY, "JDBC:PostgreSQL://db.internal/idm");

        ProfileRefused refused = assertThrows(ProfileRefused.class, () -> AuthorityDataSource.trustMarkRegistry(Startup.FEDERATION));

        assertTrue(refused.getMessage().contains("names a JDBC:PostgreSQL: database"), refused.getMessage());
        assertTrue(refused.getMessage().contains("use a jdbc:postgresql: URL"), refused.getMessage());
        assertFalse(TrustMarkSupport.isConfigured());
    }

    @Test
    void aDirectUrlThatIsNotPostgreSqlIsRefusedInProductionNamingOnlyItsScheme() {
        profile(DeploymentProfile.PRODUCTION);
        System.setProperty(URL_PROPERTY, "jdbc:mysql://db.internal/idm?password=hunter2");

        ProfileRefused refused = assertThrows(ProfileRefused.class, () -> AuthorityDataSource.trustMarkRegistry(Startup.FEDERATION));
        assertTrue(refused.getMessage().contains("names a jdbc:mysql: database for the Trust Mark registry"), refused.getMessage());
        assertFalse(refused.getMessage().contains("hunter2"), "a JDBC URL can carry a password");
        assertFalse(TrustMarkSupport.isConfigured());
        assertEquals("non-JDBC", PfDataSources.scheme("nothing"));

        ProfileRefusals.resetForTests();
        profile(DeploymentProfile.DEVELOPMENT);
        System.setProperty(URL_PROPERTY, "jdbc:example:idm");
        assertDoesNotThrow(() -> AuthorityDataSource.keyHistoryStore(Startup.FEDERATION), "a WARN under development");
        assertTrue(KeyHistorySupport.isConfigured());
    }

    /** A data store is asked what its database is, on one connection, since no URL shows what a data store id points at. */
    @Test
    void aDataStoreIsHeldToPostgreSqlByWhatItsDatabaseSays() {
        profile(DeploymentProfile.PRODUCTION);

        assertDoesNotThrow(() -> AuthorityDataSource.requirePostgreSql(Startup.HOSTING, database("PostgreSQL"), "the hosted-entity registry"));
        ProfileRefused mysql = assertThrows(ProfileRefused.class,
                () -> AuthorityDataSource.requirePostgreSql(Startup.HOSTING, database("MySQL"), "the hosted-entity registry"));
        assertTrue(mysql.getMessage().contains("is MySQL, not PostgreSQL"), mysql.getMessage());
        assertEquals(List.of(Startup.HOSTING), mysql.violation().components());
        IllegalStateException down = assertThrows(IllegalStateException.class,
                () -> AuthorityDataSource.requirePostgreSql(Startup.HOSTING, database(null), "the hosted-entity registry"));
        assertInstanceOf(SQLException.class, down.getCause(), "a dependency failure, retried by the supervisor");

        ProfileRefusals.resetForTests();
        profile(DeploymentProfile.DEVELOPMENT);
        assertDoesNotThrow(() -> AuthorityDataSource.requirePostgreSql(Startup.HOSTING, database("MySQL"), "the hosted-entity registry"));
    }
}
