package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.util.Map;
import java.util.Optional;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

/**
 * The authority's store, found the same way by whichever servlet asks first. No driver claims {@code jdbc:nowhere:}, so
 * {@link java.sql.DriverManager}'s refusal names the URL each case chose.
 */
class AuthorityDataSourceTest {

    private static Optional<DataSource> from(Map<String, String> env, Map<String, String> props) {
        return AuthorityDataSource.from(env::get, props::get);
    }

    private static String urlTried(DataSource store) {
        return assertThrows(SQLException.class, store::getConnection).getMessage();
    }

    @Test
    void aJdbcUrlIsUsedDirectly() {
        DataSource store = from(Map.of(AuthorityDataSource.JDBC_URL_ENV, "jdbc:nowhere:env", AuthorityDataSource.JDBC_USERNAME_ENV, "idm",
                AuthorityDataSource.JDBC_PASSWORD_ENV, "secret"), Map.of()).orElseThrow();

        assertTrue(urlTried(store).contains("jdbc:nowhere:env"), urlTried(store));
    }

    @Test
    void aSystemPropertyBeatsTheEnvironmentAndAUrlBeatsADataStore() {
        DataSource store = from(Map.of(AuthorityDataSource.JDBC_URL_ENV, "jdbc:nowhere:env", AuthorityDataSource.DATA_STORE_ID_ENV, "pf-store"),
                Map.of("oidf.authority.jdbc.url", "jdbc:nowhere:property")).orElseThrow();

        assertTrue(urlTried(store).contains("jdbc:nowhere:property"), urlTried(store));
    }

    @Test
    void aDataStoreIdIsPingFederatesPoolAndNothingSetIsNone() {
        assertTrue(from(Map.of(AuthorityDataSource.DATA_STORE_ID_ENV, "pf-store"), Map.of()).isPresent());
        assertTrue(from(Map.of(), Map.of()).isEmpty());
        assertTrue(from(Map.of(AuthorityDataSource.JDBC_URL_ENV, " "), Map.of()).isEmpty());
        AuthorityDataSource.fromEnvironment();
    }
}
