/*
 * The domain authority's durable store, as configured for the process.
 */
package com.pingidentity.ps.oidf.pf;

import java.util.Optional;
import java.util.function.Function;
import javax.sql.DataSource;

/**
 * The authority's JDBC store from system properties or the environment - the settings {@code HostedEntityServlet}
 * reads, less its init-params. Any servlet that needs the store before {@code HostedEntityServlet} has started (it
 * starts on its first request) reads it here, so every one of them points at the same database.
 */
public final class AuthorityDataSource {
    public static final String JDBC_URL_ENV = "OIDF_AUTHORITY_JDBC_URL";
    public static final String JDBC_USERNAME_ENV = "OIDF_AUTHORITY_JDBC_USERNAME";
    public static final String JDBC_PASSWORD_ENV = "OIDF_AUTHORITY_JDBC_PASSWORD";
    public static final String DATA_STORE_ID_ENV = "OIDF_AUTHORITY_DATA_STORE_ID";

    private AuthorityDataSource() {
    }

    /** A direct JDBC URL (with its credentials) wins over a PingFederate data store id; neither set is empty. */
    public static Optional<DataSource> from(Function<String, String> env, Function<String, String> props) {
        String url = setting(env, props, "oidf.authority.jdbc.url", JDBC_URL_ENV);
        if (url != null) {
            return Optional.of(PfDataSources.direct(url, setting(env, props, "oidf.authority.jdbc.username", JDBC_USERNAME_ENV),
                    setting(env, props, "oidf.authority.jdbc.password", JDBC_PASSWORD_ENV)));
        }
        String dataStoreId = setting(env, props, "oidf.authority.data_store_id", DATA_STORE_ID_ENV);
        return dataStoreId == null ? Optional.empty() : Optional.of(PfDataSources.pfManaged(dataStoreId));
    }

    public static Optional<DataSource> fromEnvironment() {
        return from(System::getenv, System::getProperty);
    }

    private static String setting(Function<String, String> env, Function<String, String> props, String prop, String var) {
        String value = props.apply(prop);
        if (value == null || value.isBlank()) {
            value = env.apply(var);
        }
        return value == null || value.isBlank() ? null : value.trim();
    }
}
