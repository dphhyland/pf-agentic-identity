/*
 * The domain authority's durable store, as configured for the process.
 */
package com.pingidentity.ps.oidf.pf;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Optional;
import java.util.function.Function;
import javax.sql.DataSource;
import com.pingidentity.ps.oidf.keyhistory.KeyHistorySupport;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisk;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupport;

/**
 * The authority's JDBC store - the hosted entities, the Trust Mark grants and the key history - read through the
 * {@value #CATALOGUE} settings catalogue, so every servlet that needs it reads the same entries in the same order
 * (plan item ST-5): {@code HostedEntityServlet} with its init-params, anything that needs the store before it has
 * started without them. And PR-2's refusals of that store under the production profile (Phase 3 plan, decisions 9, 10
 * and 15): a store kept in memory without the {@code in-memory-state} risk, and a database that is not PostgreSQL.
 */
public final class AuthorityDataSource {
    /** The settings catalogue the authority's store is in ({@code META-INF/oidf-settings/hosted-entities.json}). */
    public static final String CATALOGUE = "hosted-entities";
    public static final String JDBC_URL_ENV = "OIDF_AUTHORITY_JDBC_URL";
    public static final String JDBC_USERNAME_ENV = "OIDF_AUTHORITY_JDBC_USERNAME";
    public static final String JDBC_PASSWORD_ENV = "OIDF_AUTHORITY_JDBC_PASSWORD";
    public static final String DATA_STORE_ID_ENV = "OIDF_AUTHORITY_DATA_STORE_ID";
    /** The only URL scheme the authority's stores are written and tested for. */
    static final String POSTGRESQL_URL = "jdbc:postgresql:";
    /** What PostgreSQL's JDBC driver reports as {@code DatabaseMetaData.getDatabaseProductName()}. */
    static final String POSTGRESQL_PRODUCT = "PostgreSQL";

    private AuthorityDataSource() {
    }

    /** The authority's settings, read from {@code sources}. */
    public static Settings settings(Sources sources) {
        return Settings.load(AuthorityDataSource.class.getClassLoader(), CATALOGUE).with(sources);
    }

    /**
     * The store {@code sources} name: a direct JDBC URL (with its credentials) wins over a PingFederate data store id;
     * neither set is empty. Each is its catalogue entry's: the init-param, then the system property, then the
     * environment variable; the password may be read from the file its {@code _FILE} variant names.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused for a value its entry refuses
     */
    public static Optional<DataSource> from(Sources sources) {
        Settings settings = settings(sources);
        String url = settings.string(JDBC_URL_ENV);
        if (url != null) {
            Secret password = settings.secret(JDBC_PASSWORD_ENV);
            return Optional.of(PfDataSources.direct(url, settings.string(JDBC_USERNAME_ENV), password == null ? null : password.reveal()));
        }
        String dataStoreId = settings.string(DATA_STORE_ID_ENV);
        return dataStoreId == null ? Optional.empty() : Optional.of(PfDataSources.pfManaged(dataStoreId));
    }

    /** Test seam: {@link #from(Sources)} with this environment and these system properties, and no init-params. */
    public static Optional<DataSource> from(Function<String, String> env, Function<String, String> props) {
        return from(Sources.of(env, props, null));
    }

    public static Optional<DataSource> fromEnvironment() {
        return from(Sources.process());
    }

    /**
     * Points the Trust Mark registry at the authority's store, for {@code component}, which issues Trust Marks: with no
     * store the grants are kept in memory, which the production profile refuses without the {@code in-memory-state}
     * risk; a store is held to PostgreSQL ({@link #requirePostgreSql}). Nothing to do once a registry is configured.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.ProfileRefused under production, for either refusal
     */
    public static void trustMarkRegistry(String component) {
        if (!TrustMarkSupport.isConfigured()) {
            trustMarkRegistry(component, fromEnvironment());
        }
    }

    /** {@link #trustMarkRegistry(String)} with {@code store} as the authority's store. */
    static void trustMarkRegistry(String component, Optional<DataSource> store) {
        if (store.isEmpty()) {
            ProfileRefusals.requireRisk(component, AcceptedRisk.IN_MEMORY_STATE, "the Trust Mark registry is in memory (neither "
                    + DATA_STORE_ID_ENV + " nor " + JDBC_URL_ENV + " is set)");
            return;
        }
        requirePostgreSql(component, store.get(), "the Trust Mark registry");
        TrustMarkSupport.configureJdbcRegistry(store.get());
    }

    /**
     * Points the key history at the authority's store, for {@code component}, which publishes it (OpenID Federation 1.0
     * §8.7): as {@link #trustMarkRegistry}, for the key history. A history kept in memory also misses a rotation across a
     * restart.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.ProfileRefused under production, for either refusal
     */
    public static void keyHistoryStore(String component) {
        if (!KeyHistorySupport.isConfigured()) {
            keyHistoryStore(component, fromEnvironment());
        }
    }

    /** {@link #keyHistoryStore(String)} with {@code store} as the authority's store. */
    static void keyHistoryStore(String component, Optional<DataSource> store) {
        if (store.isEmpty()) {
            ProfileRefusals.requireRisk(component, AcceptedRisk.IN_MEMORY_STATE, "the key history is in memory (neither "
                    + DATA_STORE_ID_ENV + " nor " + JDBC_URL_ENV + " is set)");
            return;
        }
        requirePostgreSql(component, store.get(), "the key history");
        KeyHistorySupport.configureJdbcStore(store.get());
    }

    /**
     * Holds {@code store} to PostgreSQL, for {@code component}: the authority's tables are written and tested for
     * PostgreSQL only (Phase 3 plan, decision 10). A direct URL is judged by its scheme, spelt as the driver accepts it;
     * a data store by the product name its database reports on one connection, since no URL shows what a data store id
     * points at. H2 and HSQLDB,
     * dropped in 0.5.0, are refused in every profile ({@link PfDataSources}); any other database that is not PostgreSQL
     * is refused under production ({@link ProfileRefusals#refuse}) and warned of under development.
     *
     * @throws IllegalStateException wrapping the {@link SQLException} when no connection can be had, so the part is
     *                               {@code FAILED_DEPENDENCY} and retried
     * @throws com.pingidentity.ps.oidf.platform.settings.ProfileRefused under production, for a database that is not
     *                                                                   PostgreSQL
     */
    public static void requirePostgreSql(String component, DataSource store, String what) {
        String url = PfDataSources.urlOf(store);
        if (url != null) {
            // Case-sensitive, as PfDataSources loads the driver and as PostgreSQL's driver accepts a URL: a scheme spelt in
            // another case would pass here and fail at first use.
            if (!url.startsWith(POSTGRESQL_URL)) {
                ProfileRefusals.refuse(component, JDBC_URL_ENV + " names a " + PfDataSources.scheme(url) + " database for " + what
                        + ": the authority's stores are written and tested for PostgreSQL only; use a " + POSTGRESQL_URL
                        + " URL or a PingFederate data store on PostgreSQL");
            }
            return;
        }
        String product;
        try (Connection connection = store.getConnection()) {
            product = connection.getMetaData().getDatabaseProductName();
        } catch (SQLException e) {
            throw new IllegalStateException("the authority's database (" + DATA_STORE_ID_ENV + ") could not be reached for " + what, e);
        }
        if (!POSTGRESQL_PRODUCT.equals(product)) {
            ProfileRefusals.refuse(component, "the authority's database (" + DATA_STORE_ID_ENV + ") is " + product + ", not PostgreSQL,"
                    + " for " + what + ": the authority's stores are written and tested for PostgreSQL only; point the data store at"
                    + " PostgreSQL");
        }
    }
}
