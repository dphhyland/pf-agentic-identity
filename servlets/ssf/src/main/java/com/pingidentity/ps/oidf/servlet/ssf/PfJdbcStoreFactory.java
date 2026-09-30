/*
 * Builds a JDBC-backed SsfStore from a PingFederate-configured JDBC data store id (no own connection pool).
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.access.DataSourceAccessor;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.ssf.JdbcSsfStore;
import com.pingidentity.ps.oidf.ssf.LdmSsfStore;
import com.pingidentity.ps.oidf.ssf.PushHeaderCipher;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfStore;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.logging.Logger;
import javax.sql.DataSource;

/**
 * The runtime {@link SsfSupport.StoreFactory}: turns a {@code dataStoreId} into a {@link JdbcSsfStore} backed by
 * the PingFederate-managed JDBC data store of that id. Connections come from PF's own pool via
 * {@link DataSourceAccessor#getConnection(String)} — this module never opens its own pool — wrapped in a minimal
 * {@link DataSource} so the store's plain-JDBC code is unchanged. Installed by the SSF servlets before
 * {@link SsfSupport#configure} (which then selects this store whenever {@code dataStoreId} is set). Checks the
 * database on one connection ({@link #checkDatabase}) and applies the DDL on boot. Compiles against the
 * {@code provided} PF SDK; the data-store half is exercised only inside PingFederate.
 */
public final class PfJdbcStoreFactory implements SsfSupport.StoreFactory {

    /** The prefix of a PostgreSQL JDBC URL, the one database the SSF store is written and tested for. */
    static final String POSTGRESQL_URL = "jdbc:postgresql:";

    /** The product name PostgreSQL's JDBC driver reports ({@code DatabaseMetaData.getDatabaseProductName}). */
    static final String POSTGRESQL_PRODUCT = "PostgreSQL";

    @Override
    public SsfStore create(SsfConfiguration config) {
        // A direct JDBC URL (demo/dev) wins over a PF-configured data store id (production).
        String source = config.jdbcUrl() != null ? SsfConfiguration.JDBC_URL : "PingFederate data store '" + config.dataStoreId() + "'";
        DataSource ds = config.jdbcUrl() != null
                ? new DriverManagerDataSource(config.jdbcUrl(), config.jdbcUsername(), config.jdbcPassword())
                : new PfManagedDataSource(config.dataStoreId());
        checkDatabase(ds, source);
        // H-SSF-7: a push stream's authorization_header is sealed at rest; production refuses to keep one without the key.
        PushHeaderCipher headers = config.pushHeaderCipher(DeploymentProfile.current().isProduction());
        SsfStore store;
        if ("ldm".equals(config.storeDialect())) {
            // Identity Object Model entry store — schema owned by the model repo's migration workflow
            // (0001-add-shared-signals-ssf); this store never creates tables.
            store = new LdmSsfStore(ds, headers);
        } else {
            JdbcSsfStore tables = new JdbcSsfStore(ds, headers);
            tables.ensureSchema();
            store = tables;
        }
        headers.refuseStoredWithoutKey(store);
        return store;
    }

    /**
     * Opens one connection and asks the database what it is, before the store uses it: so a database that is down is a
     * dependency failure at start-up for either dialect (an {@code ldm} store opens nothing until its first query), and
     * a database the store is not written for is refused. H2 and HSQLDB, dropped in 0.5.0, are refused in every
     * profile ({@link #refuseDroppedProduct}); any other database that is not PostgreSQL is refused under the
     * production profile ({@link ProfileRefusals#refuse}, the component {@code SSF}) and warned of under development
     * (Phase 3 plan, decision 10). How it is told: the product name the JDBC driver reports,
     * {@code DatabaseMetaData.getDatabaseProductName()}, which is {@value #POSTGRESQL_PRODUCT} for PostgreSQL's driver - a
     * URL prefix cannot show what a PingFederate data store id points at. The {@code ldm} dialect is the Identity Object
     * Model's PostgreSQL schema, so it is held to the same rule.
     *
     * @throws IllegalStateException wrapping the {@link SQLException} when no connection can be had, so the part is
     *                               {@code FAILED_DEPENDENCY} and retried
     */
    static void checkDatabase(DataSource ds, String source) {
        String product;
        try (Connection connection = ds.getConnection()) {
            product = refuseDroppedProduct(connection).getMetaData().getDatabaseProductName();
        } catch (SQLException e) {
            throw new IllegalStateException("the SSF store's database (" + source + ") could not be reached", e);
        }
        if (!POSTGRESQL_PRODUCT.equals(product)) {
            ProfileRefusals.refuse(Startup.SSF, "the SSF store's database (" + source + ") is " + product + ", not PostgreSQL:"
                    + " the SSF store's tables and the ldm dialect are written and tested for PostgreSQL only; point "
                    + SsfConfiguration.JDBC_URL + " or the data store at PostgreSQL");
        }
    }

    /** The scheme of a JDBC URL - {@code jdbc:mysql:} - and nothing after it, which can carry a password. */
    static String scheme(String url) {
        int first = url.indexOf(':');
        int second = first < 0 ? -1 : url.indexOf(':', first + 1);
        return second < 0 ? "non-JDBC" : url.substring(0, second + 1);
    }

    /**
     * Refuses a {@code jdbc:h2:} or {@code jdbc:hsqldb:} {@code OIDF_SSF_JDBC_URL} (in any case) with a message naming
     * PostgreSQL. Names the prefix only: the rest of a JDBC URL can carry a password.
     */
    static void refuseDroppedDatabase(String url) {
        for (String dropped : new String[] {"jdbc:h2:", "jdbc:hsqldb:"}) {
            if (url.regionMatches(true, 0, dropped, 0, dropped.length())) {
                throw new IllegalArgumentException("a " + dropped + " SSF store URL is not supported: H2 and HSQLDB "
                        + "support was dropped in 0.5.0; use PostgreSQL (a jdbc:postgresql: URL) or a PingFederate JDBC "
                        + "data store id on PostgreSQL");
            }
        }
    }

    /**
     * Refuses a connection whose database is H2 or HSQLDB, the engines dropped in 0.5.0, with a message naming
     * PostgreSQL. A PingFederate data store id can name PingFederate's own bundled HSQLDB (2.7.1 in the 13.1.3 image),
     * which no URL prefix shows; the product names are the ones those drivers report ({@code HSQL Database Engine},
     * {@code H2}, read with the image's java 21 on 2026-09-28). A configuration fault, not a dependency's: the
     * refusal is an {@link IllegalArgumentException}, so the part is {@code FAILED_CONFIG} and not retried.
     */
    static Connection refuseDroppedProduct(Connection connection) throws SQLException {
        String product = connection.getMetaData().getDatabaseProductName();
        if ("HSQL Database Engine".equalsIgnoreCase(product) || "H2".equalsIgnoreCase(product)) {
            throw new IllegalArgumentException("the SSF store's database is " + product + ", which is not supported: H2 and "
                    + "HSQLDB support was dropped in 0.5.0; point the data store id at a PostgreSQL data store");
        }
        return connection;
    }

    /** Demo/dev {@link DataSource}: unpooled connections straight from {@link java.sql.DriverManager}. */
    private static final class DriverManagerDataSource implements DataSource {
        private final String url;
        private final String username;
        private final String password;

        private DriverManagerDataSource(String url, String username, String password) {
            this.url = url;
            this.username = username;
            this.password = password;
            ensureDriverLoaded(url);
        }

        /**
         * DriverManager only auto-registers drivers from the system classpath; a driver shipped inside
         * pf-runtime.war's WEB-INF/lib must be loaded explicitly (its static initializer self-registers).
         * H2 and HSQLDB were dropped in 0.5.0: their URLs are refused here, so the SSF store does not start on
         * a database nothing tests against.
         */
        private static void ensureDriverLoaded(String url) {
            refuseDroppedDatabase(url);
            String driverClass = null;
            if (url.startsWith("jdbc:postgresql:")) {
                driverClass = "org.postgresql.Driver";
            }
            if (driverClass != null) {
                try {
                    Class.forName(driverClass, true, DriverManagerDataSource.class.getClassLoader());
                } catch (ClassNotFoundException e) {
                    throw new IllegalStateException("JDBC driver " + driverClass + " not on the classpath for " + url, e);
                }
            }
        }

        @Override
        public Connection getConnection() throws SQLException {
            return java.sql.DriverManager.getConnection(this.url, this.username, this.password);
        }

        @Override
        public Connection getConnection(String u, String p) throws SQLException {
            return java.sql.DriverManager.getConnection(this.url, u, p);
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
            // not used
        }

        @Override
        public void setLoginTimeout(int seconds) {
            // not used
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getLogger("com.pingidentity.ps.oidf.ssf");
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            if (iface.isInstance(this)) {
                return iface.cast(this);
            }
            throw new SQLException("not a wrapper for " + iface);
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return iface.isInstance(this);
        }
    }

    /** A {@link DataSource} whose connections are PF-pooled connections for one configured data store id. */
    private static final class PfManagedDataSource implements DataSource {
        private final String dataStoreId;

        private PfManagedDataSource(String dataStoreId) {
            this.dataStoreId = dataStoreId;
        }

        /** A pooled connection for the data store; {@link #checkDatabase} has asked the first one what it is. */
        @Override
        public Connection getConnection() throws SQLException {
            try {
                return new DataSourceAccessor().getConnection(this.dataStoreId);
            } catch (SQLException e) {
                throw e;
            } catch (Exception e) {
                throw new SQLException("could not obtain a connection for PF data store '" + this.dataStoreId + "'", e);
            }
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return getConnection();
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
            // PF manages logging for its data sources
        }

        @Override
        public void setLoginTimeout(int seconds) {
            // PF manages pool timeouts
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getLogger("com.pingidentity.ps.oidf.ssf");
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            if (iface.isInstance(this)) {
                return iface.cast(this);
            }
            throw new SQLException("not a wrapper for " + iface);
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return iface.isInstance(this);
        }
    }
}
