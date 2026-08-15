/*
 * javax.sql.DataSource factories for modules storing state via PF-managed or direct JDBC connections.
 */
package com.pingidentity.ps.oidf.pf;

import com.pingidentity.access.DataSourceAccessor;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.logging.Logger;
import javax.sql.DataSource;

/**
 * Two {@link DataSource} shapes, mirroring the pattern {@code servlets/ssf}'s
 * {@code PfJdbcStoreFactory} already established for its own store: a direct JDBC URL (demo/dev,
 * unpooled connections straight from {@link java.sql.DriverManager}) or a PingFederate-managed JDBC
 * data store id (production, connections pooled by PF itself — this module never opens its own pool).
 * Extracted here rather than duplicated a second time, since {@code servlets/pf-integration} is already
 * the common PF-SDK-dependent module for anything wanting either shape.
 */
public final class PfDataSources {

    private PfDataSources() {
    }

    /** Connections straight from {@link java.sql.DriverManager} — demo/dev only, no pooling. */
    public static DataSource direct(String jdbcUrl, String username, String password) {
        return new DriverManagerDataSource(jdbcUrl, username, password);
    }

    /** Connections from PF's own pool for a PF-configured JDBC data store id. */
    public static DataSource pfManaged(String dataStoreId) {
        return new PfManagedDataSource(dataStoreId);
    }

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
         */
        private static void ensureDriverLoaded(String url) {
            String driverClass = null;
            if (url.startsWith("jdbc:postgresql:")) {
                driverClass = "org.postgresql.Driver";
            } else if (url.startsWith("jdbc:hsqldb:")) {
                driverClass = "org.hsqldb.jdbc.JDBCDriver";
            } else if (url.startsWith("jdbc:h2:")) {
                driverClass = "org.h2.Driver";
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
            return Logger.getLogger("com.pingidentity.ps.oidf.pf");
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

    private static final class PfManagedDataSource implements DataSource {
        private final String dataStoreId;

        private PfManagedDataSource(String dataStoreId) {
            this.dataStoreId = dataStoreId;
        }

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
            return Logger.getLogger("com.pingidentity.ps.oidf.pf");
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
