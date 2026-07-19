/*
 * Builds a JDBC-backed SsfStore from a PingFederate-configured JDBC data store id (no own connection pool).
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.access.DataSourceAccessor;
import com.pingidentity.ps.oidf.ssf.JdbcSsfStore;
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
 * {@link SsfSupport#configure} (which then selects this store whenever {@code dataStoreId} is set). Applies the
 * DDL on boot. Compiles against the {@code provided} PF SDK; exercised only inside PingFederate.
 */
public final class PfJdbcStoreFactory implements SsfSupport.StoreFactory {

    @Override
    public SsfStore create(String dataStoreId) {
        JdbcSsfStore store = new JdbcSsfStore(new PfManagedDataSource(dataStoreId));
        store.ensureSchema();
        return store;
    }

    /** A {@link DataSource} whose connections are PF-pooled connections for one configured data store id. */
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
