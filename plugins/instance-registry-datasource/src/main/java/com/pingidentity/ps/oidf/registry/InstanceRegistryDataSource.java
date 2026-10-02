/*
 * PingFederate CustomDataSourceDriver over the agent instance registry.
 */
package com.pingidentity.ps.oidf.registry;

import com.pingidentity.access.DataSourceAccessor;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.IomInstanceRegistry;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.sources.CustomDataSourceDriver;
import com.pingidentity.sources.CustomDataSourceDriverDescriptor;
import com.pingidentity.sources.CustomDataSourceDriverException;
import com.pingidentity.sources.SourceDescriptor;
import com.pingidentity.sources.gui.FilterFieldsGuiDescriptor;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.logging.Logger;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.postgresql.ds.PGSimpleDataSource;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.SimpleFieldList;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.JdbcDatastoreFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;

/**
 * Exposes the agent instance registry to PingFederate as a data source, so an access token mapping can
 * resolve a pseudonymous instance identifier at issuance time.
 *
 * <p>The reason this exists rather than trusting the attestation alone: the attestation is valid for
 * fifteen minutes, and within that window the instance can be revoked, the device can fall out of
 * compliance, or the user-verification window can lapse. A token minted from a still-valid attestation
 * would carry none of that. Reading the registry on every issuance is what makes revocation immediate.
 *
 * <p>The lookup logic lives in {@link InstanceLookup}, which has no PF dependency and is unit tested.
 * This class is only the SDK shell — configuration, the filter field, and the value map PF expects.
 *
 * <h2>Deployment</h2>
 *
 * <p>Discovered via {@code PF-INF/custom-drivers}, in a jar whose filename starts {@code pf.plugins.} —
 * without that prefix PF ignores it silently, which is one of the ways this fails with no error.
 *
 * <p>Configure an access token mapping with a filter of {@code instance_id=$\{agent_id\}} against the
 * attestation's {@code agent_id} claim (the instance id in every mode — {@code sub} becomes the client
 * id once {@code OIDF_ATTESTATION_SUB=client_id}), then gate issuance on {@code instance_active}, {@code device_compliant} and
 * {@code uv_fresh}. Map {@code owner_subject} to the token's {@code sub}: RFC 8693 puts the human
 * there and the instance in {@code act.sub}.
 *
 * <h2>Where the registry is (plan item PR-3)</h2>
 *
 * <p>{@value #CONFIG_DATA_STORE} is the production way: a PingFederate JDBC data store, chosen from the SDK's
 * {@link JdbcDatastoreFieldDescriptor}, whose value is the data store's JNDI name - which PingFederate 13.1.3 sets to
 * the data store's id ({@code JdbcDataSource.getJndiName()} returns {@code getId()}; javap, 2026-09-30) - and whose
 * connections come from {@link DataSourceAccessor#getConnection(String)}, a JNDI lookup of that name: PingFederate's
 * pool and credentials, no URL or password in this driver's configuration. {@value #CONFIG_JDBC_URL} is the
 * development way, a connection per lookup straight from the PostgreSQL driver; it is {@code forbidden-in-production}
 * in the {@code instance-registry} catalogue, and since a plugin's fields are read at {@code configure}, not by the
 * start-up sweep, this driver refuses it there under the production profile, naming the field to use instead. A data
 * store whose database is not PostgreSQL is refused under production at its first connection (Phase 3 plan, decision
 * 15). A refused or unconfigured driver answers every lookup with a {@link CustomDataSourceDriverException}, so an
 * issuance criterion never passes on it.
 */
public class InstanceRegistryDataSource implements CustomDataSourceDriver {

    private static final Log LOGGER = LogFactory.getLog(InstanceRegistryDataSource.class);

    /** The filter field a mapping supplies: the attestation's {@code agent_id}. */
    public static final String FILTER_INSTANCE_ID = "instance_id";

    /** The production way to the registry: a PingFederate JDBC data store, by its JNDI name (its id). */
    static final String CONFIG_DATA_STORE = "PingFederate data store";
    /** The development way: a JDBC URL, credentials included. */
    static final String CONFIG_JDBC_URL = "JDBC URL";
    static final String CONFIG_UV_MAX_AGE = "User verification max age (seconds)";
    /** The field's default, as the catalogue says. */
    static final long DEFAULT_UV_MAX_AGE_SECONDS = 300L;
    /** The settings catalogue the three fields are read through. */
    static final String CATALOGUE = "instance-registry";
    /** The component a refusal names (DefaultComponents' table). */
    static final String COMPONENT = "INSTANCE_REGISTRY";
    /** The product name PostgreSQL's JDBC driver reports ({@code DatabaseMetaData.getDatabaseProductName}). */
    static final String POSTGRESQL_PRODUCT = "PostgreSQL";

    private final CustomDataSourceDriverDescriptor descriptor;
    private final Function<String, String> env;
    private volatile InstanceLookup lookup;
    /** Why the driver answers no lookup, once configure has refused; null otherwise. */
    private volatile String refusal;

    public InstanceRegistryDataSource() {
        this(System::getenv, JdbcDatastoreFieldDescriptor::new);
    }

    /**
     * The driver, reading the deployment profile from {@code env}; {@code dataStoreField} builds the data store
     * selector, which asks PingFederate for its data stores and so has a stand-in in a unit test.
     */
    InstanceRegistryDataSource(Function<String, String> env, FieldFactory dataStoreField) {
        this.env = env;
        AdapterConfigurationGuiDescriptor gui = new AdapterConfigurationGuiDescriptor(
                "Reads the agent instance registry so an access token mapping can resolve a "
                        + "pseudonymous instance identifier to its owner, status, device compliance and "
                        + "user-verification recency at the moment of issuance.");
        gui.addField(dataStoreField.field(CONFIG_DATA_STORE,
                "The PingFederate JDBC data store on the Identity Object Model directory that holds the registry - the "
                        + "SAME database the enrolment service writes to (its IDM_DATABASE_URL) - on PostgreSQL. "
                        + "PingFederate keeps its pool and credentials. The production way to the registry."));
        gui.addField(new TextFieldDescriptor(CONFIG_JDBC_URL,
                "Development only: a jdbc:postgresql: URL of the same directory, credentials included, used when no "
                        + "data store is chosen. Under the production profile (OIDF_DEPLOYMENT_PROFILE unset or anything "
                        + "but development) a value here refuses every lookup: choose the data store above instead."));
        TextFieldDescriptor uvMaxAge = new TextFieldDescriptor(CONFIG_UV_MAX_AGE,
                "How recent user verification must be for uv_fresh to be true. Must match the enrolment "
                        + "service's UV_MAX_AGE_SECONDS, or the two disagree about when an agent stops.");
        uvMaxAge.setDefaultValue(String.valueOf(DEFAULT_UV_MAX_AGE_SECONDS));
        gui.addField(uvMaxAge);

        FilterFieldsGuiDescriptor filterFields = new FilterFieldsGuiDescriptor();
        filterFields.addField(new TextFieldDescriptor(FILTER_INSTANCE_ID,
                "The agent instance identifier — the attestation's agent_id claim."));

        this.descriptor = new CustomDataSourceDriverDescriptor(
                this, "Agent Instance Registry", gui, filterFields);
    }

    @Override
    public SourceDescriptor getSourceDescriptor() {
        return this.descriptor;
    }

    @Override
    public void configure(Configuration configuration) {
        configure(configuration.getFieldValue(CONFIG_DATA_STORE), configuration.getFieldValue(CONFIG_JDBC_URL),
                configuration.getFieldValue(CONFIG_UV_MAX_AGE));
    }

    /**
     * The three fields, read strictly through the {@code instance-registry} catalogue. A refusal - the JDBC URL under
     * production, a field that does not parse, no database at all - leaves the driver answering every lookup with it,
     * logged once at ERROR; nothing is thrown at PingFederate from here.
     */
    void configure(String dataStore, String jdbcUrl, String uvMaxAgeField) {
        this.lookup = null;
        this.refusal = null;
        Settings settings = Settings.of(Holder.CATALOGUE, Sources.of(this.env, System::getProperty, null));
        Duration uvMaxAge;
        String store;
        Secret url;
        try {
            uvMaxAge = (Duration) settings.parse(CONFIG_UV_MAX_AGE, uvMaxAgeField);
            store = (String) settings.parse(CONFIG_DATA_STORE, dataStore);
            url = (Secret) settings.parse(CONFIG_JDBC_URL, jdbcUrl);
        } catch (ProfileRefused e) {
            refuse(e.getMessage() + " Choose the registry's database in '" + CONFIG_DATA_STORE + "' instead - a PingFederate"
                    + " JDBC data store on PostgreSQL - and clear '" + CONFIG_JDBC_URL + "'.");
            return;
        } catch (SettingRefused e) {
            refuse(e.getMessage());
            return;
        }
        if (uvMaxAge == null) {
            uvMaxAge = Duration.ofSeconds(DEFAULT_UV_MAX_AGE_SECONDS);
        }
        InstanceRegistry registry;
        if (store != null) {
            if (url != null) {
                LOGGER.warn((Object) ("Agent instance registry: '" + CONFIG_JDBC_URL + "' is set as well as '" + CONFIG_DATA_STORE
                        + "'; the data store is used and the URL ignored"));
            }
            registry = dataStoreRegistry(store);
        } else if (url != null) {
            registry = registry(url.reveal());
        } else {
            refuse("no database is configured: choose the registry's PingFederate JDBC data store in '" + CONFIG_DATA_STORE + "'");
            return;
        }
        this.lookup = new InstanceLookup(registry, uvMaxAge);
        LOGGER.info((Object) ("Agent instance registry data source configured: " + (store != null ? "data store '" + store + "'"
                : "JDBC URL (development)") + ", uvMaxAge=" + uvMaxAge.toSeconds() + "s"));
    }

    /** Holds {@code reason} as the answer to every lookup, and logs it at ERROR. */
    private void refuse(String reason) {
        this.refusal = "the agent instance registry data source is not configured: " + reason;
        LOGGER.error((Object) this.refusal);
    }

    /** The catalogue, loaded once from this class's loader: the plugin jar, with platform shaded beside it. */
    private static final class Holder {
        static final Catalogue CATALOGUE = Catalogue.load(InstanceRegistryDataSource.class.getClassLoader(),
                InstanceRegistryDataSource.CATALOGUE);
    }

    /** Builds the data store selector: the SDK's, in PingFederate. */
    @FunctionalInterface
    interface FieldFactory {
        FieldDescriptor field(String name, String description);
    }

    @Override
    public boolean testConnection() {
        try {
            // A lookup of an identifier that cannot exist: exercises the connection and the schema
            // without depending on any particular row being present.
            requireLookup().lookup("connection-test-" + Instant.now().toEpochMilli(), Instant.now());
            return true;
        } catch (Exception e) {
            LOGGER.warn((Object) ("instance registry connection test failed: " + e.getMessage()), e);
            return false;
        }
    }

    @Override
    public List<String> getAvailableFields() {
        return InstanceLookup.AVAILABLE_FIELDS;
    }

    @Override
    public Map<String, Object> retrieveValues(Collection<String> attributeNamesToFill,
                                              SimpleFieldList filterConfiguration)
            throws CustomDataSourceDriverException {
        String instanceId = filterConfiguration == null
                ? null
                : filterConfiguration.getFieldValue(FILTER_INSTANCE_ID);
        Map<String, Object> resolved;
        try {
            resolved = requireLookup().lookup(instanceId, Instant.now());
        } catch (Exception e) {
            // Fail closed and loudly. Returning partial values here would let an issuance criterion
            // pass on a missing field while the registry was unreachable.
            LOGGER.error((Object) ("instance registry lookup failed for '" + instanceId + "'"), e);
            throw new CustomDataSourceDriverException(
                    "could not read the agent instance registry: " + e.getMessage());
        }

        // Return only what was asked for, but never invent a field: an unknown name maps to null, and
        // a criterion written against it fails rather than silently passing.
        Map<String, Object> values = new LinkedHashMap<>();
        if (attributeNamesToFill == null || attributeNamesToFill.isEmpty()) {
            values.putAll(resolved);
        } else {
            for (String name : attributeNamesToFill) {
                values.put(name, resolved.get(name));
            }
        }
        return values;
    }

    private InstanceLookup requireLookup() {
        InstanceLookup current = this.lookup;
        if (current == null) {
            String refused = this.refusal;
            throw new IllegalStateException(refused != null ? refused : "the data source has not been configured");
        }
        return current;
    }

    /** Why the driver answers no lookup, or null. */
    String refusal() {
        return this.refusal;
    }

    /** The development way: overridable so tests can supply an in-memory registry. */
    protected InstanceRegistry registry(String url) {
        return DirectUrl.registry(url);
    }

    /** The production way: the registry over a PingFederate data store's pool; overridable for tests. */
    protected InstanceRegistry dataStoreRegistry(String dataStore) {
        return new IomInstanceRegistry(new DataStoreSource(dataStore, name -> new DataSourceAccessor().getConnection(name)));
    }

    /**
     * Kept apart so the PostgreSQL driver's classes are linked only when a JDBC URL is used: the data store way needs
     * no driver in this plugin's loader - PingFederate's data store brings its own.
     */
    private static final class DirectUrl {
        static InstanceRegistry registry(String url) {
            PGSimpleDataSource source = new PGSimpleDataSource();
            source.setUrl(url);
            return new IomInstanceRegistry((DataSource) source);
        }
    }

    /** A connection by a data store's JNDI name. */
    @FunctionalInterface
    interface Connections {
        Connection get(String jndiName) throws Exception;
    }

    /**
     * A PingFederate JDBC data store as a {@link DataSource}: each connection from PingFederate's pool, by the data
     * store's JNDI name. The first connection is asked what its database is, and one that is not PostgreSQL is refused
     * through {@link ProfileRefusals#refuse} (the component {@value #COMPONENT}): under production that throws, so every
     * lookup fails; under development it is a warning, once.
     */
    static final class DataStoreSource implements DataSource {
        private final String jndiName;
        private final Connections connections;
        private volatile boolean productChecked;

        DataStoreSource(String jndiName, Connections connections) {
            this.jndiName = jndiName;
            this.connections = connections;
        }

        @Override
        public Connection getConnection() throws SQLException {
            Connection connection;
            try {
                connection = this.connections.get(this.jndiName);
            } catch (SQLException e) {
                throw e;
            } catch (Exception e) {
                throw new SQLException("could not obtain a connection from the PingFederate data store '" + this.jndiName + "'", e);
            }
            if (!this.productChecked) {
                String product = connection.getMetaData().getDatabaseProductName();
                if (!POSTGRESQL_PRODUCT.equals(product)) {
                    try {
                        ProfileRefusals.refuse(COMPONENT, "the PingFederate data store '" + this.jndiName + "' is " + product
                                + ", not PostgreSQL: the agent instance registry's tables are the Identity Object Model's, written"
                                + " and tested for PostgreSQL only; choose a data store on PostgreSQL in '" + CONFIG_DATA_STORE + "'");
                    } catch (RuntimeException refused) {
                        connection.close();
                        throw refused;
                    }
                }
                this.productChecked = true;
            }
            return connection;
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
            // PingFederate's data store logs for itself
        }

        @Override
        public void setLoginTimeout(int seconds) {
            // PingFederate's pool has its own timeouts
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException("PingFederate's data store logs for itself");
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

    /** Test seam: install a prepared lookup without going through PF configuration. */
    void setLookup(InstanceLookup lookup) {
        this.lookup = lookup;
    }
}
