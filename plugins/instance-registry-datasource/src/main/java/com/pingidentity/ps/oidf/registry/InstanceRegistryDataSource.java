/*
 * PingFederate CustomDataSourceDriver over the agent instance registry.
 */
package com.pingidentity.ps.oidf.registry;

import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.JdbcInstanceRegistry;
import com.pingidentity.sources.CustomDataSourceDriver;
import com.pingidentity.sources.CustomDataSourceDriverDescriptor;
import com.pingidentity.sources.CustomDataSourceDriverException;
import com.pingidentity.sources.SourceDescriptor;
import com.pingidentity.sources.gui.FilterFieldsGuiDescriptor;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.postgresql.ds.PGSimpleDataSource;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.SimpleFieldList;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
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
 * <p>Configure an access token mapping with a filter of {@code instance_id=$\{sub\}} against the
 * attestation's subject, then gate issuance on {@code instance_active}, {@code device_compliant} and
 * {@code uv_fresh}. Map {@code owner_subject} to the token's {@code sub}: RFC 8693 puts the human
 * there and the instance in {@code act.sub}.
 */
public class InstanceRegistryDataSource implements CustomDataSourceDriver {

    private static final Log LOGGER = LogFactory.getLog(InstanceRegistryDataSource.class);

    /** The filter field a mapping supplies: the attestation's {@code sub}. */
    public static final String FILTER_INSTANCE_ID = "instance_id";

    private static final String CONFIG_JDBC_URL = "JDBC URL";
    private static final String CONFIG_UV_MAX_AGE = "User verification max age (seconds)";
    private static final long DEFAULT_UV_MAX_AGE_SECONDS = 300L;

    private final CustomDataSourceDriverDescriptor descriptor;
    private volatile InstanceLookup lookup;
    private volatile String jdbcUrl;

    public InstanceRegistryDataSource() {
        AdapterConfigurationGuiDescriptor gui = new AdapterConfigurationGuiDescriptor(
                "Reads the agent instance registry so an access token mapping can resolve a "
                        + "pseudonymous instance identifier to its owner, status, device compliance and "
                        + "user-verification recency at the moment of issuance.");
        gui.addField(new TextFieldDescriptor(CONFIG_JDBC_URL,
                "JDBC URL of the instance registry, e.g. jdbc:postgresql://host:5432/enrolment"));
        TextFieldDescriptor uvMaxAge = new TextFieldDescriptor(CONFIG_UV_MAX_AGE,
                "How recent user verification must be for uv_fresh to be true. Must match the enrolment "
                        + "service's UV_MAX_AGE_SECONDS, or the two disagree about when an agent stops.");
        uvMaxAge.setDefaultValue(String.valueOf(DEFAULT_UV_MAX_AGE_SECONDS));
        gui.addField(uvMaxAge);

        FilterFieldsGuiDescriptor filterFields = new FilterFieldsGuiDescriptor();
        filterFields.addField(new TextFieldDescriptor(FILTER_INSTANCE_ID,
                "The agent instance identifier — the attestation's sub."));

        this.descriptor = new CustomDataSourceDriverDescriptor(
                this, "Agent Instance Registry", gui, filterFields);
    }

    @Override
    public SourceDescriptor getSourceDescriptor() {
        return this.descriptor;
    }

    @Override
    public void configure(Configuration configuration) {
        this.jdbcUrl = configuration.getFieldValue(CONFIG_JDBC_URL);
        long uvMaxAge = DEFAULT_UV_MAX_AGE_SECONDS;
        String configured = configuration.getFieldValue(CONFIG_UV_MAX_AGE);
        if (configured != null && !configured.isBlank()) {
            try {
                uvMaxAge = Long.parseLong(configured.trim());
            } catch (NumberFormatException e) {
                LOGGER.warn((Object) ("'" + CONFIG_UV_MAX_AGE + "' is not a number: " + configured
                        + " — falling back to " + DEFAULT_UV_MAX_AGE_SECONDS + "s"));
            }
        }
        this.lookup = new InstanceLookup(registry(this.jdbcUrl), Duration.ofSeconds(uvMaxAge));
        LOGGER.info((Object) ("Agent instance registry data source configured: uvMaxAge=" + uvMaxAge + "s"));
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
            throw new IllegalStateException("the data source has not been configured");
        }
        return current;
    }

    /** Overridable so tests can supply an in-memory or H2-backed registry. */
    protected InstanceRegistry registry(String url) {
        PGSimpleDataSource source = new PGSimpleDataSource();
        source.setUrl(url);
        return new JdbcInstanceRegistry((DataSource) source);
    }

    /** Test seam: install a prepared lookup without going through PF configuration. */
    void setLookup(InstanceLookup lookup) {
        this.lookup = lookup;
    }
}
