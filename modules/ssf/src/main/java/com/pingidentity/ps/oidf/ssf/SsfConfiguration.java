/*
 * Typed configuration for the SSF transmitter, read from servlet init parameters.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.servlet.ServletConfig;

/**
 * Configuration surface for the Shared Signals transmitter, following the {@code FederationConfiguration}
 * convention: an immutable value read from servlet {@code init-param}s via {@link #fromServletConfig}, with a
 * {@link Builder} for unit tests. All timing/size knobs have documented defaults so a minimal deployment only
 * needs {@code issuer}.
 *
 * <p>{@code dataStoreId} selects persistence: when blank, the transmitter uses the per-node in-memory store
 * (dev fallback, not cluster-safe); when set, it names a PingFederate-configured JDBC data store. Kafka
 * fan-out is fully off unless {@code kafkaEnabled} is true, and when off no Kafka classes are loaded.
 */
public final class SsfConfiguration {

    private static final String DEFAULT_SIGNING_ALGORITHM = "RS256";
    private static final Set<String> SUPPORTED_SIGNING_ALGORITHMS = Set.of("RS256", "PS256");
    private static final String DEFAULT_BASE_PATH = "/ssf";
    private static final String DEFAULT_STORE_DIALECT = "tables";
    private static final Set<String> SUPPORTED_STORE_DIALECTS = Set.of("tables", "ldm");
    private static final String DEFAULT_KAFKA_TOPIC = "sse-events";
    private static final String DEFAULT_KAFKA_SECURITY_PROTOCOL = "PLAINTEXT";
    private static final String DEFAULT_RECEIVER_SCOPE = "ssf.manage";
    private static final int DEFAULT_PUSH_RETRY_MAX_ATTEMPTS = 5;
    private static final int DEFAULT_PUSH_RETRY_BACKOFF_SECONDS = 5;
    private static final int DEFAULT_POLL_MAX_EVENTS = 100;
    private static final long DEFAULT_SET_TTL_SECONDS = 604800L; // 7 days
    private static final List<String> DEFAULT_EVENT_TYPES = List.of(
            SsfEventTypes.CAEP_SESSION_REVOKED,
            SsfEventTypes.CAEP_CREDENTIAL_CHANGE,
            SsfEventTypes.RISC_ACCOUNT_DISABLED,
            SsfEventTypes.RISC_ACCOUNT_ENABLED);

    private final String issuer;
    private final String signingAlgorithm;
    private final String basePath;
    private final String dataStoreId;
    private final String storeDialect;
    private final String jdbcUrl;
    private final String jdbcUsername;
    private final String jdbcPassword;
    private final boolean kafkaEnabled;
    private final String kafkaBootstrapServers;
    private final String kafkaTopic;
    private final String kafkaSecurityProtocol;
    private final String kafkaSaslMechanism;
    private final String kafkaSaslUsername;
    private final String kafkaSaslPassword;
    private final int pushRetryMaxAttempts;
    private final int pushRetryBackoffSeconds;
    private final int pollMaxEvents;
    private final long setTtlSeconds;
    private final String receiverScope;
    private final String introspectionEndpoint;
    private final String introspectionClientId;
    private final String introspectionClientSecret;
    private final boolean introspectionInsecureTls;
    private final List<String> defaultEventTypes;
    private final boolean verificationEventEnabled;
    private final String receiverExpectedIssuer;
    private final String receiverJwksUrl;
    private final String receiverAudience;
    private final String receiverEndpointAuthToken;
    private final long receiverJwksCacheSeconds;
    private final boolean receiverInsecureTls;
    private final String receiverPollUrl;
    private final String receiverPollToken;
    private final long receiverPollIntervalSeconds;
    private final boolean receiverActionsEnabled;
    private final boolean auditEventsEnabled;
    private final String auditEventMap;

    private SsfConfiguration(Builder b) {
        if (b.issuer == null || b.issuer.isBlank()) {
            throw new IllegalArgumentException("issuer is required");
        }
        this.issuer = stripTrailingSlash(b.issuer.trim());
        this.signingAlgorithm = b.signingAlgorithm;
        this.basePath = b.basePath;
        this.dataStoreId = b.dataStoreId;
        this.storeDialect = parseStoreDialect(b.storeDialect);
        this.jdbcUrl = b.jdbcUrl;
        this.jdbcUsername = b.jdbcUsername;
        this.jdbcPassword = b.jdbcPassword;
        this.kafkaEnabled = b.kafkaEnabled;
        this.kafkaBootstrapServers = b.kafkaBootstrapServers;
        this.kafkaTopic = b.kafkaTopic;
        this.kafkaSecurityProtocol = b.kafkaSecurityProtocol;
        this.kafkaSaslMechanism = b.kafkaSaslMechanism;
        this.kafkaSaslUsername = b.kafkaSaslUsername;
        this.kafkaSaslPassword = b.kafkaSaslPassword;
        this.pushRetryMaxAttempts = b.pushRetryMaxAttempts;
        this.pushRetryBackoffSeconds = b.pushRetryBackoffSeconds;
        this.pollMaxEvents = b.pollMaxEvents;
        this.setTtlSeconds = b.setTtlSeconds;
        this.receiverScope = b.receiverScope;
        this.introspectionEndpoint = b.introspectionEndpoint;
        this.introspectionClientId = b.introspectionClientId;
        this.introspectionClientSecret = b.introspectionClientSecret;
        this.introspectionInsecureTls = b.introspectionInsecureTls;
        this.defaultEventTypes = (b.defaultEventTypes == null || b.defaultEventTypes.isEmpty())
                ? DEFAULT_EVENT_TYPES : List.copyOf(b.defaultEventTypes);
        this.verificationEventEnabled = b.verificationEventEnabled;
        this.receiverExpectedIssuer = b.receiverExpectedIssuer;
        this.receiverJwksUrl = b.receiverJwksUrl;
        this.receiverAudience = b.receiverAudience;
        this.receiverEndpointAuthToken = b.receiverEndpointAuthToken;
        this.receiverJwksCacheSeconds = b.receiverJwksCacheSeconds;
        this.receiverInsecureTls = b.receiverInsecureTls;
        this.receiverPollUrl = b.receiverPollUrl;
        this.receiverPollToken = b.receiverPollToken;
        this.receiverPollIntervalSeconds = b.receiverPollIntervalSeconds;
        this.receiverActionsEnabled = b.receiverActionsEnabled;
        this.auditEventsEnabled = b.auditEventsEnabled;
        this.auditEventMap = b.auditEventMap;
        if (this.kafkaEnabled && (this.kafkaBootstrapServers == null || this.kafkaBootstrapServers.isBlank())) {
            throw new IllegalArgumentException("kafkaBootstrapServers is required when kafkaEnabled=true");
        }
    }

    public static SsfConfiguration fromServletConfig(ServletConfig config) {
        try {
            Builder b = new Builder()
                    .issuer(param(config,"issuer"))
                    .signingAlgorithm(parseSigningAlgorithm(param(config,"signingAlgorithm")))
                    .basePath(orDefault(param(config,"basePath"), DEFAULT_BASE_PATH))
                    .dataStoreId(trimOrNull(param(config,"dataStoreId")))
                    .storeDialect(trimOrNull(param(config,"storeDialect")))
                    .jdbcUrl(trimOrNull(param(config,"jdbcUrl")))
                    .jdbcUsername(trimOrNull(param(config,"jdbcUsername")))
                    .jdbcPassword(trimOrNull(param(config,"jdbcPassword")))
                    .kafkaEnabled(parseBoolean(param(config,"kafkaEnabled"), false))
                    .kafkaBootstrapServers(trimOrNull(param(config,"kafkaBootstrapServers")))
                    .kafkaTopic(orDefault(param(config,"kafkaTopic"), DEFAULT_KAFKA_TOPIC))
                    .kafkaSecurityProtocol(orDefault(param(config,"kafkaSecurityProtocol"), DEFAULT_KAFKA_SECURITY_PROTOCOL))
                    .kafkaSaslMechanism(trimOrNull(param(config,"kafkaSaslMechanism")))
                    .kafkaSaslUsername(trimOrNull(param(config,"kafkaSaslUsername")))
                    .kafkaSaslPassword(trimOrNull(param(config,"kafkaSaslPassword")))
                    .pushRetryMaxAttempts(parseInt(param(config,"pushRetryMaxAttempts"), DEFAULT_PUSH_RETRY_MAX_ATTEMPTS))
                    .pushRetryBackoffSeconds(parseInt(param(config,"pushRetryBackoffSeconds"), DEFAULT_PUSH_RETRY_BACKOFF_SECONDS))
                    .pollMaxEvents(parseInt(param(config,"pollMaxEvents"), DEFAULT_POLL_MAX_EVENTS))
                    .setTtlSeconds(parseLong(param(config,"setTtlSeconds"), DEFAULT_SET_TTL_SECONDS))
                    .receiverScope(orDefault(param(config,"receiverScope"), DEFAULT_RECEIVER_SCOPE))
                    .introspectionEndpoint(trimOrNull(param(config,"introspectionEndpoint")))
                    .introspectionClientId(trimOrNull(param(config,"introspectionClientId")))
                    .introspectionClientSecret(trimOrNull(param(config,"introspectionClientSecret")))
                    .introspectionInsecureTls(parseBoolean(param(config,"introspectionInsecureTls"), false))
                    .defaultEventTypes(parseCommaSeparated(param(config,"defaultEventTypes")))
                    .verificationEventEnabled(parseBoolean(param(config,"verificationEventEnabled"), true))
                    .receiverExpectedIssuer(trimOrNull(param(config,"receiverExpectedIssuer")))
                    .receiverJwksUrl(trimOrNull(param(config,"receiverJwksUrl")))
                    .receiverAudience(trimOrNull(param(config,"receiverAudience")))
                    .receiverEndpointAuthToken(trimOrNull(param(config,"receiverEndpointAuthToken")))
                    .receiverJwksCacheSeconds(parseLong(param(config,"receiverJwksCacheSeconds"), 300L))
                    .receiverInsecureTls(parseBoolean(param(config,"receiverInsecureTls"), false))
                    .receiverPollUrl(trimOrNull(param(config,"receiverPollUrl")))
                    .receiverPollToken(trimOrNull(param(config,"receiverPollToken")))
                    .receiverPollIntervalSeconds(parseLong(param(config,"receiverPollIntervalSeconds"), 10L))
                    .receiverActionsEnabled(parseBoolean(param(config,"receiverActionsEnabled"), true))
                    .auditEventsEnabled(parseBoolean(param(config,"auditEventsEnabled"), true))
                    .auditEventMap(trimOrNull(param(config,"auditEventMap")));
            return b.build();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid SSF servlet configuration", e);
        }
    }

    public String issuer() {
        return this.issuer;
    }

    public String signingAlgorithm() {
        return this.signingAlgorithm;
    }

    public String basePath() {
        return this.basePath;
    }

    public String dataStoreId() {
        return this.dataStoreId;
    }

    /**
     * Which persistence layout the JDBC-backed store uses: {@code tables} (the module's own three
     * ssf_* tables) or {@code ldm} (the ID Partners Identity Object Model entry store — streams,
     * subjects, and pending SETs as object-class entries). Only meaningful when {@code dataStoreId} is set.
     */
    public String storeDialect() {
        return this.storeDialect;
    }

    public boolean usesInMemoryStore() {
        return (this.dataStoreId == null || this.dataStoreId.isBlank())
                && (this.jdbcUrl == null || this.jdbcUrl.isBlank());
    }

    /**
     * Direct JDBC URL (e.g. {@code jdbc:postgresql://host/db}) for the store — a demo/dev alternative to a
     * PingFederate-configured data store id. When set, it wins over {@code dataStoreId}. Production should
     * prefer {@code dataStoreId} (PF-managed pooling).
     */
    public String jdbcUrl() {
        return this.jdbcUrl;
    }

    public String jdbcUsername() {
        return this.jdbcUsername;
    }

    public String jdbcPassword() {
        return this.jdbcPassword;
    }

    public boolean kafkaEnabled() {
        return this.kafkaEnabled;
    }

    public String kafkaBootstrapServers() {
        return this.kafkaBootstrapServers;
    }

    public String kafkaTopic() {
        return this.kafkaTopic;
    }

    public String kafkaSecurityProtocol() {
        return this.kafkaSecurityProtocol;
    }

    public String kafkaSaslMechanism() {
        return this.kafkaSaslMechanism;
    }

    public String kafkaSaslUsername() {
        return this.kafkaSaslUsername;
    }

    public String kafkaSaslPassword() {
        return this.kafkaSaslPassword;
    }

    public int pushRetryMaxAttempts() {
        return this.pushRetryMaxAttempts;
    }

    public int pushRetryBackoffSeconds() {
        return this.pushRetryBackoffSeconds;
    }

    public int pollMaxEvents() {
        return this.pollMaxEvents;
    }

    public long setTtlSeconds() {
        return this.setTtlSeconds;
    }

    public String receiverScope() {
        return this.receiverScope;
    }

    /** Token introspection endpoint for receiver auth; defaults to {@code <issuer>/as/introspect.oauth2}. */
    public String introspectionEndpoint() {
        return this.introspectionEndpoint != null ? this.introspectionEndpoint
                : this.issuer + "/as/introspect.oauth2";
    }

    public String introspectionClientId() {
        return this.introspectionClientId;
    }

    public String introspectionClientSecret() {
        return this.introspectionClientSecret;
    }

    public boolean introspectionInsecureTls() {
        return this.introspectionInsecureTls;
    }

    /** True when the introspection client credentials needed for receiver auth are configured. */
    public boolean receiverAuthConfigured() {
        return this.introspectionClientId != null && !this.introspectionClientId.isBlank();
    }

    public List<String> defaultEventTypes() {
        return this.defaultEventTypes;
    }

    public boolean verificationEventEnabled() {
        return this.verificationEventEnabled;
    }

    // ---- receiver side (inbound SETs) ----

    /** The transmitter issuer we accept inbound SETs from; unset = the receiver is disabled. */
    public String receiverExpectedIssuer() {
        return this.receiverExpectedIssuer;
    }

    public boolean receiverConfigured() {
        return this.receiverExpectedIssuer != null && !this.receiverExpectedIssuer.isBlank();
    }

    /** Source SSF events from PF's security-audit loggers ({@code SsfAuditLogSource}); default on. */
    public boolean auditEventsEnabled() {
        return this.auditEventsEnabled;
    }

    /** Optional {@code EVENT=action} CSV extending/overriding the audit event vocabulary (null = defaults). */
    public String auditEventMap() {
        return this.auditEventMap;
    }

    /** JWKS to verify inbound SETs against; defaults to {@code <receiverExpectedIssuer>/pf/JWKS}. */
    public String receiverJwksUrl() {
        return this.receiverJwksUrl != null ? this.receiverJwksUrl
                : this.receiverExpectedIssuer + "/pf/JWKS";
    }

    /** Expected {@code aud} of inbound SETs (null = not enforced). */
    public String receiverAudience() {
        return this.receiverAudience;
    }

    /** Optional bearer token the transmitter must present when POSTing to our push endpoint. */
    public String receiverEndpointAuthToken() {
        return this.receiverEndpointAuthToken;
    }

    public long receiverJwksCacheSeconds() {
        return this.receiverJwksCacheSeconds;
    }

    public boolean receiverInsecureTls() {
        return this.receiverInsecureTls;
    }

    /** Remote transmitter poll endpoint to pull SETs from (null = no polling; push only). */
    public String receiverPollUrl() {
        return this.receiverPollUrl;
    }

    public String receiverPollToken() {
        return this.receiverPollToken;
    }

    public long receiverPollIntervalSeconds() {
        return this.receiverPollIntervalSeconds;
    }

    /** Whether inbound revocation signals act on PF (revoke the subject's grants). Default true. */
    public boolean receiverActionsEnabled() {
        return this.receiverActionsEnabled;
    }

    // ---- endpoint URLs advertised in ssf-configuration (issuer + fixed module paths) ----

    public String configurationEndpoint() {
        return this.issuer + this.basePath + "/streams";
    }

    public String statusEndpoint() {
        return this.issuer + this.basePath + "/status";
    }

    public String addSubjectEndpoint() {
        return this.issuer + this.basePath + "/subjects:add";
    }

    public String removeSubjectEndpoint() {
        return this.issuer + this.basePath + "/subjects:remove";
    }

    public String verificationEndpoint() {
        return this.issuer + this.basePath + "/verify";
    }

    public String jwksUri() {
        return this.issuer + "/pf/JWKS";
    }

    // ---- parsing helpers (mirrors FederationConfiguration) ----

    /**
     * Resolve a configuration value from, in order: the servlet {@code init-param} (web.xml), the system
     * property {@code oidf.ssf.<name>} (PingFederate loads {@code run.properties} entries as system
     * properties — the same channel the attestation module uses), then the environment variable
     * {@code OIDF_SSF_<UPPER_SNAKE(name)>}. This lets the SSF servlets be configured with no web.xml when they
     * are annotation-mapped inside {@code pf-runtime.war} — via {@code run.properties} or Railway env vars.
     */
    static String param(ServletConfig config, String name) {
        String v = config != null ? config.getInitParameter(name) : null;
        if (v == null || v.isBlank()) {
            v = System.getProperty("oidf.ssf." + name);
        }
        if (v == null || v.isBlank()) {
            v = System.getenv("OIDF_SSF_" + camelToUpperSnake(name));
        }
        return v == null || v.isBlank() ? null : v;
    }

    private static String camelToUpperSnake(String camel) {
        StringBuilder sb = new StringBuilder(camel.length() + 4);
        for (int i = 0; i < camel.length(); i++) {
            char c = camel.charAt(i);
            if (Character.isUpperCase(c) && i > 0) {
                sb.append('_');
            }
            sb.append(Character.toUpperCase(c));
        }
        return sb.toString();
    }

    private static String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private static List<String> parseCommaSeparated(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        ArrayList<String> result = new ArrayList<>();
        for (String token : value.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }

    private static String orDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static String trimOrNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static boolean parseBoolean(String value, boolean fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return Boolean.parseBoolean(value.trim());
    }

    private static String parseSigningAlgorithm(String value) {
        if (value == null || value.isBlank()) {
            return DEFAULT_SIGNING_ALGORITHM;
        }
        String trimmed = value.trim();
        if (!SUPPORTED_SIGNING_ALGORITHMS.contains(trimmed)) {
            throw new IllegalArgumentException("signingAlgorithm must be RS256 or PS256, got: " + trimmed);
        }
        return trimmed;
    }

    private static String parseStoreDialect(String value) {
        if (value == null || value.isBlank()) {
            return DEFAULT_STORE_DIALECT;
        }
        String trimmed = value.trim();
        if (!SUPPORTED_STORE_DIALECTS.contains(trimmed)) {
            throw new IllegalArgumentException("storeDialect must be tables or ldm, got: " + trimmed);
        }
        return trimmed;
    }

    private static int parseInt(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid integer value: " + value, e);
        }
    }

    private static long parseLong(String value, long fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid long value: " + value, e);
        }
    }

    /** Mutable builder; every setter tolerates null and falls back to the documented default at {@link #build()}. */
    public static final class Builder {
        private String issuer;
        private String signingAlgorithm = DEFAULT_SIGNING_ALGORITHM;
        private String basePath = DEFAULT_BASE_PATH;
        private String dataStoreId;
        private String storeDialect;
        private String jdbcUrl;
        private String jdbcUsername;
        private String jdbcPassword;
        private boolean kafkaEnabled;
        private String kafkaBootstrapServers;
        private String kafkaTopic = DEFAULT_KAFKA_TOPIC;
        private String kafkaSecurityProtocol = DEFAULT_KAFKA_SECURITY_PROTOCOL;
        private String kafkaSaslMechanism;
        private String kafkaSaslUsername;
        private String kafkaSaslPassword;
        private int pushRetryMaxAttempts = DEFAULT_PUSH_RETRY_MAX_ATTEMPTS;
        private int pushRetryBackoffSeconds = DEFAULT_PUSH_RETRY_BACKOFF_SECONDS;
        private int pollMaxEvents = DEFAULT_POLL_MAX_EVENTS;
        private long setTtlSeconds = DEFAULT_SET_TTL_SECONDS;
        private String receiverScope = DEFAULT_RECEIVER_SCOPE;
        private String introspectionEndpoint;
        private String introspectionClientId;
        private String introspectionClientSecret;
        private boolean introspectionInsecureTls;
        private List<String> defaultEventTypes;
        private boolean verificationEventEnabled = true;
        private String receiverExpectedIssuer;
        private String receiverJwksUrl;
        private String receiverAudience;
        private String receiverEndpointAuthToken;
        private long receiverJwksCacheSeconds = 300L;
        private boolean receiverInsecureTls;
        private String receiverPollUrl;
        private String receiverPollToken;
        private long receiverPollIntervalSeconds = 10L;
        private boolean receiverActionsEnabled = true;
        private boolean auditEventsEnabled = true;
        private String auditEventMap;

        public Builder issuer(String v) {
            this.issuer = v;
            return this;
        }

        public Builder signingAlgorithm(String v) {
            if (v != null && !v.isBlank()) {
                this.signingAlgorithm = v;
            }
            return this;
        }

        public Builder basePath(String v) {
            if (v != null && !v.isBlank()) {
                this.basePath = v;
            }
            return this;
        }

        public Builder dataStoreId(String v) {
            this.dataStoreId = v;
            return this;
        }

        public Builder storeDialect(String v) {
            this.storeDialect = v;
            return this;
        }

        public Builder jdbcUrl(String v) {
            this.jdbcUrl = v;
            return this;
        }

        public Builder jdbcUsername(String v) {
            this.jdbcUsername = v;
            return this;
        }

        public Builder jdbcPassword(String v) {
            this.jdbcPassword = v;
            return this;
        }

        public Builder kafkaEnabled(boolean v) {
            this.kafkaEnabled = v;
            return this;
        }

        public Builder kafkaBootstrapServers(String v) {
            this.kafkaBootstrapServers = v;
            return this;
        }

        public Builder kafkaTopic(String v) {
            if (v != null && !v.isBlank()) {
                this.kafkaTopic = v;
            }
            return this;
        }

        public Builder kafkaSecurityProtocol(String v) {
            if (v != null && !v.isBlank()) {
                this.kafkaSecurityProtocol = v;
            }
            return this;
        }

        public Builder kafkaSaslMechanism(String v) {
            this.kafkaSaslMechanism = v;
            return this;
        }

        public Builder kafkaSaslUsername(String v) {
            this.kafkaSaslUsername = v;
            return this;
        }

        public Builder kafkaSaslPassword(String v) {
            this.kafkaSaslPassword = v;
            return this;
        }

        public Builder pushRetryMaxAttempts(int v) {
            this.pushRetryMaxAttempts = v;
            return this;
        }

        public Builder pushRetryBackoffSeconds(int v) {
            this.pushRetryBackoffSeconds = v;
            return this;
        }

        public Builder pollMaxEvents(int v) {
            this.pollMaxEvents = v;
            return this;
        }

        public Builder setTtlSeconds(long v) {
            this.setTtlSeconds = v;
            return this;
        }

        public Builder receiverScope(String v) {
            if (v != null && !v.isBlank()) {
                this.receiverScope = v;
            }
            return this;
        }

        public Builder introspectionEndpoint(String v) {
            this.introspectionEndpoint = v;
            return this;
        }

        public Builder introspectionClientId(String v) {
            this.introspectionClientId = v;
            return this;
        }

        public Builder introspectionClientSecret(String v) {
            this.introspectionClientSecret = v;
            return this;
        }

        public Builder introspectionInsecureTls(boolean v) {
            this.introspectionInsecureTls = v;
            return this;
        }

        public Builder defaultEventTypes(List<String> v) {
            this.defaultEventTypes = v;
            return this;
        }

        public Builder verificationEventEnabled(boolean v) {
            this.verificationEventEnabled = v;
            return this;
        }

        public Builder receiverExpectedIssuer(String v) {
            this.receiverExpectedIssuer = v;
            return this;
        }

        public Builder receiverJwksUrl(String v) {
            this.receiverJwksUrl = v;
            return this;
        }

        public Builder receiverAudience(String v) {
            this.receiverAudience = v;
            return this;
        }

        public Builder receiverEndpointAuthToken(String v) {
            this.receiverEndpointAuthToken = v;
            return this;
        }

        public Builder receiverJwksCacheSeconds(long v) {
            this.receiverJwksCacheSeconds = v;
            return this;
        }

        public Builder receiverInsecureTls(boolean v) {
            this.receiverInsecureTls = v;
            return this;
        }

        public Builder receiverPollUrl(String v) {
            this.receiverPollUrl = v;
            return this;
        }

        public Builder receiverPollToken(String v) {
            this.receiverPollToken = v;
            return this;
        }

        public Builder receiverPollIntervalSeconds(long v) {
            this.receiverPollIntervalSeconds = v;
            return this;
        }

        public Builder receiverActionsEnabled(boolean v) {
            this.receiverActionsEnabled = v;
            return this;
        }

        public Builder auditEventsEnabled(boolean v) {
            this.auditEventsEnabled = v;
            return this;
        }

        public Builder auditEventMap(String v) {
            this.auditEventMap = v;
            return this;
        }

        public SsfConfiguration build() {
            return new SsfConfiguration(this);
        }
    }
}
