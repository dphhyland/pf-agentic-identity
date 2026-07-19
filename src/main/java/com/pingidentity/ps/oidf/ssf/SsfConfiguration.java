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
    private final List<String> defaultEventTypes;
    private final boolean verificationEventEnabled;

    private SsfConfiguration(Builder b) {
        if (b.issuer == null || b.issuer.isBlank()) {
            throw new IllegalArgumentException("issuer is required");
        }
        this.issuer = stripTrailingSlash(b.issuer.trim());
        this.signingAlgorithm = b.signingAlgorithm;
        this.basePath = b.basePath;
        this.dataStoreId = b.dataStoreId;
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
        this.defaultEventTypes = (b.defaultEventTypes == null || b.defaultEventTypes.isEmpty())
                ? DEFAULT_EVENT_TYPES : List.copyOf(b.defaultEventTypes);
        this.verificationEventEnabled = b.verificationEventEnabled;
        if (this.kafkaEnabled && (this.kafkaBootstrapServers == null || this.kafkaBootstrapServers.isBlank())) {
            throw new IllegalArgumentException("kafkaBootstrapServers is required when kafkaEnabled=true");
        }
    }

    public static SsfConfiguration fromServletConfig(ServletConfig config) {
        try {
            Builder b = new Builder()
                    .issuer(config.getInitParameter("issuer"))
                    .signingAlgorithm(parseSigningAlgorithm(config.getInitParameter("signingAlgorithm")))
                    .basePath(orDefault(config.getInitParameter("basePath"), DEFAULT_BASE_PATH))
                    .dataStoreId(trimOrNull(config.getInitParameter("dataStoreId")))
                    .kafkaEnabled(parseBoolean(config.getInitParameter("kafkaEnabled"), false))
                    .kafkaBootstrapServers(trimOrNull(config.getInitParameter("kafkaBootstrapServers")))
                    .kafkaTopic(orDefault(config.getInitParameter("kafkaTopic"), DEFAULT_KAFKA_TOPIC))
                    .kafkaSecurityProtocol(orDefault(config.getInitParameter("kafkaSecurityProtocol"), DEFAULT_KAFKA_SECURITY_PROTOCOL))
                    .kafkaSaslMechanism(trimOrNull(config.getInitParameter("kafkaSaslMechanism")))
                    .kafkaSaslUsername(trimOrNull(config.getInitParameter("kafkaSaslUsername")))
                    .kafkaSaslPassword(trimOrNull(config.getInitParameter("kafkaSaslPassword")))
                    .pushRetryMaxAttempts(parseInt(config.getInitParameter("pushRetryMaxAttempts"), DEFAULT_PUSH_RETRY_MAX_ATTEMPTS))
                    .pushRetryBackoffSeconds(parseInt(config.getInitParameter("pushRetryBackoffSeconds"), DEFAULT_PUSH_RETRY_BACKOFF_SECONDS))
                    .pollMaxEvents(parseInt(config.getInitParameter("pollMaxEvents"), DEFAULT_POLL_MAX_EVENTS))
                    .setTtlSeconds(parseLong(config.getInitParameter("setTtlSeconds"), DEFAULT_SET_TTL_SECONDS))
                    .receiverScope(orDefault(config.getInitParameter("receiverScope"), DEFAULT_RECEIVER_SCOPE))
                    .defaultEventTypes(parseCommaSeparated(config.getInitParameter("defaultEventTypes")))
                    .verificationEventEnabled(parseBoolean(config.getInitParameter("verificationEventEnabled"), true));
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

    public boolean usesInMemoryStore() {
        return this.dataStoreId == null || this.dataStoreId.isBlank();
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

    public List<String> defaultEventTypes() {
        return this.defaultEventTypes;
    }

    public boolean verificationEventEnabled() {
        return this.verificationEventEnabled;
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
        private List<String> defaultEventTypes;
        private boolean verificationEventEnabled = true;

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

        public Builder defaultEventTypes(List<String> v) {
            this.defaultEventTypes = v;
            return this;
        }

        public Builder verificationEventEnabled(boolean v) {
            this.verificationEventEnabled = v;
            return this;
        }

        public SsfConfiguration build() {
            return new SsfConfiguration(this);
        }
    }
}
