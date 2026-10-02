/*
 * Typed configuration for the SSF transmitter, read through its settings catalogue.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.pf.settings.InitParams;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.ServletConfig;

/**
 * Configuration surface for the Shared Signals transmitter: an immutable value read through the
 * {@code ssf-transmitter} settings catalogue ({@link #from(Settings)}; {@link #fromServletConfig} with a servlet's
 * init-params, the {@code oidf.ssf.<camelCase>} system properties and the {@code OIDF_SSF_*} environment, in that
 * order), with a {@link Builder} for unit tests. All timing/size knobs have documented defaults so a minimal
 * deployment only needs {@code OIDF_SSF_ISSUER}.
 *
 * <p>{@code dataStoreId} selects persistence: when blank, the transmitter uses the per-node in-memory store
 * (dev fallback, not cluster-safe); when set, it names a PingFederate-configured JDBC data store. Kafka
 * fan-out is fully off unless {@code kafkaEnabled} is true, and when off no Kafka classes are loaded.
 */
public final class SsfConfiguration {

    private static final String DEFAULT_SIGNING_ALGORITHM = "RS256";
    private static final String DEFAULT_STORE_DIALECT = "tables";
    private static final Set<String> SUPPORTED_STORE_DIALECTS = Set.of("tables", "ldm");
    private static final String DEFAULT_KAFKA_TOPIC = "sse-events";
    /** TLS by default (plan item PR-2): PLAINTEXT and SASL_PLAINTEXT are forbidden in production and must be asked for. */
    private static final String DEFAULT_KAFKA_SECURITY_PROTOCOL = "SSL";
    /** Kafka's producer timeouts, bounded (S5d): send() blocks the thread that raised the event for up to max.block.ms. */
    static final int DEFAULT_KAFKA_REQUEST_TIMEOUT_MS = 10_000;
    static final int DEFAULT_KAFKA_DELIVERY_TIMEOUT_MS = 30_000;
    static final int DEFAULT_KAFKA_MAX_BLOCK_MS = 2_000;
    private static final String DEFAULT_RECEIVER_SCOPE = "ssf.manage";
    private static final int DEFAULT_PUSH_RETRY_MAX_ATTEMPTS = 5;
    private static final int DEFAULT_PUSH_RETRY_BACKOFF_SECONDS = 5;
    private static final int DEFAULT_POLL_MAX_EVENTS = 100;
    private static final int DEFAULT_POLL_MAX_EVENTS_CAP = 100;
    private static final int DEFAULT_POLL_LONG_POLL_WAIT_SECONDS = 10;
    private static final int DEFAULT_MAX_STREAMS_PER_CLIENT = 10;
    private static final int DEFAULT_MIN_VERIFICATION_INTERVAL_SECONDS = 30;
    private static final long DEFAULT_SET_TTL_SECONDS = 604800L; // 7 days
    private static final List<String> DEFAULT_EVENT_TYPES = List.of(
            SsfEventTypes.CAEP_SESSION_REVOKED,
            SsfEventTypes.CAEP_CREDENTIAL_CHANGE,
            SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE,
            SsfEventTypes.RISC_ACCOUNT_DISABLED,
            SsfEventTypes.RISC_ACCOUNT_ENABLED);
    static final String DEFAULT_SUBJECTS_ALL = "ALL";
    static final String DEFAULT_SUBJECTS_NONE = "NONE";

    private final String issuer;
    private final String signingAlgorithm;
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
    private final String kafkaSslTruststoreLocation;
    private final String kafkaSslTruststorePassword;
    private final String kafkaSslTruststoreType;
    private final String kafkaSslKeystoreLocation;
    private final String kafkaSslKeystorePassword;
    private final String kafkaSslKeystoreType;
    private final String kafkaSslKeyPassword;
    private final boolean kafkaSslHostnameVerification;
    private final int kafkaRequestTimeoutMs;
    private final int kafkaDeliveryTimeoutMs;
    private final int kafkaMaxBlockMs;
    private final String secretKey;
    private final String secretKeyPrevious;
    private final int pushRetryMaxAttempts;
    private final int pushRetryBackoffSeconds;
    private final int pollMaxEvents;
    private final long setTtlSeconds;
    private final String receiverScope;
    private final String unownedStreamOwner;
    private final String provisionerScope;
    private final Map<String, Set<String>> allowedAudiences;
    private final String introspectionEndpoint;
    private final String introspectionClientId;
    private final String introspectionClientSecret;
    private final boolean introspectionInsecureTls;
    private final List<String> defaultEventTypes;
    private final String defaultSubjects;
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
    private final boolean receiverInstanceRegistry;
    private final boolean auditEventsEnabled;
    private final String auditEventMap;
    // H-SSF-1 and H-SSF-2 (0.6.0): the receiver's client, its managed stream, and the poll endpoint's cap and wait.
    private final String receiverTokenEndpoint;
    private final String receiverClientId;
    private final String receiverClientSecret;
    private final String receiverClientKey;
    private final String receiverClientScope;
    private final String receiverTransmitterConfigurationUrl;
    private final String receiverPushEndpointUrl;
    private final List<String> receiverEventsRequested;
    private final int pollMaxEventsCap;
    private final int pollLongPollWaitSeconds;
    private final Set<String> receiverSubjectIssuers;
    private final int maxStreamsPerClient;
    private final int minVerificationIntervalSeconds;
    private final long inactivityTimeoutSeconds;

    private SsfConfiguration(Builder b) {
        if (b.issuer == null || b.issuer.isBlank()) {
            throw new IllegalArgumentException("issuer is required");
        }
        this.issuer = stripTrailingSlash(b.issuer.trim());
        this.signingAlgorithm = b.signingAlgorithm;
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
        this.kafkaSslTruststoreLocation = trimOrNull(b.kafkaSslTruststoreLocation);
        this.kafkaSslTruststorePassword = b.kafkaSslTruststorePassword;
        this.kafkaSslTruststoreType = trimOrNull(b.kafkaSslTruststoreType);
        this.kafkaSslKeystoreLocation = trimOrNull(b.kafkaSslKeystoreLocation);
        this.kafkaSslKeystorePassword = b.kafkaSslKeystorePassword;
        this.kafkaSslKeystoreType = trimOrNull(b.kafkaSslKeystoreType);
        this.kafkaSslKeyPassword = b.kafkaSslKeyPassword;
        this.kafkaSslHostnameVerification = b.kafkaSslHostnameVerification;
        this.kafkaRequestTimeoutMs = b.kafkaRequestTimeoutMs;
        this.kafkaDeliveryTimeoutMs = b.kafkaDeliveryTimeoutMs;
        this.kafkaMaxBlockMs = b.kafkaMaxBlockMs;
        if (this.kafkaDeliveryTimeoutMs < this.kafkaRequestTimeoutMs) {
            // Kafka's producer refuses to start otherwise: delivery.timeout.ms "should be greater than or equal to the
            // sum of request.timeout.ms and linger.ms", and KafkaSetPublisher sets linger.ms to 0.
            throw new Refused(KAFKA_DELIVERY_TIMEOUT_MS, KAFKA_DELIVERY_TIMEOUT_MS + " (" + this.kafkaDeliveryTimeoutMs
                    + ") is less than " + KAFKA_REQUEST_TIMEOUT_MS + " (" + this.kafkaRequestTimeoutMs + "): Kafka's producer"
                    + " requires delivery.timeout.ms >= request.timeout.ms + linger.ms (0 here)");
        }
        this.secretKey = trimOrNull(b.secretKey);
        this.secretKeyPrevious = trimOrNull(b.secretKeyPrevious);
        checkSecretKeys(this.secretKey, this.secretKeyPrevious);
        this.pushRetryMaxAttempts = b.pushRetryMaxAttempts;
        this.pushRetryBackoffSeconds = b.pushRetryBackoffSeconds;
        this.pollMaxEvents = b.pollMaxEvents;
        this.setTtlSeconds = b.setTtlSeconds;
        this.receiverScope = b.receiverScope;
        this.unownedStreamOwner = trimOrNull(b.unownedStreamOwner);
        this.provisionerScope = trimOrNull(b.provisionerScope);
        this.allowedAudiences = parseAllowedAudiences(b.allowedAudiences);
        if (this.receiverScope.equals(this.provisionerScope)) {
            throw new Refused(PROVISIONER_SCOPE, PROVISIONER_SCOPE + " must not be the receiver scope (" + RECEIVER_SCOPE + ", '"
                    + this.receiverScope + "'): every receiver would be a provisioner, able to have an account-disabled signed"
                    + " about any subject");
        }
        this.introspectionEndpoint = b.introspectionEndpoint;
        this.introspectionClientId = b.introspectionClientId;
        this.introspectionClientSecret = b.introspectionClientSecret;
        this.introspectionInsecureTls = b.introspectionInsecureTls;
        this.defaultEventTypes = (b.defaultEventTypes == null || b.defaultEventTypes.isEmpty())
                ? DEFAULT_EVENT_TYPES : List.copyOf(b.defaultEventTypes);
        this.defaultSubjects = parseDefaultSubjects(b.defaultSubjects);
        this.verificationEventEnabled = b.verificationEventEnabled;
        this.receiverExpectedIssuer = b.receiverExpectedIssuer;
        this.receiverJwksUrl = b.receiverJwksUrl;
        this.receiverAudience = trimOrNull(b.receiverAudience);
        this.receiverEndpointAuthToken = trimOrNull(b.receiverEndpointAuthToken);
        this.receiverJwksCacheSeconds = b.receiverJwksCacheSeconds;
        this.receiverInsecureTls = b.receiverInsecureTls;
        this.receiverPollUrl = b.receiverPollUrl;
        this.receiverPollToken = b.receiverPollToken;
        this.receiverPollIntervalSeconds = b.receiverPollIntervalSeconds;
        this.receiverActionsEnabled = b.receiverActionsEnabled;
        this.receiverInstanceRegistry = b.receiverInstanceRegistry;
        this.auditEventsEnabled = b.auditEventsEnabled;
        this.auditEventMap = b.auditEventMap;
        if (this.kafkaEnabled && (this.kafkaBootstrapServers == null || this.kafkaBootstrapServers.isBlank())) {
            throw new Refused(KAFKA_BOOTSTRAP_SERVERS, KAFKA_BOOTSTRAP_SERVERS + " is required when " + KAFKA_ENABLED + "=true");
        }
        this.receiverTokenEndpoint = trimOrNull(b.receiverTokenEndpoint);
        this.receiverClientId = trimOrNull(b.receiverClientId);
        this.receiverClientSecret = trimOrNull(b.receiverClientSecret);
        this.receiverClientKey = trimOrNull(b.receiverClientKey);
        this.receiverClientScope = trimOrNull(b.receiverClientScope);
        this.receiverTransmitterConfigurationUrl = trimOrNull(b.receiverTransmitterConfigurationUrl);
        this.receiverPushEndpointUrl = trimOrNull(b.receiverPushEndpointUrl);
        this.receiverEventsRequested = b.receiverEventsRequested == null || b.receiverEventsRequested.isEmpty()
                ? RECEIVER_DEFAULT_EVENTS : List.copyOf(b.receiverEventsRequested);
        this.pollMaxEventsCap = b.pollMaxEventsCap;
        this.pollLongPollWaitSeconds = b.pollLongPollWaitSeconds;
        this.receiverSubjectIssuers = b.receiverSubjectIssuers == null ? Set.of() : Set.copyOf(b.receiverSubjectIssuers);
        this.maxStreamsPerClient = b.maxStreamsPerClient;
        this.minVerificationIntervalSeconds = b.minVerificationIntervalSeconds;
        this.inactivityTimeoutSeconds = b.inactivityTimeoutSeconds;
        refuseReceiverCombinations();
    }

    /** The events a managed stream asks for when {@code OIDF_SSF_RECEIVER_EVENTS_REQUESTED} is unset: what the handlers act on. */
    static final List<String> RECEIVER_DEFAULT_EVENTS = List.of(SsfEventTypes.CAEP_SESSION_REVOKED,
            SsfEventTypes.CAEP_CREDENTIAL_CHANGE, SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE,
            SsfEventTypes.RISC_ACCOUNT_DISABLED, SsfEventTypes.RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED);

    /**
     * The receiver's token and stream settings that only make sense together (H-SSF-1): a client needs its token
     * endpoint, an id and exactly one of a secret or a key that parses; the static poll token and a client are not
     * both set; a managed stream needs a token and takes its poll URL from the stream; a push endpoint needs a managed
     * stream.
     */
    private void refuseReceiverCombinations() {
        boolean client = this.receiverClientId != null || this.receiverClientSecret != null || this.receiverClientKey != null;
        if (client && this.receiverTokenEndpoint == null) {
            throw new Refused(RECEIVER_TOKEN_ENDPOINT, RECEIVER_TOKEN_ENDPOINT + " is required when the receiver has a client ("
                    + RECEIVER_CLIENT_ID + ", " + RECEIVER_CLIENT_SECRET + " or " + RECEIVER_CLIENT_KEY + ")");
        }
        if (this.receiverTokenEndpoint != null) {
            if (this.receiverClientId == null) {
                throw new Refused(RECEIVER_CLIENT_ID, RECEIVER_CLIENT_ID + " is required with " + RECEIVER_TOKEN_ENDPOINT);
            }
            if ((this.receiverClientSecret == null) == (this.receiverClientKey == null)) {
                throw new Refused(RECEIVER_CLIENT_SECRET, "set one of " + RECEIVER_CLIENT_SECRET + " and " + RECEIVER_CLIENT_KEY
                        + " with " + RECEIVER_TOKEN_ENDPOINT + ", not " + (this.receiverClientSecret == null ? "neither" : "both"));
            }
            if (this.receiverClientKey != null) {
                try {
                    ClientCredentialsToken.privateKey(this.receiverClientKey);
                } catch (IllegalArgumentException e) {
                    throw new Refused(RECEIVER_CLIENT_KEY, RECEIVER_CLIENT_KEY + ": " + e.getMessage());
                }
            }
            if (this.receiverPollToken != null && !this.receiverPollToken.isBlank()) {
                throw new Refused(RECEIVER_POLL_TOKEN, RECEIVER_POLL_TOKEN + " is the development token; unset it now that the"
                        + " receiver has a client (" + RECEIVER_TOKEN_ENDPOINT + ")");
            }
        }
        if (this.receiverTransmitterConfigurationUrl != null) {
            if (this.receiverTokenEndpoint == null && (this.receiverPollToken == null || this.receiverPollToken.isBlank())) {
                throw new Refused(RECEIVER_TRANSMITTER_CONFIGURATION_URL, RECEIVER_TRANSMITTER_CONFIGURATION_URL
                        + " needs a token for the transmitter's stream API: set " + RECEIVER_TOKEN_ENDPOINT + " and its client");
            }
            if (this.receiverPollUrl != null) {
                throw new Refused(RECEIVER_POLL_URL, RECEIVER_POLL_URL + " is the transmitter's to say when the receiver manages"
                        + " its stream (" + RECEIVER_TRANSMITTER_CONFIGURATION_URL + "): unset it");
            }
        } else if (this.receiverPushEndpointUrl != null) {
            throw new Refused(RECEIVER_PUSH_ENDPOINT_URL, RECEIVER_PUSH_ENDPOINT_URL + " names where a managed stream pushes, so it"
                    + " needs " + RECEIVER_TRANSMITTER_CONFIGURATION_URL);
        }
    }

    // The catalogue's names (META-INF/oidf-settings/ssf-transmitter.json), read through platform.settings. Each entry's
    // sources are the init-param, the system property oidf.ssf.<init-param> and the environment variable, in that
    // order, as SsfConfiguration.param read them before 0.6.0 (F-0235).
    public static final String ISSUER = "OIDF_SSF_ISSUER";
    static final String SIGNING_ALGORITHM = "OIDF_SSF_SIGNING_ALGORITHM";
    static final String DATA_STORE_ID = "OIDF_SSF_DATA_STORE_ID";
    static final String STORE_DIALECT = "OIDF_SSF_STORE_DIALECT";
    public static final String JDBC_URL = "OIDF_SSF_JDBC_URL";
    static final String JDBC_USERNAME = "OIDF_SSF_JDBC_USERNAME";
    static final String JDBC_PASSWORD = "OIDF_SSF_JDBC_PASSWORD";
    static final String KAFKA_ENABLED = "OIDF_SSF_KAFKA_ENABLED";
    static final String KAFKA_BOOTSTRAP_SERVERS = "OIDF_SSF_KAFKA_BOOTSTRAP_SERVERS";
    static final String KAFKA_TOPIC = "OIDF_SSF_KAFKA_TOPIC";
    static final String KAFKA_SECURITY_PROTOCOL = "OIDF_SSF_KAFKA_SECURITY_PROTOCOL";
    static final String KAFKA_SASL_MECHANISM = "OIDF_SSF_KAFKA_SASL_MECHANISM";
    static final String KAFKA_SASL_USERNAME = "OIDF_SSF_KAFKA_SASL_USERNAME";
    static final String KAFKA_SASL_PASSWORD = "OIDF_SSF_KAFKA_SASL_PASSWORD";
    static final String KAFKA_SSL_TRUSTSTORE_LOCATION = "OIDF_SSF_KAFKA_SSL_TRUSTSTORE_LOCATION";
    static final String KAFKA_SSL_TRUSTSTORE_PASSWORD = "OIDF_SSF_KAFKA_SSL_TRUSTSTORE_PASSWORD";
    static final String KAFKA_SSL_TRUSTSTORE_TYPE = "OIDF_SSF_KAFKA_SSL_TRUSTSTORE_TYPE";
    static final String KAFKA_SSL_KEYSTORE_LOCATION = "OIDF_SSF_KAFKA_SSL_KEYSTORE_LOCATION";
    static final String KAFKA_SSL_KEYSTORE_PASSWORD = "OIDF_SSF_KAFKA_SSL_KEYSTORE_PASSWORD";
    static final String KAFKA_SSL_KEYSTORE_TYPE = "OIDF_SSF_KAFKA_SSL_KEYSTORE_TYPE";
    static final String KAFKA_SSL_KEY_PASSWORD = "OIDF_SSF_KAFKA_SSL_KEY_PASSWORD";
    static final String KAFKA_SSL_HOSTNAME_VERIFICATION = "OIDF_SSF_KAFKA_SSL_HOSTNAME_VERIFICATION";
    static final String KAFKA_REQUEST_TIMEOUT_MS = "OIDF_SSF_KAFKA_REQUEST_TIMEOUT_MS";
    static final String KAFKA_DELIVERY_TIMEOUT_MS = "OIDF_SSF_KAFKA_DELIVERY_TIMEOUT_MS";
    static final String KAFKA_MAX_BLOCK_MS = "OIDF_SSF_KAFKA_MAX_BLOCK_MS";
    static final String SECRET_KEY = PushHeaderCipher.KEY_SETTING;
    static final String SECRET_KEY_PREVIOUS = PushHeaderCipher.PREVIOUS_KEY_SETTING;
    static final String PUSH_RETRY_MAX_ATTEMPTS = "OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS";
    static final String PUSH_RETRY_BACKOFF_SECONDS = "OIDF_SSF_PUSH_RETRY_BACKOFF_SECONDS";
    static final String POLL_MAX_EVENTS = "OIDF_SSF_POLL_MAX_EVENTS";
    static final String SET_TTL_SECONDS = "OIDF_SSF_SET_TTL_SECONDS";
    static final String RECEIVER_SCOPE = "OIDF_SSF_RECEIVER_SCOPE";
    static final String UNOWNED_STREAM_OWNER = "OIDF_SSF_UNOWNED_STREAM_OWNER";
    static final String PROVISIONER_SCOPE = "OIDF_SSF_PROVISIONER_SCOPE";
    static final String ALLOWED_AUDIENCES = "OIDF_SSF_ALLOWED_AUDIENCES";
    static final String INTROSPECTION_ENDPOINT = "OIDF_SSF_INTROSPECTION_ENDPOINT";
    static final String INTROSPECTION_CLIENT_ID = "OIDF_SSF_INTROSPECTION_CLIENT_ID";
    static final String INTROSPECTION_CLIENT_SECRET = "OIDF_SSF_INTROSPECTION_CLIENT_SECRET";
    static final String INTROSPECTION_INSECURE_TLS_SETTING = "OIDF_SSF_INTROSPECTION_INSECURE_TLS";
    static final String DEFAULT_EVENT_TYPES_SETTING = "OIDF_SSF_DEFAULT_EVENT_TYPES";
    static final String DEFAULT_SUBJECTS = "OIDF_SSF_DEFAULT_SUBJECTS";
    static final String VERIFICATION_EVENT_ENABLED = "OIDF_SSF_VERIFICATION_EVENT_ENABLED";
    public static final String RECEIVER_EXPECTED_ISSUER = "OIDF_SSF_RECEIVER_EXPECTED_ISSUER";
    static final String RECEIVER_JWKS_URL = "OIDF_SSF_RECEIVER_JWKS_URL";
    public static final String RECEIVER_AUDIENCE = "OIDF_SSF_RECEIVER_AUDIENCE";
    public static final String RECEIVER_ENDPOINT_AUTH_TOKEN = "OIDF_SSF_RECEIVER_ENDPOINT_AUTH_TOKEN";
    static final String RECEIVER_JWKS_CACHE_SECONDS = "OIDF_SSF_RECEIVER_JWKS_CACHE_SECONDS";
    static final String RECEIVER_INSECURE_TLS_SETTING = "OIDF_SSF_RECEIVER_INSECURE_TLS";
    static final String RECEIVER_POLL_URL = "OIDF_SSF_RECEIVER_POLL_URL";
    static final String RECEIVER_POLL_TOKEN = "OIDF_SSF_RECEIVER_POLL_TOKEN";
    static final String RECEIVER_POLL_INTERVAL_SECONDS = "OIDF_SSF_RECEIVER_POLL_INTERVAL_SECONDS";
    static final String RECEIVER_ACTIONS_ENABLED = "OIDF_SSF_RECEIVER_ACTIONS_ENABLED";
    static final String RECEIVER_INSTANCE_REGISTRY = "OIDF_SSF_RECEIVER_INSTANCE_REGISTRY";
    static final String AUDIT_EVENTS_ENABLED = "OIDF_SSF_AUDIT_EVENTS_ENABLED";
    static final String AUDIT_EVENT_MAP = "OIDF_SSF_AUDIT_EVENT_MAP";
    static final String RECEIVER_TOKEN_ENDPOINT = "OIDF_SSF_RECEIVER_TOKEN_ENDPOINT";
    static final String RECEIVER_CLIENT_ID = "OIDF_SSF_RECEIVER_CLIENT_ID";
    static final String RECEIVER_CLIENT_SECRET = "OIDF_SSF_RECEIVER_CLIENT_SECRET";
    static final String RECEIVER_CLIENT_KEY = "OIDF_SSF_RECEIVER_CLIENT_KEY";
    static final String RECEIVER_CLIENT_SCOPE = "OIDF_SSF_RECEIVER_CLIENT_SCOPE";
    static final String RECEIVER_TRANSMITTER_CONFIGURATION_URL = "OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL";
    static final String RECEIVER_PUSH_ENDPOINT_URL = "OIDF_SSF_RECEIVER_PUSH_ENDPOINT_URL";
    static final String RECEIVER_EVENTS_REQUESTED = "OIDF_SSF_RECEIVER_EVENTS_REQUESTED";
    static final String POLL_MAX_EVENTS_CAP = "OIDF_SSF_POLL_MAX_EVENTS_CAP";
    static final String POLL_LONG_POLL_WAIT_SECONDS = "OIDF_SSF_POLL_LONG_POLL_WAIT_SECONDS";
    static final String RECEIVER_SUBJECT_ISSUERS = "OIDF_SSF_RECEIVER_SUBJECT_ISSUERS";
    static final String MAX_STREAMS_PER_CLIENT = "OIDF_SSF_MAX_STREAMS_PER_CLIENT";
    static final String MIN_VERIFICATION_INTERVAL_SECONDS = "OIDF_SSF_MIN_VERIFICATION_INTERVAL_SECONDS";
    static final String INACTIVITY_TIMEOUT_SECONDS = "OIDF_SSF_INACTIVITY_TIMEOUT_SECONDS";

    /** The transmitter's catalogue, {@code META-INF/oidf-settings/ssf-transmitter.json}. */
    public static final String CATALOGUE = "ssf-transmitter";

    /**
     * The transmitter's settings as a servlet reads them: its init-params, this process's system properties and its
     * environment (platform-pf's {@link InitParams}), through the {@value #CATALOGUE} catalogue. A null config has no
     * init-params.
     */
    public static Settings settings(ServletConfig config) {
        return Settings.load(SsfConfiguration.class.getClassLoader(), CATALOGUE).with(InitParams.sources(config));
    }

    /** Whether the settings name an issuer, without which the transmitter is not configured at all. */
    public static boolean issuerSet(Settings settings) {
        return settings.string(ISSUER) != null;
    }

    /**
     * The configuration {@code config}'s settings describe ({@link #settings(ServletConfig)}, {@link #from(Settings)}).
     *
     * @throws SettingRefused for a setting that is missing or wrong, naming it
     */
    public static SsfConfiguration fromServletConfig(ServletConfig config) {
        return from(settings(config));
    }

    /**
     * The configuration these settings describe, each read strictly through its catalogue entry: a switch is
     * {@code true} or {@code false} (the development profile reads a legacy spelling as {@code false}, with a
     * warning), a number is a whole number, a choice is one of its choices in any case (spelt as the catalogue spells
     * it), a URL is an http or https URL with a host. Every refusal names its setting.
     *
     * @throws SettingRefused for {@link #ISSUER} unset, or any setting its entry refuses, or a combination this class
     *                        refuses (Kafka on with no bootstrap servers, the provisioner scope equal to the receiver
     *                        scope, an allowed-audiences entry that is not {@code clientId=aud[,aud]}); a
     *                        {@link com.pingidentity.ps.oidf.platform.settings.ProfileRefused} for a governed value
     *                        from an init-param that the production profile refuses
     */
    public static SsfConfiguration from(Settings s) {
        String issuer = s.string(ISSUER);
        if (issuer == null) {
            throw new SettingRefused(ISSUER, ISSUER + " is not set: the SSF transmitter has no issuer");
        }
        Builder b = new Builder()
                .issuer(issuer)
                .signingAlgorithm(s.choice(SIGNING_ALGORITHM))
                .dataStoreId(s.string(DATA_STORE_ID))
                .storeDialect(s.choice(STORE_DIALECT))
                .jdbcUrl(s.string(JDBC_URL))
                .jdbcUsername(s.string(JDBC_USERNAME))
                .jdbcPassword(reveal(s.secret(JDBC_PASSWORD)))
                .kafkaEnabled(s.bool(KAFKA_ENABLED))
                .kafkaBootstrapServers(s.string(KAFKA_BOOTSTRAP_SERVERS))
                .kafkaTopic(s.string(KAFKA_TOPIC))
                .kafkaSecurityProtocol(s.choice(KAFKA_SECURITY_PROTOCOL))
                .kafkaSaslMechanism(s.string(KAFKA_SASL_MECHANISM))
                .kafkaSaslUsername(s.string(KAFKA_SASL_USERNAME))
                .kafkaSaslPassword(reveal(s.secret(KAFKA_SASL_PASSWORD)))
                .kafkaSslTruststoreLocation(text(s.path(KAFKA_SSL_TRUSTSTORE_LOCATION)))
                .kafkaSslTruststorePassword(reveal(s.secret(KAFKA_SSL_TRUSTSTORE_PASSWORD)))
                .kafkaSslTruststoreType(s.choice(KAFKA_SSL_TRUSTSTORE_TYPE))
                .kafkaSslKeystoreLocation(text(s.path(KAFKA_SSL_KEYSTORE_LOCATION)))
                .kafkaSslKeystorePassword(reveal(s.secret(KAFKA_SSL_KEYSTORE_PASSWORD)))
                .kafkaSslKeystoreType(s.choice(KAFKA_SSL_KEYSTORE_TYPE))
                .kafkaSslKeyPassword(reveal(s.secret(KAFKA_SSL_KEY_PASSWORD)))
                .kafkaSslHostnameVerification(s.bool(KAFKA_SSL_HOSTNAME_VERIFICATION))
                .kafkaRequestTimeoutMs(millis(s.duration(KAFKA_REQUEST_TIMEOUT_MS)))
                .kafkaDeliveryTimeoutMs(millis(s.duration(KAFKA_DELIVERY_TIMEOUT_MS)))
                .kafkaMaxBlockMs(millis(s.duration(KAFKA_MAX_BLOCK_MS)))
                .secretKey(reveal(s.secret(SECRET_KEY)))
                .secretKeyPrevious(reveal(s.secret(SECRET_KEY_PREVIOUS)))
                .pushRetryMaxAttempts(s.integer(PUSH_RETRY_MAX_ATTEMPTS))
                .pushRetryBackoffSeconds(s.integer(PUSH_RETRY_BACKOFF_SECONDS))
                .pollMaxEvents(s.integer(POLL_MAX_EVENTS))
                .setTtlSeconds(s.longValue(SET_TTL_SECONDS))
                .receiverScope(s.string(RECEIVER_SCOPE))
                .unownedStreamOwner(s.string(UNOWNED_STREAM_OWNER))
                .provisionerScope(s.string(PROVISIONER_SCOPE))
                .allowedAudiences(s.string(ALLOWED_AUDIENCES))
                .introspectionEndpoint(text(s.url(INTROSPECTION_ENDPOINT)))
                .introspectionClientId(s.string(INTROSPECTION_CLIENT_ID))
                .introspectionClientSecret(reveal(s.secret(INTROSPECTION_CLIENT_SECRET)))
                .introspectionInsecureTls(s.bool(INTROSPECTION_INSECURE_TLS_SETTING))
                .defaultEventTypes(list(s.words(DEFAULT_EVENT_TYPES_SETTING)))
                .defaultSubjects(s.choice(DEFAULT_SUBJECTS))
                .verificationEventEnabled(s.bool(VERIFICATION_EVENT_ENABLED))
                .receiverExpectedIssuer(s.string(RECEIVER_EXPECTED_ISSUER))
                .receiverJwksUrl(text(s.url(RECEIVER_JWKS_URL)))
                .receiverAudience(s.string(RECEIVER_AUDIENCE))
                .receiverEndpointAuthToken(reveal(s.secret(RECEIVER_ENDPOINT_AUTH_TOKEN)))
                .receiverJwksCacheSeconds(s.longValue(RECEIVER_JWKS_CACHE_SECONDS))
                .receiverInsecureTls(s.bool(RECEIVER_INSECURE_TLS_SETTING))
                .receiverPollUrl(text(s.url(RECEIVER_POLL_URL)))
                .receiverPollToken(reveal(s.secret(RECEIVER_POLL_TOKEN)))
                .receiverPollIntervalSeconds(s.longValue(RECEIVER_POLL_INTERVAL_SECONDS))
                .receiverActionsEnabled(s.bool(RECEIVER_ACTIONS_ENABLED))
                .receiverInstanceRegistry(s.bool(RECEIVER_INSTANCE_REGISTRY))
                .auditEventsEnabled(s.bool(AUDIT_EVENTS_ENABLED))
                .auditEventMap(s.string(AUDIT_EVENT_MAP))
                .receiverTokenEndpoint(text(s.url(RECEIVER_TOKEN_ENDPOINT)))
                .receiverClientId(s.string(RECEIVER_CLIENT_ID))
                .receiverClientSecret(reveal(s.secret(RECEIVER_CLIENT_SECRET)))
                .receiverClientKey(reveal(s.secret(RECEIVER_CLIENT_KEY)))
                .receiverClientScope(s.string(RECEIVER_CLIENT_SCOPE))
                .receiverTransmitterConfigurationUrl(text(s.url(RECEIVER_TRANSMITTER_CONFIGURATION_URL)))
                .receiverPushEndpointUrl(text(s.url(RECEIVER_PUSH_ENDPOINT_URL)))
                .receiverEventsRequested(list(s.words(RECEIVER_EVENTS_REQUESTED)))
                .pollMaxEventsCap(s.integer(POLL_MAX_EVENTS_CAP))
                .pollLongPollWaitSeconds(s.integer(POLL_LONG_POLL_WAIT_SECONDS))
                .receiverSubjectIssuers(list(s.words(RECEIVER_SUBJECT_ISSUERS)))
                .maxStreamsPerClient(s.integer(MAX_STREAMS_PER_CLIENT))
                .minVerificationIntervalSeconds(s.integer(MIN_VERIFICATION_INTERVAL_SECONDS))
                .inactivityTimeoutSeconds(s.longValue(INACTIVITY_TIMEOUT_SECONDS));
        try {
            return b.build();
        } catch (Refused e) {
            throw new SettingRefused(e.setting, e.getMessage());
        }
    }

    /**
     * A combination of settings the constructor refuses, naming the setting to change. An
     * {@link IllegalArgumentException}, as the {@link Builder}'s refusals always were; {@link #from} turns it into the
     * {@link SettingRefused} every other refusal is.
     */
    static final class Refused extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        private final String setting;

        Refused(String setting, String message) {
            super(message);
            this.setting = setting;
        }
    }

    private static String reveal(Secret secret) {
        return secret == null ? null : secret.reveal();
    }

    private static String text(URI uri) {
        return uri == null ? null : uri.toString();
    }

    private static String text(java.nio.file.Path path) {
        return path == null ? null : path.toString();
    }

    private static Integer millis(java.time.Duration d) {
        return d == null ? null : (int) d.toMillis();
    }

    /** Each key 32 bytes of base64, and the previous key only with a current one; a refusal names the setting. */
    private static void checkSecretKeys(String current, String previous) {
        try {
            if (current != null) {
                PushHeaderCipher.key(SECRET_KEY, current);
            }
            if (previous != null) {
                PushHeaderCipher.key(SECRET_KEY_PREVIOUS, previous);
                if (current == null) {
                    throw new IllegalArgumentException(SECRET_KEY_PREVIOUS + " is set without " + SECRET_KEY
                            + ": the previous key only opens values while a current key seals new ones");
                }
            }
        } catch (IllegalArgumentException e) {
            throw new Refused(e.getMessage().startsWith(SECRET_KEY_PREVIOUS) ? SECRET_KEY_PREVIOUS : SECRET_KEY, e.getMessage());
        }
    }

    private static List<String> list(Set<String> words) {
        return words == null ? null : List.copyOf(words);
    }

    public String issuer() {
        return this.issuer;
    }

    public String signingAlgorithm() {
        return this.signingAlgorithm;
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

    /** {@code ssl.truststore.location}: the file of the CAs that sign the brokers' certificates; null for the JVM's. */
    public String kafkaSslTruststoreLocation() {
        return this.kafkaSslTruststoreLocation;
    }

    public String kafkaSslTruststorePassword() {
        return this.kafkaSslTruststorePassword;
    }

    /** {@code ssl.truststore.type}: JKS, PKCS12 or PEM; null for Kafka's default. */
    public String kafkaSslTruststoreType() {
        return this.kafkaSslTruststoreType;
    }

    /** {@code ssl.keystore.location}: the client certificate and key for mutual TLS; null for none. */
    public String kafkaSslKeystoreLocation() {
        return this.kafkaSslKeystoreLocation;
    }

    public String kafkaSslKeystorePassword() {
        return this.kafkaSslKeystorePassword;
    }

    public String kafkaSslKeystoreType() {
        return this.kafkaSslKeystoreType;
    }

    public String kafkaSslKeyPassword() {
        return this.kafkaSslKeyPassword;
    }

    /** Whether the broker's certificate is checked against its host name ({@code ssl.endpoint.identification.algorithm=https}). */
    public boolean kafkaSslHostnameVerification() {
        return this.kafkaSslHostnameVerification;
    }

    public int kafkaRequestTimeoutMs() {
        return this.kafkaRequestTimeoutMs;
    }

    public int kafkaDeliveryTimeoutMs() {
        return this.kafkaDeliveryTimeoutMs;
    }

    public int kafkaMaxBlockMs() {
        return this.kafkaMaxBlockMs;
    }

    /** {@value #SECRET_KEY}, as set (the cipher is {@link #pushHeaderCipher}). */
    String secretKey() {
        return this.secretKey;
    }

    /** {@value #SECRET_KEY_PREVIOUS}, as set. */
    String secretKeyPrevious() {
        return this.secretKeyPrevious;
    }

    /**
     * The cipher that seals a push stream's {@code authorization_header} at rest ({@value #SECRET_KEY}, and
     * {@value #SECRET_KEY_PREVIOUS} during a rotation), for a store under the production profile or not.
     */
    public PushHeaderCipher pushHeaderCipher(boolean production) {
        return PushHeaderCipher.of(this.secretKey, this.secretKeyPrevious, production);
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

    /**
     * The one client admitted to streams that record no owner - those created before streams had owners
     * ({@code OIDF_SSF_UNOWNED_STREAM_OWNER}). Unset, which is the default, nobody is: such a stream answers
     * every receiver as though it did not exist, because the transmitter never recorded whose it was and
     * every guess open to it - the {@code aud} its creator chose, or whoever asks first - is one a second
     * receiver can make as well.
     *
     * <p>A client id rather than a switch. A switch could only put these streams back where any holder of
     * the receiver scope reads, repoints, polls and deletes them, which is the fault ownership closes; a
     * name admits one client the operator chose. Nothing is written to the stream, so unsetting this
     * withdraws it. Where unowned streams belong to several receivers, name none of them: have each
     * create its stream again, or set the owner in the store.
     */
    public String unownedStreamOwner() {
        return this.unownedStreamOwner;
    }

    /**
     * The scope that makes a client a provisioner, admitted to {@code /ssf/scim/v2/Users}
     * ({@code OIDF_SSF_PROVISIONER_SCOPE}, e.g. {@code ssf.provision}). Unset, which is the default, nobody
     * is and the endpoint refuses every caller. It is never the receiver scope: a deprovision has the
     * transmitter sign an account-disabled about a subject of the caller's choosing, and a receiver that
     * could ask for that could take the JWS to any other receiver of this transmitter. A provisioner acts
     * across every receiver's streams, so grant the scope to the provisioning client and to nothing else.
     */
    public String provisionerScope() {
        return this.provisionerScope;
    }

    /**
     * The {@code aud} values a client may name when it creates a stream, other than its own client id
     * ({@code OIDF_SSF_ALLOWED_AUDIENCES}, {@code clientA=aud1,aud2;clientB=aud3}). SSF 1.0 §8.1.1 makes
     * {@code aud} Transmitter-Supplied, and lets the two sides "agree upon the audience value out of band":
     * this is where the operator records that agreement. Empty for a client named nowhere.
     */
    public Set<String> allowedAudiences(String clientId) {
        return this.allowedAudiences.getOrDefault(clientId, Set.of());
    }

    /**
     * The settings an enabled receiver is missing and may not run without: {@code receiverAudience} and
     * {@code receiverEndpointAuthToken}. A signature and an {@code iss} say the transmitter signed a SET,
     * not that it signed it for this receiver or that the transmitter is who delivered it - and a SET acted
     * on here revokes a user's grants. Empty when the receiver is off, or is on and has both.
     */
    public List<String> receiverMissingRequirements() {
        ArrayList<String> missing = new ArrayList<>();
        if (receiverConfigured()) {
            if (this.receiverAudience == null) {
                missing.add("receiverAudience");
            }
            if (this.receiverEndpointAuthToken == null) {
                missing.add("receiverEndpointAuthToken");
            }
        }
        return missing;
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

    /**
     * Which subjects a stream hears about before any are added to it: {@code NONE}, the default, or
     * {@code ALL} ({@code OIDF_SSF_DEFAULT_SUBJECTS}). This is the transmitter's {@code default_subjects}
     * (SSF 1.0 §7.1.1) and is advertised as such. With {@code ALL}, every enabled stream that delivers an
     * event's type receives it whether or not the subject was ever added - which is the model the CAEP
     * Interop Profile requires (§2.4.4: a receiver "MUST assume that all subjects are implicitly included
     * in a Stream, without any Add Subject method invocations"). It says nothing about whose streams they
     * are: ownership decides who manages and drains a stream, this decides what it hears.
     */
    public String defaultSubjects() {
        return this.defaultSubjects;
    }

    public boolean defaultSubjectsAll() {
        return DEFAULT_SUBJECTS_ALL.equals(this.defaultSubjects);
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

    /** Expected {@code aud} of inbound SETs. Required when the receiver is on ({@link #receiverMissingRequirements}). */
    public String receiverAudience() {
        return this.receiverAudience;
    }

    /** Bearer token the transmitter must present when POSTing to our push endpoint. Required when the receiver is on. */
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

    /**
     * Whether inbound CAEP signals ({@code device-compliance-change}, {@code session-revoked},
     * {@code credential-change}) act on the agent instance registry. Default false — opt-in because it
     * additionally requires {@code storeDialect=ldm} (the registry lives in the same Identity Object
     * Model database as the {@code ldm} SSF store; on any other dialect this is refused at configure
     * time with a warning, not silently skipped).
     */
    public boolean receiverInstanceRegistry() {
        return this.receiverInstanceRegistry;
    }

    // ---- the receiver's client and managed stream, the poll endpoint's cap and wait (H-SSF-1, H-SSF-2) ----

    /** The transmitter's token endpoint for the receiver's client credentials; null for none (development's static token). */
    public String receiverTokenEndpoint() {
        return this.receiverTokenEndpoint;
    }

    public String receiverClientId() {
        return this.receiverClientId;
    }

    /** The client's secret ({@code client_secret_basic}); null when it has a key instead. */
    public String receiverClientSecret() {
        return this.receiverClientSecret;
    }

    /** The client's private JWK ({@code private_key_jwt}); null when it has a secret instead. */
    public String receiverClientKey() {
        return this.receiverClientKey;
    }

    public String receiverClientScope() {
        return this.receiverClientScope;
    }

    /** The transmitter's configuration metadata URL; set, the receiver manages its own stream there. */
    public String receiverTransmitterConfigurationUrl() {
        return this.receiverTransmitterConfigurationUrl;
    }

    /** Where the managed stream pushes (this receiver's public endpoint); null for a poll stream. */
    public String receiverPushEndpointUrl() {
        return this.receiverPushEndpointUrl;
    }

    /** The events the managed stream asks for. */
    public List<String> receiverEventsRequested() {
        return this.receiverEventsRequested;
    }

    /** The most SETs one poll answer carries (1-1000). */
    public int pollMaxEventsCap() {
        return this.pollMaxEventsCap;
    }

    /** How long a long poll is held with nothing to return, in seconds (0-30); 0 answers at once. */
    public int pollLongPollWaitSeconds() {
        return this.pollLongPollWaitSeconds;
    }

    /** The most streams one receiver client may have at once (1-1000); one more is refused (plan item H-SSF-3). */
    public int maxStreamsPerClient() {
        return this.maxStreamsPerClient;
    }

    /**
     * The {@code min_verification_interval} a new stream is given, in seconds (0-86400); 0 gives it none (SSF 1.0
     * §8.1.1, plan item H-SSF-3).
     */
    public int minVerificationIntervalSeconds() {
        return this.minVerificationIntervalSeconds;
    }

    /**
     * The {@code inactivity_timeout} a new stream is given, in seconds (0-31536000); 0 gives it none. Recorded and
     * reported, not acted on (SSF 1.0 §8.1.1, plan item H-SSF-3; pausing an inactive stream is S-10's).
     */
    public long inactivityTimeoutSeconds() {
        return this.inactivityTimeoutSeconds;
    }

    /**
     * The issuers whose {@code iss_sub} subjects name a user here, besides the SET's own: this PingFederate's SSF
     * issuer and {@code OIDF_SSF_RECEIVER_SUBJECT_ISSUERS}.
     */
    public Set<String> receiverLocalIssuers() {
        Set<String> out = new LinkedHashSet<>(this.receiverSubjectIssuers);
        out.add(this.issuer);
        return out;
    }

    // ---- endpoint URLs advertised in ssf-configuration: the issuer and the servlets' paths (SsfPaths) ----

    public String configurationEndpoint() {
        return this.issuer + SsfPaths.STREAMS;
    }

    public String statusEndpoint() {
        return this.issuer + SsfPaths.STATUS;
    }

    public String addSubjectEndpoint() {
        return this.issuer + SsfPaths.SUBJECTS_ADD;
    }

    public String removeSubjectEndpoint() {
        return this.issuer + SsfPaths.SUBJECTS_REMOVE;
    }

    public String verificationEndpoint() {
        return this.issuer + SsfPaths.VERIFY;
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

    private static Map<String, Set<String>> parseAllowedAudiences(String value) {
        LinkedHashMap<String, Set<String>> byClient = new LinkedHashMap<>();
        if (value == null || value.isBlank()) {
            return byClient;
        }
        for (String entry : value.split(";")) {
            if (entry.isBlank()) {
                continue;
            }
            int eq = entry.indexOf('=');
            if (eq < 0 || entry.substring(0, eq).isBlank()) {
                throw new Refused(ALLOWED_AUDIENCES, ALLOWED_AUDIENCES + " entry '" + entry.trim() + "' is not clientId=aud[,aud]");
            }
            byClient.computeIfAbsent(entry.substring(0, eq).trim(), k -> new LinkedHashSet<>())
                    .addAll(parseCommaSeparated(entry.substring(eq + 1)));
        }
        return byClient;
    }

    private static String trimOrNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    /** Exactly {@code ALL} or {@code NONE}, as SSF 1.0 §7.1.1 spells them; unset is {@code NONE}. */
    static String parseDefaultSubjects(String value) {
        if (value == null || value.isBlank()) {
            return DEFAULT_SUBJECTS_NONE;
        }
        String trimmed = value.trim();
        if (!DEFAULT_SUBJECTS_ALL.equals(trimmed) && !DEFAULT_SUBJECTS_NONE.equals(trimmed)) {
            throw new IllegalArgumentException("defaultSubjects must be ALL or NONE, got: " + trimmed);
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

    /** Mutable builder; every setter tolerates null and falls back to the documented default at {@link #build()}. */
    public static final class Builder {
        private String issuer;
        private String signingAlgorithm = DEFAULT_SIGNING_ALGORITHM;
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
        private String kafkaSslTruststoreLocation;
        private String kafkaSslTruststorePassword;
        private String kafkaSslTruststoreType;
        private String kafkaSslKeystoreLocation;
        private String kafkaSslKeystorePassword;
        private String kafkaSslKeystoreType;
        private String kafkaSslKeyPassword;
        private boolean kafkaSslHostnameVerification = true;
        private int kafkaRequestTimeoutMs = DEFAULT_KAFKA_REQUEST_TIMEOUT_MS;
        private int kafkaDeliveryTimeoutMs = DEFAULT_KAFKA_DELIVERY_TIMEOUT_MS;
        private int kafkaMaxBlockMs = DEFAULT_KAFKA_MAX_BLOCK_MS;
        private String secretKey;
        private String secretKeyPrevious;
        private int pushRetryMaxAttempts = DEFAULT_PUSH_RETRY_MAX_ATTEMPTS;
        private int pushRetryBackoffSeconds = DEFAULT_PUSH_RETRY_BACKOFF_SECONDS;
        private int pollMaxEvents = DEFAULT_POLL_MAX_EVENTS;
        private long setTtlSeconds = DEFAULT_SET_TTL_SECONDS;
        private String receiverScope = DEFAULT_RECEIVER_SCOPE;
        private String unownedStreamOwner;
        private String provisionerScope;
        private String allowedAudiences;
        private String introspectionEndpoint;
        private String introspectionClientId;
        private String introspectionClientSecret;
        private boolean introspectionInsecureTls;
        private List<String> defaultEventTypes;
        private String defaultSubjects;
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
        private boolean receiverInstanceRegistry;
        private boolean auditEventsEnabled = true;
        private String auditEventMap;
        private String receiverTokenEndpoint;
        private String receiverClientId;
        private String receiverClientSecret;
        private String receiverClientKey;
        private String receiverClientScope;
        private String receiverTransmitterConfigurationUrl;
        private String receiverPushEndpointUrl;
        private List<String> receiverEventsRequested;
        private int pollMaxEventsCap = DEFAULT_POLL_MAX_EVENTS_CAP;
        private int pollLongPollWaitSeconds = DEFAULT_POLL_LONG_POLL_WAIT_SECONDS;
        private List<String> receiverSubjectIssuers;
        private int maxStreamsPerClient = DEFAULT_MAX_STREAMS_PER_CLIENT;
        private int minVerificationIntervalSeconds = DEFAULT_MIN_VERIFICATION_INTERVAL_SECONDS;
        private long inactivityTimeoutSeconds;

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

        public Builder kafkaSslTruststoreLocation(String v) {
            this.kafkaSslTruststoreLocation = v;
            return this;
        }

        public Builder kafkaSslTruststorePassword(String v) {
            this.kafkaSslTruststorePassword = v;
            return this;
        }

        public Builder kafkaSslTruststoreType(String v) {
            this.kafkaSslTruststoreType = v;
            return this;
        }

        public Builder kafkaSslKeystoreLocation(String v) {
            this.kafkaSslKeystoreLocation = v;
            return this;
        }

        public Builder kafkaSslKeystorePassword(String v) {
            this.kafkaSslKeystorePassword = v;
            return this;
        }

        public Builder kafkaSslKeystoreType(String v) {
            this.kafkaSslKeystoreType = v;
            return this;
        }

        public Builder kafkaSslKeyPassword(String v) {
            this.kafkaSslKeyPassword = v;
            return this;
        }

        public Builder kafkaSslHostnameVerification(boolean v) {
            this.kafkaSslHostnameVerification = v;
            return this;
        }

        public Builder kafkaRequestTimeoutMs(Integer v) {
            if (v != null) {
                this.kafkaRequestTimeoutMs = v;
            }
            return this;
        }

        public Builder kafkaDeliveryTimeoutMs(Integer v) {
            if (v != null) {
                this.kafkaDeliveryTimeoutMs = v;
            }
            return this;
        }

        public Builder kafkaMaxBlockMs(Integer v) {
            if (v != null) {
                this.kafkaMaxBlockMs = v;
            }
            return this;
        }

        /** {@value SsfConfiguration#SECRET_KEY}: 32 bytes, base64. */
        public Builder secretKey(String v) {
            this.secretKey = v;
            return this;
        }

        public Builder secretKeyPrevious(String v) {
            this.secretKeyPrevious = v;
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

        public Builder unownedStreamOwner(String v) {
            this.unownedStreamOwner = v;
            return this;
        }

        public Builder provisionerScope(String v) {
            this.provisionerScope = v;
            return this;
        }

        /** {@code clientA=aud1,aud2;clientB=aud3} - see {@link SsfConfiguration#allowedAudiences(String)}. */
        public Builder allowedAudiences(String v) {
            this.allowedAudiences = v;
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

        /** {@code ALL} or {@code NONE} - see {@link SsfConfiguration#defaultSubjects()}. */
        public Builder defaultSubjects(String v) {
            this.defaultSubjects = v;
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

        public Builder receiverInstanceRegistry(boolean v) {
            this.receiverInstanceRegistry = v;
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

        public Builder receiverTokenEndpoint(String v) {
            this.receiverTokenEndpoint = v;
            return this;
        }

        public Builder receiverClientId(String v) {
            this.receiverClientId = v;
            return this;
        }

        public Builder receiverClientSecret(String v) {
            this.receiverClientSecret = v;
            return this;
        }

        public Builder receiverClientKey(String v) {
            this.receiverClientKey = v;
            return this;
        }

        public Builder receiverClientScope(String v) {
            this.receiverClientScope = v;
            return this;
        }

        public Builder receiverTransmitterConfigurationUrl(String v) {
            this.receiverTransmitterConfigurationUrl = v;
            return this;
        }

        public Builder receiverPushEndpointUrl(String v) {
            this.receiverPushEndpointUrl = v;
            return this;
        }

        public Builder receiverEventsRequested(List<String> v) {
            this.receiverEventsRequested = v;
            return this;
        }

        public Builder pollMaxEventsCap(int v) {
            this.pollMaxEventsCap = v;
            return this;
        }

        public Builder pollLongPollWaitSeconds(int v) {
            this.pollLongPollWaitSeconds = v;
            return this;
        }

        public Builder receiverSubjectIssuers(List<String> v) {
            this.receiverSubjectIssuers = v;
            return this;
        }

        public Builder maxStreamsPerClient(int v) {
            this.maxStreamsPerClient = v;
            return this;
        }

        public Builder minVerificationIntervalSeconds(int v) {
            this.minVerificationIntervalSeconds = v;
            return this;
        }

        public Builder inactivityTimeoutSeconds(long v) {
            this.inactivityTimeoutSeconds = v;
            return this;
        }

        public SsfConfiguration build() {
            return new SsfConfiguration(this);
        }
    }
}
