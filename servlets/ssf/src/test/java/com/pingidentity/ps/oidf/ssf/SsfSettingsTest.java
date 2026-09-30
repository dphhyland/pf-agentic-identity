/*
 * Every SSF transmitter setting through its three sources, strictly, and each refusal naming its setting.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.ps.oidf.platform.settings.Setting;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.SettingType;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Source;
import com.pingidentity.ps.oidf.platform.settings.SourceName;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Plan item ST-5 for servlets/ssf: {@link SsfConfiguration} reads every setting through the {@code ssf-transmitter}
 * catalogue. Before 0.6.0 {@code SsfConfiguration.param} read each from the init-param, then the system property
 * {@code oidf.ssf.<init-param>}, then {@code OIDF_SSF_<UPPER_SNAKE>}; the catalogue now names all three (F-0235), so
 * nothing that was read stops being read, in the same order.
 */
class SsfSettingsTest {

    private static final Catalogue CATALOGUE = Catalogue.load(SsfSettingsTest.class.getClassLoader(), SsfConfiguration.CATALOGUE);

    /** A value for each setting, and what the configuration reads it as. */
    private record Case(String value, Function<SsfConfiguration, Object> read, Object expected) {
    }

    /** Two push-header keys, 32 bytes each. */
    static final String KEY_A = java.util.Base64.getEncoder().encodeToString(new byte[32]);
    static final String KEY_B = java.util.Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes(
            java.nio.charset.StandardCharsets.US_ASCII));

    private static final Map<String, Case> CASES = new LinkedHashMap<>();

    /** A private JWK for the receiver's client key. */
    static final String CLIENT_JWK = newClientJwk();

    private static String newClientJwk() {
        try {
            org.jose4j.jwk.RsaJsonWebKey k = org.jose4j.jwk.RsaJwkGenerator.generateJwk(2048);
            return k.toJson(org.jose4j.jwk.JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        } catch (org.jose4j.lang.JoseException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void add(String name, String value, Function<SsfConfiguration, Object> read, Object expected) {
        CASES.put(name, new Case(value, read, expected));
    }

    static {
        add("OIDF_SSF_ISSUER", "https://iss.example.com/", SsfConfiguration::issuer, "https://iss.example.com");
        add("OIDF_SSF_SIGNING_ALGORITHM", "PS256", SsfConfiguration::signingAlgorithm, "PS256");
        add("OIDF_SSF_DATA_STORE_ID", "pf-ds", SsfConfiguration::dataStoreId, "pf-ds");
        add("OIDF_SSF_STORE_DIALECT", "ldm", SsfConfiguration::storeDialect, "ldm");
        add("OIDF_SSF_JDBC_URL", "jdbc:postgresql://db/ssf", SsfConfiguration::jdbcUrl, "jdbc:postgresql://db/ssf");
        add("OIDF_SSF_JDBC_USERNAME", "ssf", SsfConfiguration::jdbcUsername, "ssf");
        add("OIDF_SSF_JDBC_PASSWORD", "pw", SsfConfiguration::jdbcPassword, "pw");
        add("OIDF_SSF_KAFKA_ENABLED", "true", SsfConfiguration::kafkaEnabled, true);
        add("OIDF_SSF_KAFKA_BOOTSTRAP_SERVERS", "kafka:9092", SsfConfiguration::kafkaBootstrapServers, "kafka:9092");
        add("OIDF_SSF_KAFKA_TOPIC", "t", SsfConfiguration::kafkaTopic, "t");
        add("OIDF_SSF_KAFKA_SECURITY_PROTOCOL", "SSL", SsfConfiguration::kafkaSecurityProtocol, "SSL");
        add("OIDF_SSF_KAFKA_SASL_MECHANISM", "PLAIN", SsfConfiguration::kafkaSaslMechanism, "PLAIN");
        add("OIDF_SSF_KAFKA_SASL_USERNAME", "u", SsfConfiguration::kafkaSaslUsername, "u");
        add("OIDF_SSF_KAFKA_SASL_PASSWORD", "p", SsfConfiguration::kafkaSaslPassword, "p");
        add("OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS", "7", SsfConfiguration::pushRetryMaxAttempts, 7);
        add("OIDF_SSF_PUSH_RETRY_BACKOFF_SECONDS", "3", SsfConfiguration::pushRetryBackoffSeconds, 3);
        add("OIDF_SSF_POLL_MAX_EVENTS", "50", SsfConfiguration::pollMaxEvents, 50);
        add("OIDF_SSF_SET_TTL_SECONDS", "60", SsfConfiguration::setTtlSeconds, 60L);
        add("OIDF_SSF_RECEIVER_SCOPE", "ssf.receive", SsfConfiguration::receiverScope, "ssf.receive");
        add("OIDF_SSF_UNOWNED_STREAM_OWNER", "legacy", SsfConfiguration::unownedStreamOwner, "legacy");
        add("OIDF_SSF_PROVISIONER_SCOPE", "ssf.provision", SsfConfiguration::provisionerScope, "ssf.provision");
        add("OIDF_SSF_ALLOWED_AUDIENCES", "rx=https://a.example.com", c -> c.allowedAudiences("rx"), Set.of("https://a.example.com"));
        add("OIDF_SSF_INTROSPECTION_ENDPOINT", "https://pf.example.com/as/introspect.oauth2", SsfConfiguration::introspectionEndpoint,
                "https://pf.example.com/as/introspect.oauth2");
        add("OIDF_SSF_INTROSPECTION_CLIENT_ID", "c", SsfConfiguration::introspectionClientId, "c");
        add("OIDF_SSF_INTROSPECTION_CLIENT_SECRET", "s", SsfConfiguration::introspectionClientSecret, "s");
        add("OIDF_SSF_INTROSPECTION_INSECURE_TLS", "true", SsfConfiguration::introspectionInsecureTls, true);
        add("OIDF_SSF_DEFAULT_EVENT_TYPES", "urn:a, urn:b", SsfConfiguration::defaultEventTypes, List.of("urn:a", "urn:b"));
        add("OIDF_SSF_DEFAULT_SUBJECTS", "ALL", SsfConfiguration::defaultSubjects, "ALL");
        add("OIDF_SSF_VERIFICATION_EVENT_ENABLED", "false", SsfConfiguration::verificationEventEnabled, false);
        add("OIDF_SSF_RECEIVER_EXPECTED_ISSUER", "https://tx.example.com", SsfConfiguration::receiverExpectedIssuer, "https://tx.example.com");
        add("OIDF_SSF_RECEIVER_JWKS_URL", "https://tx.example.com/jwks", SsfConfiguration::receiverJwksUrl, "https://tx.example.com/jwks");
        add("OIDF_SSF_RECEIVER_AUDIENCE", "aud", SsfConfiguration::receiverAudience, "aud");
        add("OIDF_SSF_RECEIVER_ENDPOINT_AUTH_TOKEN", "tok", SsfConfiguration::receiverEndpointAuthToken, "tok");
        add("OIDF_SSF_RECEIVER_JWKS_CACHE_SECONDS", "30", SsfConfiguration::receiverJwksCacheSeconds, 30L);
        add("OIDF_SSF_RECEIVER_INSECURE_TLS", "true", SsfConfiguration::receiverInsecureTls, true);
        add("OIDF_SSF_RECEIVER_POLL_URL", "https://tx.example.com/poll", SsfConfiguration::receiverPollUrl, "https://tx.example.com/poll");
        add("OIDF_SSF_RECEIVER_POLL_TOKEN", "pt", SsfConfiguration::receiverPollToken, "pt");
        add("OIDF_SSF_RECEIVER_POLL_INTERVAL_SECONDS", "5", SsfConfiguration::receiverPollIntervalSeconds, 5L);
        add("OIDF_SSF_RECEIVER_ACTIONS_ENABLED", "false", SsfConfiguration::receiverActionsEnabled, false);
        add("OIDF_SSF_RECEIVER_INSTANCE_REGISTRY", "true", SsfConfiguration::receiverInstanceRegistry, true);
        add("OIDF_SSF_AUDIT_EVENTS_ENABLED", "false", SsfConfiguration::auditEventsEnabled, false);
        add("OIDF_SSF_AUDIT_EVENT_MAP", "LOGOUT=session-revoked", SsfConfiguration::auditEventMap, "LOGOUT=session-revoked");
        add("OIDF_SSF_RECEIVER_TOKEN_ENDPOINT", "https://as.example.com/token", SsfConfiguration::receiverTokenEndpoint,
                "https://as.example.com/token");
        add("OIDF_SSF_RECEIVER_CLIENT_ID", "rx", SsfConfiguration::receiverClientId, "rx");
        add("OIDF_SSF_RECEIVER_CLIENT_SECRET", "cs", SsfConfiguration::receiverClientSecret, "cs");
        add("OIDF_SSF_RECEIVER_CLIENT_KEY", CLIENT_JWK, SsfConfiguration::receiverClientKey, CLIENT_JWK);
        add("OIDF_SSF_RECEIVER_CLIENT_SCOPE", "ssf.manage", SsfConfiguration::receiverClientScope, "ssf.manage");
        add("OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL", "https://tx.example.com/.well-known/ssf-configuration",
                SsfConfiguration::receiverTransmitterConfigurationUrl, "https://tx.example.com/.well-known/ssf-configuration");
        add("OIDF_SSF_RECEIVER_PUSH_ENDPOINT_URL", "https://me.example.com/ssf/receiver/events",
                SsfConfiguration::receiverPushEndpointUrl, "https://me.example.com/ssf/receiver/events");
        add("OIDF_SSF_RECEIVER_EVENTS_REQUESTED", "urn:a,urn:b", SsfConfiguration::receiverEventsRequested, List.of("urn:a", "urn:b"));
        add("OIDF_SSF_POLL_MAX_EVENTS_CAP", "500", SsfConfiguration::pollMaxEventsCap, 500);
        add("OIDF_SSF_POLL_LONG_POLL_WAIT_SECONDS", "0", SsfConfiguration::pollLongPollWaitSeconds, 0);
        add("OIDF_SSF_RECEIVER_SUBJECT_ISSUERS", "https://idp.example.com", c -> c.receiverLocalIssuers(),
                Set.of("https://idp.example.com", "https://op.example.com"));
        add("OIDF_SSF_MAX_STREAMS_PER_CLIENT", "3", SsfConfiguration::maxStreamsPerClient, 3);
        add("OIDF_SSF_MIN_VERIFICATION_INTERVAL_SECONDS", "0", SsfConfiguration::minVerificationIntervalSeconds, 0);
        add("OIDF_SSF_INACTIVITY_TIMEOUT_SECONDS", "3600", SsfConfiguration::inactivityTimeoutSeconds, 3600L);
        // HSSF3: Kafka's TLS and timeouts, and the push-header keys.
        add("OIDF_SSF_KAFKA_SSL_TRUSTSTORE_LOCATION", "/opt/kafka/trust.p12", SsfConfiguration::kafkaSslTruststoreLocation,
                "/opt/kafka/trust.p12");
        add("OIDF_SSF_KAFKA_SSL_TRUSTSTORE_PASSWORD", "tp", SsfConfiguration::kafkaSslTruststorePassword, "tp");
        add("OIDF_SSF_KAFKA_SSL_TRUSTSTORE_TYPE", "pkcs12", SsfConfiguration::kafkaSslTruststoreType, "PKCS12");
        add("OIDF_SSF_KAFKA_SSL_KEYSTORE_LOCATION", "/opt/kafka/client.p12", SsfConfiguration::kafkaSslKeystoreLocation,
                "/opt/kafka/client.p12");
        add("OIDF_SSF_KAFKA_SSL_KEYSTORE_PASSWORD", "kp", SsfConfiguration::kafkaSslKeystorePassword, "kp");
        add("OIDF_SSF_KAFKA_SSL_KEYSTORE_TYPE", "PEM", SsfConfiguration::kafkaSslKeystoreType, "PEM");
        add("OIDF_SSF_KAFKA_SSL_KEY_PASSWORD", "kk", SsfConfiguration::kafkaSslKeyPassword, "kk");
        add("OIDF_SSF_KAFKA_SSL_HOSTNAME_VERIFICATION", "false", SsfConfiguration::kafkaSslHostnameVerification, false);
        add("OIDF_SSF_KAFKA_REQUEST_TIMEOUT_MS", "5000", SsfConfiguration::kafkaRequestTimeoutMs, 5000);
        add("OIDF_SSF_KAFKA_DELIVERY_TIMEOUT_MS", "60000", SsfConfiguration::kafkaDeliveryTimeoutMs, 60000);
        add("OIDF_SSF_KAFKA_MAX_BLOCK_MS", "500", SsfConfiguration::kafkaMaxBlockMs, 500);
        add("OIDF_SSF_SECRET_KEY", KEY_A, SsfConfiguration::secretKey, KEY_A);
        add("OIDF_SSF_SECRET_KEY_PREVIOUS", KEY_B, SsfConfiguration::secretKeyPrevious, KEY_B);
    }



    /** The seven switches, strict since 0.6.0 (finding F-0237). */
    private static final List<String> SWITCHES = List.of("OIDF_SSF_KAFKA_ENABLED", "OIDF_SSF_INTROSPECTION_INSECURE_TLS",
            "OIDF_SSF_VERIFICATION_EVENT_ENABLED", "OIDF_SSF_RECEIVER_INSECURE_TLS", "OIDF_SSF_RECEIVER_ACTIONS_ENABLED",
            "OIDF_SSF_RECEIVER_INSTANCE_REGISTRY", "OIDF_SSF_AUDIT_EVENTS_ENABLED");

    private static final String DEVELOPMENT = "development";

    /** The configuration read from these three maps. */
    private static SsfConfiguration read(Map<String, String> env, Map<String, String> props, Map<String, String> init) {
        return SsfConfiguration.from(Settings.of(CATALOGUE, Sources.of(env::get, props::get, init::get)));
    }

    /** The settings every read needs besides the one under test: an issuer, and the servers Kafka on needs. */
    private static Map<String, String> base(String under) {
        Map<String, String> env = new HashMap<>();
        if (!under.equals("OIDF_SSF_ISSUER")) {
            env.put("OIDF_SSF_ISSUER", "https://op.example.com");
        }
        // The receiver's client and managed stream settings come in sets (SsfConfiguration.refuseReceiverCombinations).
        if (Set.of("OIDF_SSF_RECEIVER_TOKEN_ENDPOINT", "OIDF_SSF_RECEIVER_CLIENT_ID", "OIDF_SSF_RECEIVER_CLIENT_SECRET",
                "OIDF_SSF_RECEIVER_CLIENT_KEY").contains(under)) {
            env.put("OIDF_SSF_RECEIVER_TOKEN_ENDPOINT", "https://as.example.com/token");
            env.put("OIDF_SSF_RECEIVER_CLIENT_ID", "rx");
            if (!under.equals("OIDF_SSF_RECEIVER_CLIENT_KEY")) {
                env.put("OIDF_SSF_RECEIVER_CLIENT_SECRET", "cs");
            }
            env.remove(under);
        }
        if (Set.of("OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL", "OIDF_SSF_RECEIVER_PUSH_ENDPOINT_URL").contains(under)) {
            env.put("OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL", "https://tx.example.com/.well-known/ssf-configuration");
            env.put("OIDF_SSF_RECEIVER_POLL_TOKEN", "pt");
            env.remove(under);
        }
        if (under.equals("OIDF_SSF_SECRET_KEY_PREVIOUS")) {
            env.put("OIDF_SSF_SECRET_KEY", KEY_A); // the previous key only with a current one
        }
        if (!under.equals("OIDF_SSF_KAFKA_BOOTSTRAP_SERVERS")) {
            env.put("OIDF_SSF_KAFKA_BOOTSTRAP_SERVERS", "kafka:9092");
        }
        return env;
    }

    private static String source(Setting setting, Source source) {
        return setting.sources().stream().filter(s -> s.source() == source).map(SourceName::name).findFirst().orElseThrow();
    }

    @Test
    void everyEntryHasACase() {
        Set<String> entries = new TreeSet<>();
        for (Setting s : CATALOGUE.settings()) {
            entries.add(s.name());
        }
        assertEquals(entries, new TreeSet<>(CASES.keySet()));
        assertEquals(69, entries.size());
    }

    /**
     * The names SsfConfiguration.param read, in its order: the init-param, {@code oidf.ssf.<init-param>}, then
     * {@code OIDF_SSF_} and the init-param in upper snake case. Every one is an entry's source, so the settings scan
     * matches each (F-0235: the 42 camelCase system properties are catalogued under their real names).
     */
    @Test
    void everyEntryIsReadFromTheNamesParamRead() {
        for (Setting s : CATALOGUE.settings()) {
            String init = source(s, Source.INIT_PARAM);
            StringBuilder snake = new StringBuilder();
            for (int i = 0; i < init.length(); i++) {
                char c = init.charAt(i);
                snake.append(Character.isUpperCase(c) && i > 0 ? "_" : "").append(Character.toUpperCase(c));
            }
            List<String> expected = List.of(Source.INIT_PARAM + " " + init, Source.SYSTEM_PROPERTY + " oidf.ssf." + init,
                    Source.ENV + " OIDF_SSF_" + snake);
            List<String> actual = new ArrayList<>();
            for (SourceName n : s.sources()) {
                actual.add(n.source() + " " + n.name());
            }
            assertEquals(expected, actual, s.name());
            assertEquals("OIDF_SSF_" + snake, s.name());
            assertEquals(List.of(), s.aliases(), s.name());
        }
    }

    /** Each setting read from each of its three sources, the others unset. */
    @Test
    void everySettingIsReadFromEachOfItsSources() {
        for (Setting s : CATALOGUE.settings()) {
            Case c = CASES.get(s.name());
            for (Source source : List.of(Source.INIT_PARAM, Source.SYSTEM_PROPERTY, Source.ENV)) {
                Map<String, String> env = base(s.name());
                Map<String, String> props = new HashMap<>();
                Map<String, String> init = new HashMap<>();
                (source == Source.INIT_PARAM ? init : source == Source.SYSTEM_PROPERTY ? props : env).put(source(s, source), c.value());
                if (source != Source.ENV) {
                    env.put("OIDF_DEPLOYMENT_PROFILE", DEVELOPMENT); // a governed value from an init-param is refused in production
                }
                assertEquals(c.expected(), c.read().apply(read(env, props, init)), s.name() + " from " + source);
            }
        }
    }

    /** The five secrets, each of which may be given as a file through each source's {@code _FILE} variant. */
    private static final List<String> SECRETS = List.of("OIDF_SSF_JDBC_PASSWORD", "OIDF_SSF_KAFKA_SASL_PASSWORD",
            "OIDF_SSF_INTROSPECTION_CLIENT_SECRET", "OIDF_SSF_RECEIVER_ENDPOINT_AUTH_TOKEN", "OIDF_SSF_RECEIVER_POLL_TOKEN",
            "OIDF_SSF_RECEIVER_CLIENT_SECRET", "OIDF_SSF_RECEIVER_CLIENT_KEY", "OIDF_SSF_KAFKA_SSL_TRUSTSTORE_PASSWORD",
            "OIDF_SSF_KAFKA_SSL_KEYSTORE_PASSWORD", "OIDF_SSF_KAFKA_SSL_KEY_PASSWORD", "OIDF_SSF_SECRET_KEY",
            "OIDF_SSF_SECRET_KEY_PREVIOUS");

    /**
     * Each secret read from a file named by its {@code _FILE} variant in each source ({@code X_FILE},
     * {@code oidf.ssf.x.file}, {@code xFile}), one trailing newline trimmed; the variant is a declared name, so the
     * unknown-key sweep does not report it.
     */
    @Test
    void everySecretIsReadFromAFileThroughEachSource(@TempDir Path dir) throws IOException {
        List<String> secrets = new ArrayList<>();
        for (Setting s : CATALOGUE.settings()) {
            if (s.type() == SettingType.SECRET) {
                secrets.add(s.name());
            }
        }
        assertEquals(SECRETS, secrets);
        for (String name : SECRETS) {
            Setting s = CATALOGUE.setting(name);
            assertEquals(3, s.fileVariants().size(), name);
            assertTrue(CATALOGUE.declaredEnvironmentNames().contains(name + "_FILE"), name);
            Path file = dir.resolve(name.toLowerCase(java.util.Locale.ROOT));
            String content = name.equals("OIDF_SSF_RECEIVER_CLIENT_KEY") ? CLIENT_JWK
                    : name.equals("OIDF_SSF_SECRET_KEY") ? KEY_A : name.equals("OIDF_SSF_SECRET_KEY_PREVIOUS") ? KEY_B : "from-" + name;
            Files.writeString(file, content + "\n");
            for (SourceName variant : s.fileVariants()) {
                Map<String, String> env = base(name);
                Map<String, String> props = new HashMap<>();
                Map<String, String> init = new HashMap<>();
                Source source = variant.source();
                (source == Source.INIT_PARAM ? init : source == Source.SYSTEM_PROPERTY ? props : env).put(variant.name(), file.toString());
                if (source != Source.ENV) {
                    env.put("OIDF_DEPLOYMENT_PROFILE", DEVELOPMENT);
                }
                assertEquals(content, CASES.get(name).read().apply(read(env, props, init)), name + " from " + variant.name());
            }
        }
    }

    @Test
    void theInitParamWinsThenTheSystemPropertyThenTheEnvironment() {
        for (String name : List.of("OIDF_SSF_RECEIVER_SCOPE", "OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS", "OIDF_SSF_ISSUER")) {
            Setting s = CATALOGUE.setting(name);
            Map<String, String> env = base(name);
            env.put(name, name.equals("OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS") ? "3" : "https://env.example.com");
            Map<String, String> props = Map.of(source(s, Source.SYSTEM_PROPERTY), name.equals("OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS") ? "2"
                    : "https://prop.example.com");
            Map<String, String> init = Map.of(source(s, Source.INIT_PARAM), name.equals("OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS") ? "1"
                    : "https://init.example.com");
            Function<SsfConfiguration, Object> r = CASES.get(name).read();
            assertEquals(name.equals("OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS") ? 1 : "https://init.example.com", r.apply(read(env, props, init)));
            assertEquals(name.equals("OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS") ? 2 : "https://prop.example.com", r.apply(read(env, props, Map.of())));
            assertEquals(name.equals("OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS") ? 3 : "https://env.example.com", r.apply(read(env, Map.of(), Map.of())));
        }
    }

    /** A value the entry's type refuses, for each entry whose type refuses anything. */
    private static String bad(Setting s) {
        if (s.type() == SettingType.BOOL) {
            return "maybe";
        } else if (s.type() == SettingType.INT || s.type() == SettingType.LONG) {
            return "five";
        } else if (s.type() == SettingType.CHOICE) {
            return s.choices().get(0).toLowerCase(java.util.Locale.ROOT) + "x";
        } else if (s.type() == SettingType.URL) {
            return "not a url";
        } else if (s.type() == SettingType.WORDS) {
            return " , ";
        }
        return null;
    }

    @Test
    void everyRefusalNamesItsSetting() {
        int refused = 0;
        for (Setting s : CATALOGUE.settings()) {
            String value = bad(s);
            if (value == null) {
                continue;
            }
            Map<String, String> env = base(s.name());
            env.put(s.name(), value);
            SettingRefused e = assertThrows(SettingRefused.class, () -> read(env, Map.of(), Map.of()), s.name());
            assertEquals(s.name(), e.setting());
            assertTrue(e.getMessage().contains(s.name()), e.getMessage());
            refused++;
        }
        assertEquals(34, refused, "the switches, the numbers, the choices, the URLs, the event types and the issuers");
    }

    @Test
    void theCombinationsTheConfigurationRefusesNameTheirSettings() {
        Map<String, String> noIssuer = new HashMap<>();
        SettingRefused e = assertThrows(SettingRefused.class, () -> read(noIssuer, Map.of(), Map.of()));
        assertEquals("OIDF_SSF_ISSUER", e.setting());

        Map<String, String> kafka = Map.of("OIDF_SSF_ISSUER", "https://op.example.com", "OIDF_SSF_KAFKA_ENABLED", "true");
        e = assertThrows(SettingRefused.class, () -> read(kafka, Map.of(), Map.of()));
        assertEquals("OIDF_SSF_KAFKA_BOOTSTRAP_SERVERS", e.setting());
        assertEquals("OIDF_SSF_KAFKA_BOOTSTRAP_SERVERS is required when OIDF_SSF_KAFKA_ENABLED=true", e.getMessage());

        Map<String, String> scopes = Map.of("OIDF_SSF_ISSUER", "https://op.example.com", "OIDF_SSF_PROVISIONER_SCOPE", "ssf.manage");
        e = assertThrows(SettingRefused.class, () -> read(scopes, Map.of(), Map.of()));
        assertEquals("OIDF_SSF_PROVISIONER_SCOPE", e.setting());
        assertTrue(e.getMessage().contains("OIDF_SSF_RECEIVER_SCOPE"), e.getMessage());

        Map<String, String> audiences = Map.of("OIDF_SSF_ISSUER", "https://op.example.com", "OIDF_SSF_ALLOWED_AUDIENCES", "https://a.example.com");
        e = assertThrows(SettingRefused.class, () -> read(audiences, Map.of(), Map.of()));
        assertEquals("OIDF_SSF_ALLOWED_AUDIENCES", e.setting());
    }

    /** The receiver's client and managed stream settings come in sets; each wrong set names the setting to change. */
    @Test
    void theReceiversClientAndStreamSettingsAreRefusedOutOfTheirSets() {
        String token = "OIDF_SSF_RECEIVER_TOKEN_ENDPOINT";
        String id = "OIDF_SSF_RECEIVER_CLIENT_ID";
        String secret = "OIDF_SSF_RECEIVER_CLIENT_SECRET";
        String key = "OIDF_SSF_RECEIVER_CLIENT_KEY";
        String config = "OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL";
        String[][] cases = {
            {id, "rx", "", "", token, "OIDF_SSF_RECEIVER_TOKEN_ENDPOINT is required when the receiver has a client"},
            {secret, "s", "", "", token, null},
            {key, CLIENT_JWK, "", "", token, null},
            {token, "https://as.example.com/t", "", "", id, "OIDF_SSF_RECEIVER_CLIENT_ID is required with OIDF_SSF_RECEIVER_TOKEN_ENDPOINT"},
            {token, "https://as.example.com/t", id, "rx", secret, "set one of OIDF_SSF_RECEIVER_CLIENT_SECRET and"
                    + " OIDF_SSF_RECEIVER_CLIENT_KEY with OIDF_SSF_RECEIVER_TOKEN_ENDPOINT, not neither"},
            {key, "{\"kty\":\"oct\",\"k\":\"AAAA\"}", token, "https://as.example.com/t", key, null},
            {config, "https://tx.example.com/.well-known/ssf-configuration", "", "", config, null},
            {"OIDF_SSF_RECEIVER_PUSH_ENDPOINT_URL", "https://me.example.com/events", "", "", "OIDF_SSF_RECEIVER_PUSH_ENDPOINT_URL", null},
        };
        for (String[] c : cases) {
            Map<String, String> env = new HashMap<>(Map.of("OIDF_SSF_ISSUER", "https://op.example.com", c[0], c[1]));
            if (!c[2].isEmpty()) {
                env.put(c[2], c[3]);
            }
            if (c[0].equals(key) && !c[2].isEmpty()) {
                env.put(id, "rx");
            }
            SettingRefused e = assertThrows(SettingRefused.class, () -> read(env, Map.of(), Map.of()), c[0]);
            assertEquals(c[4], e.setting(), c[0]);
            if (c[5] != null) {
                assertTrue(e.getMessage().startsWith(c[5]), e.getMessage());
            }
        }
        Map<String, String> both = new HashMap<>(Map.of("OIDF_SSF_ISSUER", "https://op.example.com", token, "https://as.example.com/t",
                id, "rx", secret, "s", key, CLIENT_JWK));
        assertEquals(secret, assertThrows(SettingRefused.class, () -> read(both, Map.of(), Map.of())).setting());
        both.remove(key);
        both.put("OIDF_SSF_RECEIVER_POLL_TOKEN", "pt");
        assertEquals("OIDF_SSF_RECEIVER_POLL_TOKEN", assertThrows(SettingRefused.class, () -> read(both, Map.of(), Map.of())).setting());
        both.put("OIDF_SSF_RECEIVER_POLL_TOKEN", " ");
        assertEquals("rx", read(both, Map.of(), Map.of()).receiverClientId(), "a blank poll token is none");
        both.put(config, "https://tx.example.com/.well-known/ssf-configuration");
        both.put("OIDF_SSF_RECEIVER_POLL_URL", "https://tx.example.com/poll");
        assertEquals("OIDF_SSF_RECEIVER_POLL_URL", assertThrows(SettingRefused.class, () -> read(both, Map.of(), Map.of())).setting());
        both.remove("OIDF_SSF_RECEIVER_POLL_URL");
        both.put("OIDF_SSF_RECEIVER_PUSH_ENDPOINT_URL", "https://me.example.com/events");
        assertEquals("https://me.example.com/events", read(both, Map.of(), Map.of()).receiverPushEndpointUrl());
        Map<String, String> devToken = new HashMap<>(Map.of("OIDF_SSF_ISSUER", "https://op.example.com", config,
                "https://tx.example.com/.well-known/ssf-configuration", "OIDF_SSF_RECEIVER_POLL_TOKEN", " "));
        assertEquals(config, assertThrows(SettingRefused.class, () -> read(devToken, Map.of(), Map.of())).setting());
        devToken.put("OIDF_SSF_RECEIVER_POLL_TOKEN", "pt");
        assertEquals(SsfConfiguration.RECEIVER_DEFAULT_EVENTS, read(devToken, Map.of(), Map.of()).receiverEventsRequested());
    }

    /**
     * The URLs the receiver sends its tokens to or through are https in production: RFC 6749 §3.2, the authorization
     * server "MUST require the use of TLS as described in Section 1.6 when sending requests to the token endpoint";
     * SSF 1.0 §7.1, configuration_endpoint: "If present, this URL MUST use HTTP over TLS [RFC9110]". Development only
     * warns, for a rig.
     */
    @Test
    @Requirement("SSF §7.1")
    void theReceiversUrlsAreHttpsInProduction() {
        for (String name : List.of("OIDF_SSF_RECEIVER_TOKEN_ENDPOINT", "OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL",
                "OIDF_SSF_RECEIVER_PUSH_ENDPOINT_URL")) {
            List<ProfileAudit.Violation> plain = ProfileAudit.evaluate(Sources.of(Map.of(name, "http://tx.example.com/x"),
                    Map.of()), List.of(CATALOGUE), DeploymentProfile.PRODUCTION, AcceptedRisks.none()).violations();
            assertEquals(List.of(name), plain.stream().map(ProfileAudit.Violation::setting).toList(), name);
            assertEquals(List.of("SSF_RECEIVER"), plain.get(0).components(), name);
            assertEquals(List.of(), ProfileAudit.evaluate(Sources.of(Map.of(name, "https://tx.example.com/x"), Map.of()),
                    List.of(CATALOGUE), DeploymentProfile.PRODUCTION, AcceptedRisks.none()).violations(), name);
        }
    }

    /**
     * The seven switches are {@code true} or {@code false} (any case) in both profiles; a legacy spelling is refused in
     * production and read as the reader before 0.6.0 read it - {@code false}, whatever the default - in development.
     */
    @Test
    void theSwitchesAreStrictInProductionAndLegacyLenientInDevelopment() {
        for (String name : SWITCHES) {
            Function<SsfConfiguration, Object> r = CASES.get(name).read();
            for (String spelling : List.of("yes", "1", "on", "no", "0", "off", " YES ")) {
                Map<String, String> production = base(name);
                production.put(name, spelling);
                SettingRefused e = assertThrows(SettingRefused.class, () -> read(production, Map.of(), Map.of()), name + "=" + spelling);
                assertEquals(name, e.setting());

                Map<String, String> development = base(name);
                development.put(name, spelling);
                development.put("OIDF_DEPLOYMENT_PROFILE", DEVELOPMENT);
                assertEquals(false, r.apply(read(development, Map.of(), Map.of())), name + "=" + spelling + " in development");
            }
            for (String strict : List.of("TRUE", " true ", "False")) {
                Map<String, String> env = base(name);
                env.put(name, strict);
                env.put("OIDF_DEPLOYMENT_PROFILE", DEVELOPMENT); // the insecure switches are refused at read from an init-param only
                assertEquals(Boolean.parseBoolean(strict.trim()), r.apply(read(env, Map.of(), Map.of())), name + "=" + strict);
            }
            Map<String, String> typo = base(name);
            typo.put(name, "treu");
            typo.put("OIDF_DEPLOYMENT_PROFILE", DEVELOPMENT);
            assertThrows(SettingRefused.class, () -> read(typo, Map.of(), Map.of()), "a typo is no legacy spelling: " + name);
        }
    }

    /** An init-param the sweep cannot see is refused when it is read: PR-5's read-time refusal, now that SSF reads through it. */
    @Test
    void aGovernedValueFromAnInitParamIsRefusedAtReadInProduction() {
        Map<String, String> init = Map.of("introspectionInsecureTls", "true");
        ProfileRefused e = assertThrows(ProfileRefused.class, () -> read(base("x"), Map.of(), init));
        assertTrue(e.getMessage().contains("OIDF_SSF_INTROSPECTION_INSECURE_TLS"), e.getMessage());

        Map<String, String> development = base("x");
        development.put("OIDF_DEPLOYMENT_PROFILE", DEVELOPMENT);
        assertTrue(read(development, Map.of(), init).introspectionInsecureTls());
    }

    /**
     * Finding F-0297: a receiver setting the production profile refuses refuses the receiver, not the transmitter it
     * runs inside; a transmitter setting refuses both, since the receiver cannot run without the transmitter.
     */
    @Test
    void theReceiversSettingsRefuseTheReceiverOnly() {
        for (Setting s : CATALOGUE.settings()) {
            boolean receiver = s.name().startsWith("OIDF_SSF_RECEIVER_") && !s.name().equals("OIDF_SSF_RECEIVER_SCOPE");
            assertEquals(receiver ? List.of("SSF_RECEIVER") : List.of("SSF", "SSF_RECEIVER"), CATALOGUE.componentsOf(s), s.name());
        }
    }

    /**
     * Plan item H-SSF-3: OIDF_SSF_BASE_PATH changed the URLs the transmitter advertised and not the paths its servlets
     * answer, so it is removed, and a deployment that still sets it - by any of its three names - is refused, naming it.
     */
    @Test
    void theRemovedBasePathIsRefusedByEachOfItsNames() {
        Map<String, String> issuer = Map.of("OIDF_SSF_ISSUER", "https://op.example.com");
        SettingRefused e = assertThrows(SettingRefused.class, () -> read(
                Map.of("OIDF_SSF_ISSUER", "https://op.example.com", "OIDF_SSF_BASE_PATH", "/ssf"), Map.of(), Map.of()));
        assertEquals("OIDF_SSF_BASE_PATH", e.setting());
        assertEquals("OIDF_SSF_BASE_PATH was removed in 0.6.0 and nothing replaces it; unset it", e.getMessage());
        assertEquals("oidf.ssf.basePath",
                assertThrows(SettingRefused.class, () -> read(issuer, Map.of("oidf.ssf.basePath", "/ssf"), Map.of())).setting());
        assertEquals("basePath",
                assertThrows(SettingRefused.class, () -> read(issuer, Map.of(), Map.of("basePath", "/ssf"))).setting());
        assertEquals("https://op.example.com/ssf/streams", read(issuer, Map.of(), Map.of()).configurationEndpoint());
    }

    @Test
    void theDefaultsAreTheCataloguesAndTheBuilders() {
        SsfConfiguration read = read(Map.of("OIDF_SSF_ISSUER", "https://op.example.com"), Map.of(), Map.of());
        SsfConfiguration built = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        for (Map.Entry<String, Case> c : CASES.entrySet()) {
            assertEquals(c.getValue().read().apply(built), c.getValue().read().apply(read), c.getKey());
        }
        assertFalse(read.kafkaEnabled());
        assertTrue(read.usesInMemoryStore());
    }
}
