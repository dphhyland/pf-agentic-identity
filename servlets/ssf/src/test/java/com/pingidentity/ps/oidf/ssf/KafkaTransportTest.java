/*
 * H-SSF-7 and PR-2 on Kafka: TLS by default, the ssl settings passed through, JAAS escaped, bounded timeouts, and
 * plaintext refused in production.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import java.io.IOException;
import java.io.StreamTokenizer;
import java.io.StringReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class KafkaTransportTest {

    @AfterEach
    void reset() {
        ProfileRefusals.resetForTests();
        Events.reset();
    }

    private static void publish(DeploymentProfile profile) {
        ProfileRefusals.resetForTests();
        ProfileRefusals.publish(new ProfileAudit.Result(profile, List.of(), List.of()));
    }

    private static SsfConfiguration.Builder kafka() {
        return new SsfConfiguration.Builder().issuer("https://op.example.com").kafkaEnabled(true).kafkaBootstrapServers("broker:9093");
    }

    /**
     * Kafka 4.0's producer configuration gives {@code security.protocol} the default PLAINTEXT; this transmitter's is
     * SSL, with the brokers' host name checked ({@code ssl.endpoint.identification.algorithm} https), and the three
     * timeouts bounded rather than Kafka's minute of {@code max.block.ms}.
     */
    @Test
    void tlsAndBoundedTimeoutsByDefault() {
        Properties p = KafkaSetPublisher.producerProps(kafka().build());
        assertEquals("SSL", p.get("security.protocol"));
        assertEquals("https", p.get("ssl.endpoint.identification.algorithm"));
        assertEquals("10000", p.get("request.timeout.ms"));
        assertEquals("30000", p.get("delivery.timeout.ms"));
        assertEquals("2000", p.get("max.block.ms"));
        assertEquals("0", p.get("linger.ms"));
        assertNull(p.get("ssl.truststore.location"), "unset: the JVM's CAs");
        assertNull(p.get("sasl.jaas.config"));
    }

    @Test
    void theSslSettingsArePassedThrough() {
        Properties p = KafkaSetPublisher.producerProps(kafka().kafkaSecurityProtocol("sasl_ssl").kafkaSaslMechanism("SCRAM-SHA-512")
                .kafkaSaslUsername("svc").kafkaSaslPassword("pw")
                .kafkaSslTruststoreLocation("/opt/kafka/trust.p12").kafkaSslTruststorePassword("tp").kafkaSslTruststoreType("PKCS12")
                .kafkaSslKeystoreLocation("/opt/kafka/client.p12").kafkaSslKeystorePassword("kp").kafkaSslKeystoreType("PKCS12")
                .kafkaSslKeyPassword("kk").kafkaRequestTimeoutMs(5000).kafkaDeliveryTimeoutMs(6000).kafkaMaxBlockMs(100).build());
        assertEquals("SASL_SSL", p.get("security.protocol"));
        assertEquals("/opt/kafka/trust.p12", p.get("ssl.truststore.location"));
        assertEquals("tp", p.get("ssl.truststore.password"));
        assertEquals("PKCS12", p.get("ssl.truststore.type"));
        assertEquals("/opt/kafka/client.p12", p.get("ssl.keystore.location"));
        assertEquals("kp", p.get("ssl.keystore.password"));
        assertEquals("PKCS12", p.get("ssl.keystore.type"));
        assertEquals("kk", p.get("ssl.key.password"));
        assertEquals("SCRAM-SHA-512", p.get("sasl.mechanism"));
        assertTrue(((String) p.get("sasl.jaas.config")).startsWith("org.apache.kafka.common.security.scram.ScramLoginModule required"));
        assertEquals("5000", p.get("request.timeout.ms"));
        assertEquals("6000", p.get("delivery.timeout.ms"));
        assertEquals("100", p.get("max.block.ms"));
    }

    @Test
    void saslWithoutAMechanismIsPlainAndWithoutAUserHasNoJaasLine() {
        Properties p = KafkaSetPublisher.producerProps(kafka().kafkaSecurityProtocol("SASL_SSL").build());
        assertEquals("PLAIN", p.get("sasl.mechanism"));
        assertNull(p.get("sasl.jaas.config"));
        Properties q = KafkaSetPublisher.producerProps(kafka().kafkaSecurityProtocol("SASL_SSL").kafkaSaslUsername("u").build());
        assertTrue(((String) q.get("sasl.jaas.config")).startsWith("org.apache.kafka.common.security.plain.PlainLoginModule"));
    }

    @Test
    void plaintextCarriesNoSslSettingsAndHostNameVerificationOffIsEmpty() {
        Properties clear = KafkaSetPublisher.producerProps(kafka().kafkaSecurityProtocol("PLAINTEXT")
                .kafkaSslTruststoreLocation("/opt/kafka/trust.p12").build());
        assertEquals("PLAINTEXT", clear.get("security.protocol"));
        assertNull(clear.get("ssl.truststore.location"));
        assertNull(clear.get("ssl.endpoint.identification.algorithm"));
        Properties noCheck = KafkaSetPublisher.producerProps(kafka().kafkaSslHostnameVerification(false).build());
        assertEquals("", noCheck.get("ssl.endpoint.identification.algorithm"));
    }

    /**
     * Kafka's producer refuses delivery.timeout.ms below request.timeout.ms + linger.ms ("The value of this config should
     * be greater than or equal to the sum of request.timeout.ms and linger.ms"); the configuration refuses it first,
     * naming the setting.
     */
    @Test
    void aDeliveryTimeoutShorterThanTheRequestTimeoutIsRefused() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> kafka().kafkaRequestTimeoutMs(20000).kafkaDeliveryTimeoutMs(10000).build());
        assertTrue(e.getMessage().startsWith("OIDF_SSF_KAFKA_DELIVERY_TIMEOUT_MS"), e.getMessage());
    }

    // ─────────────────────────── JAAS ───────────────────────────

    /**
     * Kafka 4.0's {@code JaasConfig} constructor, as its source has it: a {@link StreamTokenizer} with {@code //} and
     * {@code /*} comments on and {@code -}, {@code _} and {@code $} as word characters, then per entry the login module,
     * the control flag, and {@code key=value} options up to {@code ;}. The test parses what the publisher writes with it.
     */
    static Map<String, String> parseLikeKafka(String jaas) throws IOException {
        StreamTokenizer tokenizer = new StreamTokenizer(new StringReader(jaas));
        tokenizer.slashSlashComments(true);
        tokenizer.slashStarComments(true);
        tokenizer.wordChars('-', '-');
        tokenizer.wordChars('_', '_');
        tokenizer.wordChars('$', '$');
        Map<String, String> options = new HashMap<>();
        int entries = 0;
        while (tokenizer.nextToken() != StreamTokenizer.TT_EOF) {
            entries++;
            options.put("<module>", tokenizer.sval);
            tokenizer.nextToken();
            options.put("<flag>", tokenizer.sval);
            while (tokenizer.nextToken() != StreamTokenizer.TT_EOF && tokenizer.ttype != ';') {
                String key = tokenizer.sval;
                if (tokenizer.nextToken() != '=' || tokenizer.nextToken() == StreamTokenizer.TT_EOF || tokenizer.sval == null) {
                    throw new IllegalArgumentException("Value not specified for key '" + key + "' in JAAS config");
                }
                options.put(key, tokenizer.sval);
            }
            if (tokenizer.ttype != ';') {
                throw new IllegalArgumentException("JAAS config entry not terminated by semi-colon");
            }
        }
        options.put("<entries>", Integer.toString(entries));
        return options;
    }

    @Test
    void hostileValuesAreReadBackAsThemselves() throws IOException {
        List<String> hostile = List.of(
                "plain",
                "quote\"inside",
                "back\\slash\\",
                "semi;colon",
                "p\"; org.evil.Module required admin=\"true",
                "line\nbreak and\r return",
                "// not a comment",
                "/* not a comment */",
                "tab\there",
                "\\n literal backslash-n",
                "\\\"",
                "single'quote",
                "unicode é ü 中文",
                "");
        for (String password : hostile) {
            for (String mechanism : List.of("PLAIN", "SCRAM-SHA-256")) {
                String jaas = KafkaSetPublisher.jaasConfig(mechanism, "user\"name", password);
                Map<String, String> parsed = parseLikeKafka(jaas);
                assertEquals("1", parsed.get("<entries>"), jaas);
                assertEquals("required", parsed.get("<flag>"));
                assertEquals("user\"name", parsed.get("username"), jaas);
                assertEquals(password, parsed.get("password"), jaas);
                assertEquals(5, parsed.size(), "no option but username and password: " + parsed);
            }
        }
        assertEquals("\"\"", KafkaSetPublisher.jaasQuote(""));
        assertEquals(parseLikeKafka(KafkaSetPublisher.jaasConfig("PLAIN", "u", null)).get("password"), "");
    }

    @Test
    void theOldUnescapedLineWouldHaveBeenInjected() throws IOException {
        // What 0.5.0 wrote for the same password: the quote ends the value and a second option follows.
        String password = "p\" admin=\"true";
        String old = "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"u\" password=\"" + password + "\";";
        assertEquals("true", parseLikeKafka(old).get("admin"));
        assertFalse(parseLikeKafka(KafkaSetPublisher.jaasConfig("PLAIN", "u", password)).containsKey("admin"));
    }

    // ─────────────────────────── the production profile ───────────────────────────

    @Test
    void plaintextIsRefusedInProduction() {
        publish(DeploymentProfile.PRODUCTION);
        for (String protocol : List.of("PLAINTEXT", "sasl_plaintext")) {
            SsfConfiguration cfg = kafka().kafkaSecurityProtocol(protocol).build();
            ProfileRefused e = assertThrows(ProfileRefused.class, () -> KafkaSetPublisher.create(cfg));
            assertTrue(e.getMessage().contains("OIDF_SSF_KAFKA_SECURITY_PROTOCOL"), e.getMessage());
        }
        SsfConfiguration noHostCheck = kafka().kafkaSslHostnameVerification(false).build();
        ProfileRefused e = assertThrows(ProfileRefused.class, () -> KafkaSetPublisher.create(noHostCheck));
        assertTrue(e.getMessage().contains("OIDF_SSF_KAFKA_SSL_HOSTNAME_VERIFICATION"), e.getMessage());
        KafkaSetPublisher.refuseClearTransport(kafka().kafkaSecurityProtocol("SASL_SSL").build()); // TLS: nothing refused
    }

    @Test
    void plaintextIsAllowedInDevelopmentWithAWarning() {
        publish(DeploymentProfile.DEVELOPMENT);
        KafkaSetPublisher.refuseClearTransport(kafka().kafkaSecurityProtocol("PLAINTEXT").kafkaSslHostnameVerification(false).build());
        assertEquals(List.of(), ProfileRefusals.codeRefusals());
        // without kafka-clients on the class path the producer is not built, whatever the protocol
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> KafkaSetPublisher.create(kafka().kafkaSecurityProtocol("PLAINTEXT").build()));
        assertTrue(e.getMessage().contains("kafka-clients"), e.getMessage());
    }

    /** SsfSupport lets the production profile's refusal through: Kafka in clear refuses SSF rather than turning Kafka off. */
    @Test
    void theRefusalReachesTheTransmittersStart() {
        publish(DeploymentProfile.PRODUCTION);
        SsfSupport.resetForTests();
        try {
            assertThrows(ProfileRefused.class, () -> SsfSupport.configure(kafka().kafkaSecurityProtocol("PLAINTEXT").build()));
            assertFalse(SsfSupport.isConfigured());
        } finally {
            SsfSupport.resetForTests();
        }
    }

    @Test
    void closingThePublisherClosesItsSender() {
        java.util.concurrent.atomic.AtomicInteger closed = new java.util.concurrent.atomic.AtomicInteger();
        new KafkaSetPublisher("t", new KafkaSetPublisher.Sender() {
            @Override
            public void send(String topic, String key, String value) {
            }

            @Override
            public void close() {
                closed.incrementAndGet();
            }
        }).close();
        assertEquals(1, closed.get());
        new KafkaSetPublisher("t", (topic, key, value) -> { }).close(); // the default close does nothing
    }

    @Test
    void aFailedPublishIsCounted() {
        List<Event> events = new CopyOnWriteArrayList<>();
        Events.configure(events::add);
        new KafkaSetPublisher("t", (topic, key, value) -> {
            throw new IOException("broker down");
        }).publish(SsfEventTypes.CAEP_SESSION_REVOKED, "k", "jws", 1L);
        assertEquals(1, events.size());
        assertEquals("ssf.set.dropped", events.get(0).code());
        assertEquals("kafka", events.get(0).reason());
        assertEquals("SSL", KafkaSetPublisher.protocolOf(new SsfConfiguration.Builder().issuer("https://op.example.com")
                .kafkaSecurityProtocol(" ").build()));
    }

    /** Kafka's Callback, as the producer declares it: onCompletion(RecordMetadata, Exception). */
    public interface Completion {
        void onCompletion(Object metadata, Exception exception);
    }

    /** A record the producer fails after send() returned (delivery.timeout.ms) reaches the callback, and is counted. */
    @Test
    void aFailureTheProducerReportsLaterIsCounted() {
        List<Event> events = new CopyOnWriteArrayList<>();
        Events.configure(events::add);
        List<Completion> callbacks = new CopyOnWriteArrayList<>();
        new KafkaSetPublisher("t", new KafkaSetPublisher.Sender() {
            @Override
            public void send(String topic, String key, String value) {
                throw new AssertionError("the publisher sends with a callback");
            }

            @Override
            public void send(String topic, String key, String value, java.util.function.Consumer<Exception> failed) {
                callbacks.add((Completion) KafkaSetPublisher.callback(Completion.class, failed));
            }
        }).publish(SsfEventTypes.CAEP_SESSION_REVOKED, "k", "jws", 1L);
        assertEquals(1, callbacks.size());
        assertTrue(events.isEmpty(), "nothing counted while the record is in flight");
        callbacks.get(0).onCompletion("metadata", null);
        assertTrue(events.isEmpty(), "acknowledged: nothing counted");
        callbacks.get(0).onCompletion(null, new IOException("Expiring 1 record(s): 30000 ms has passed since batch creation"));
        assertEquals(1, events.size());
        assertEquals("ssf.set.dropped", events.get(0).code());
        assertEquals("kafka", events.get(0).reason());
        Object callback = callbacks.get(0);
        assertEquals(callback, callback);
        assertFalse(callback.equals(new Object()));
        assertEquals(System.identityHashCode(callback), callback.hashCode());
        assertEquals("SSF Kafka callback", callback.toString());
    }

    @Test
    void theDefaultSendWithACallbackSendsWithout() throws Exception {
        List<String> sent = new CopyOnWriteArrayList<>();
        KafkaSetPublisher.Sender plain = (topic, key, value) -> sent.add(value);
        plain.send("t", "k", "v", e -> {
            throw new AssertionError(e);
        });
        assertEquals(List.of("v"), sent);
    }
}
