/*
 * Optional Kafka fan-out for emitted SETs. Uses reflection so the module has NO compile-time Kafka
 * dependency and loads zero Kafka classes when disabled.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Publishes every emitted SET to a Kafka topic (default {@code sse-events}): message key = subject identifier,
 * value = the {@link KafkaEnvelope} JSON (which embeds the full signed SET). The Kafka producer is created and
 * driven entirely by reflection against {@code org.apache.kafka.clients.producer.*}, so this module needs no
 * {@code kafka-clients} at compile time and — because {@link #create} is only called when {@code kafkaEnabled}
 * is true — triggers no Kafka classloading when the connector is off. Publishing is best-effort: a send failure
 * is logged and counted ({@code ssf.set.dropped} {@code kafka}), never propagated.
 *
 * <p><b>Transport</b> (plan items H-SSF-7 and PR-2, finding F-0058). {@code security.protocol} is {@code SSL} unless
 * {@code OIDF_SSF_KAFKA_SECURITY_PROTOCOL} says otherwise; {@code PLAINTEXT} and {@code SASL_PLAINTEXT} are refused under
 * the production profile - by the catalogue's sweep, and here as well, through {@link ProfileRefusals#refuse}, since a
 * protocol can reach the producer by a route the sweep does not read (an init-param). With TLS on, the {@code ssl.*}
 * settings go through as catalogued ({@link #producerProps}): trust and key stores, their types and passwords, and host
 * name verification, which only the development profile may turn off.
 *
 * <p><b>Timeouts</b> (S5d). {@code send()} blocks the thread that raised the event - a PingFederate request thread, or
 * the one writing its audit record - for up to {@code max.block.ms} while it waits for metadata or buffer space; Kafka's
 * default is a minute. The producer gets {@code request.timeout.ms}, {@code delivery.timeout.ms} and
 * {@code max.block.ms} from settings with bounded defaults (10 s, 30 s, 2 s), and {@code linger.ms} 0, so that
 * {@code delivery.timeout.ms >= request.timeout.ms + linger.ms} holds whatever the client version's own linger default.
 *
 * <p><b>JAAS</b>. {@code sasl.jaas.config} is one line Kafka parses with {@link java.io.StreamTokenizer} (Kafka 4.0's
 * {@code JaasConfig}): each option value is written as a double-quoted string with {@code \} and {@code "} escaped and a
 * line break written as {@code \n} or {@code \r} ({@link #jaasQuote}), so a user name or password holding a quote, a
 * semicolon or a newline is read back as itself and cannot add an option or end the entry early.
 *
 * <p>The producer call is behind the {@link Sender} seam so the envelope/keying is unit-tested without a broker.
 */
public final class KafkaSetPublisher implements SetPublisher {

    private static final Log LOGGER = LogFactory.getLog(KafkaSetPublisher.class);

    /** The protocols that send in clear: forbidden in production. */
    static final Set<String> CLEAR_PROTOCOLS = Set.of("PLAINTEXT", "SASL_PLAINTEXT");

    /** The producer send, isolated for testing: (topic, key, value) -> fire-and-forget. */
    public interface Sender {
        void send(String topic, String key, String value) throws Exception;

        default void close() {
        }
    }

    private final String topic;
    private final Sender sender;

    KafkaSetPublisher(String topic, Sender sender) {
        this.topic = topic;
        this.sender = sender;
    }

    /**
     * Build a Kafka-backed publisher from config, reflectively constructing a {@code KafkaProducer}.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.ProfileRefused under production, for a protocol that sends in
     *         clear or host name verification off
     */
    public static KafkaSetPublisher create(SsfConfiguration config) {
        refuseClearTransport(config);
        return new KafkaSetPublisher(config.kafkaTopic(), reflectiveSender(config));
    }

    /**
     * PR-2's refusal in code (Phase 3 plan, decisions 10 and 15): under production, a protocol that sends in clear, or
     * TLS without host name verification, refuses SSF; under development each is a WARN and the producer is built.
     */
    static void refuseClearTransport(SsfConfiguration config) {
        String protocol = protocolOf(config);
        if (CLEAR_PROTOCOLS.contains(protocol)) {
            ProfileRefusals.refuse(Startup.SSF, "Kafka's security.protocol is " + protocol + ": SETs, and with SASL the"
                    + " password, would cross the network in clear; set " + SsfConfiguration.KAFKA_SECURITY_PROTOCOL
                    + " to SSL or SASL_SSL and the " + "OIDF_SSF_KAFKA_SSL_* settings");
        }
        if (!config.kafkaSslHostnameVerification()) {
            ProfileRefusals.refuse(Startup.SSF, SsfConfiguration.KAFKA_SSL_HOSTNAME_VERIFICATION + " is false: any"
                    + " certificate a CA in the truststore signed is taken as the broker's, whatever its host name");
        }
    }

    /** The protocol the producer will use, upper case. */
    static String protocolOf(SsfConfiguration config) {
        String protocol = config.kafkaSecurityProtocol();
        return protocol == null || protocol.isBlank() ? "SSL" : protocol.trim().toUpperCase(Locale.ROOT);
    }

    @Override
    public void publish(String eventType, String subjectKey, String setJws, long iat) {
        String value = KafkaEnvelope.json(eventType, subjectKey, setJws, iat);
        try {
            this.sender.send(this.topic, subjectKey, value);
        } catch (Exception e) {
            LOGGER.warn((Object) ("Kafka publish failed for event " + eventType + ": " + e.getMessage()));
            SsfEvents.setDropped(eventType, null, SsfEvents.KAFKA);
        }
    }

    @Override
    public void close() {
        this.sender.close();
    }

    // ─────────────────────────── reflective producer ───────────────────────────

    private static Sender reflectiveSender(SsfConfiguration config) {
        try {
            Class<?> producerCls = Class.forName("org.apache.kafka.clients.producer.KafkaProducer");
            Class<?> recordCls = Class.forName("org.apache.kafka.clients.producer.ProducerRecord");
            Object producer = producerCls.getConstructor(Properties.class).newInstance(producerProps(config));
            Constructor<?> recordCtor = recordCls.getConstructor(String.class, Object.class, Object.class);
            Method sendMethod = producerCls.getMethod("send", recordCls);
            Method closeMethod = producerCls.getMethod("close");
            LOGGER.info((Object) ("Kafka SET publisher: topic '" + config.kafkaTopic() + "' via "
                    + config.kafkaBootstrapServers() + " (" + protocolOf(config) + ")"));
            return new Sender() {
                @Override
                public void send(String topic, String key, String value) throws Exception {
                    sendMethod.invoke(producer, recordCtor.newInstance(topic, key, value));
                }

                @Override
                public void close() {
                    try {
                        closeMethod.invoke(producer);
                    } catch (Exception e) {
                        LOGGER.warn((Object) ("Kafka producer close failed: " + e.getMessage()));
                    }
                }
            };
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("kafkaEnabled=true but kafka-clients is not on the PingFederate "
                    + "classpath (add the shaded producer jar to deploy/)", e);
        } catch (Exception e) {
            throw new IllegalStateException("failed to create Kafka producer: " + e.getMessage(), e);
        }
    }

    /**
     * The producer's properties. Kafka 4.0's producer configuration: {@code security.protocol} "Protocol used to
     * communicate with brokers", "Valid Values: (case insensitive) [SASL_SSL, PLAINTEXT, SSL, SASL_PLAINTEXT]";
     * {@code ssl.endpoint.identification.algorithm} "The endpoint identification algorithm to validate server hostname
     * using server certificate", default {@code https}; {@code max.block.ms} "controls how long the KafkaProducer's send()
     * ... methods will block".
     */
    static Properties producerProps(SsfConfiguration config) {
        Properties p = new Properties();
        p.put("bootstrap.servers", config.kafkaBootstrapServers());
        p.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        p.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        p.put("acks", "all");
        p.put("client.id", "pf-ssf-transmitter");
        p.put("request.timeout.ms", Integer.toString(config.kafkaRequestTimeoutMs()));
        p.put("delivery.timeout.ms", Integer.toString(config.kafkaDeliveryTimeoutMs()));
        p.put("max.block.ms", Integer.toString(config.kafkaMaxBlockMs()));
        p.put("linger.ms", "0");
        String protocol = protocolOf(config);
        p.put("security.protocol", protocol);
        if (protocol.endsWith("SSL")) {
            putIfSet(p, "ssl.truststore.location", config.kafkaSslTruststoreLocation());
            putIfSet(p, "ssl.truststore.password", config.kafkaSslTruststorePassword());
            putIfSet(p, "ssl.truststore.type", config.kafkaSslTruststoreType());
            putIfSet(p, "ssl.keystore.location", config.kafkaSslKeystoreLocation());
            putIfSet(p, "ssl.keystore.password", config.kafkaSslKeystorePassword());
            putIfSet(p, "ssl.keystore.type", config.kafkaSslKeystoreType());
            putIfSet(p, "ssl.key.password", config.kafkaSslKeyPassword());
            // Kafka reads an empty value as "no host name check"; https is its default and the only other value.
            p.put("ssl.endpoint.identification.algorithm", config.kafkaSslHostnameVerification() ? "https" : "");
        }
        if (protocol.startsWith("SASL")) {
            String mechanism = config.kafkaSaslMechanism() != null ? config.kafkaSaslMechanism() : "PLAIN";
            p.put("sasl.mechanism", mechanism);
            if (config.kafkaSaslUsername() != null) {
                p.put("sasl.jaas.config", jaasConfig(mechanism, config.kafkaSaslUsername(), config.kafkaSaslPassword()));
            }
        }
        return p;
    }

    private static void putIfSet(Properties p, String name, String value) {
        if (value != null && !value.isEmpty()) {
            p.put(name, value);
        }
    }

    /**
     * The JAAS entry, in the format Kafka 4.0 documents for {@code sasl.jaas.config}: "loginModuleClass controlFlag
     * (optionName=optionValue)*;", each value quoted by {@link #jaasQuote}.
     */
    static String jaasConfig(String mechanism, String username, String password) {
        String loginModule = mechanism.startsWith("SCRAM")
                ? "org.apache.kafka.common.security.scram.ScramLoginModule"
                : "org.apache.kafka.common.security.plain.PlainLoginModule";
        return loginModule + " required username=" + jaasQuote(username) + " password="
                + jaasQuote(password == null ? "" : password) + ";";
    }

    /**
     * {@code value} as a double-quoted {@link java.io.StreamTokenizer} string, the tokenizer Kafka's {@code JaasConfig}
     * reads the line with: inside quotes it takes {@code \\} as a backslash and {@code \"} as a quote, turns
     * {@code \n} and {@code \r} into line breaks, and ends the string at a raw line break, so each of those four is
     * escaped and every other character is written as it is.
     */
    static String jaasQuote(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                default -> out.append(c);
            }
        }
        return out.append('"').toString();
    }
}
