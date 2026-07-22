/*
 * Optional Kafka fan-out for emitted SETs. Uses reflection so the module has NO compile-time Kafka
 * dependency and loads zero Kafka classes when disabled.
 */
package com.pingidentity.ps.oidf.ssf;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Properties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Publishes every emitted SET to a Kafka topic (default {@code sse-events}): message key = subject identifier,
 * value = the {@link KafkaEnvelope} JSON (which embeds the full signed SET). The Kafka producer is created and
 * driven entirely by reflection against {@code org.apache.kafka.clients.producer.*}, so this module needs no
 * {@code kafka-clients} at compile time and — because {@link #create} is only called when {@code kafkaEnabled}
 * is true — triggers no Kafka classloading when the connector is off. Publishing is best-effort: a send failure
 * is logged, never propagated.
 *
 * <p>The producer call is behind the {@link Sender} seam so the envelope/keying is unit-tested without a broker.
 */
public final class KafkaSetPublisher implements SetPublisher {

    private static final Log LOGGER = LogFactory.getLog(KafkaSetPublisher.class);

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

    /** Build a Kafka-backed publisher from config, reflectively constructing a {@code KafkaProducer}. */
    public static KafkaSetPublisher create(SsfConfiguration config) {
        return new KafkaSetPublisher(config.kafkaTopic(), reflectiveSender(config));
    }

    @Override
    public void publish(String eventType, String subjectKey, String setJws, long iat) {
        String value = KafkaEnvelope.json(eventType, subjectKey, setJws, iat);
        try {
            this.sender.send(this.topic, subjectKey, value);
        } catch (Exception e) {
            LOGGER.warn((Object) ("Kafka publish failed for event " + eventType + ": " + e.getMessage()));
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
                    + config.kafkaBootstrapServers() + " (" + config.kafkaSecurityProtocol() + ")"));
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

    static Properties producerProps(SsfConfiguration config) {
        Properties p = new Properties();
        p.put("bootstrap.servers", config.kafkaBootstrapServers());
        p.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        p.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        p.put("acks", "all");
        p.put("client.id", "pf-ssf-transmitter");
        String protocol = config.kafkaSecurityProtocol();
        if (protocol != null && !protocol.isBlank()) {
            p.put("security.protocol", protocol);
        }
        if (protocol != null && protocol.contains("SASL")) {
            String mechanism = config.kafkaSaslMechanism() != null ? config.kafkaSaslMechanism() : "PLAIN";
            p.put("sasl.mechanism", mechanism);
            if (config.kafkaSaslUsername() != null) {
                p.put("sasl.jaas.config", jaasConfig(mechanism, config.kafkaSaslUsername(), config.kafkaSaslPassword()));
            }
        }
        return p;
    }

    private static String jaasConfig(String mechanism, String username, String password) {
        String loginModule = mechanism.startsWith("SCRAM")
                ? "org.apache.kafka.common.security.scram.ScramLoginModule"
                : "org.apache.kafka.common.security.plain.PlainLoginModule";
        return loginModule + " required username=\"" + username + "\" password=\"" + (password == null ? "" : password) + "\";";
    }
}
