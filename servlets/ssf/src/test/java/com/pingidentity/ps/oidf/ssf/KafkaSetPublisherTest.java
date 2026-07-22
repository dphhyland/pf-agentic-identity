/*
 * Kafka envelope shape, keying by subject, SASL props, no-op sink, and emitter -> publisher fan-out.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

class KafkaSetPublisherTest {

    private static final class Recorded {
        final String topic;
        final String key;
        final String value;

        Recorded(String topic, String key, String value) {
            this.topic = topic;
            this.key = key;
            this.value = value;
        }
    }

    @Test
    void envelopeCarriesTypeSubjectSetAndIat() throws Exception {
        Map<String, Object> env = JsonUtil.parseJson(
                KafkaEnvelope.json(SsfEventTypes.CAEP_SESSION_REVOKED, "email:a@b.com", "the.jws.here", 1700L));
        assertEquals(SsfEventTypes.CAEP_SESSION_REVOKED, env.get("type"));
        assertEquals("email:a@b.com", env.get("subject"));
        assertEquals("the.jws.here", env.get("set"));
        assertEquals(1700L, env.get("iat"));
    }

    @Test
    void publisherSendsEnvelopeKeyedBySubject() throws Exception {
        List<Recorded> sent = new ArrayList<>();
        KafkaSetPublisher pub = new KafkaSetPublisher("sse-events",
                (topic, key, value) -> sent.add(new Recorded(topic, key, value)));
        pub.publish(SsfEventTypes.RISC_ACCOUNT_DISABLED, "email:a@b.com", "jws", 42L);

        assertEquals(1, sent.size());
        assertEquals("sse-events", sent.get(0).topic);
        assertEquals("email:a@b.com", sent.get(0).key, "message key = subject identifier");
        Map<String, Object> env = JsonUtil.parseJson(sent.get(0).value);
        assertEquals(SsfEventTypes.RISC_ACCOUNT_DISABLED, env.get("type"));
        assertEquals("jws", env.get("set"));
    }

    @Test
    void saslProducerPropsCarryJaasConfig() {
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .kafkaEnabled(true).kafkaBootstrapServers("broker:9093")
                .kafkaSecurityProtocol("SASL_SSL").kafkaSaslMechanism("PLAIN")
                .kafkaSaslUsername("u").kafkaSaslPassword("p").build();
        Properties props = KafkaSetPublisher.producerProps(cfg);
        assertEquals("broker:9093", props.get("bootstrap.servers"));
        assertEquals("SASL_SSL", props.get("security.protocol"));
        assertEquals("PLAIN", props.get("sasl.mechanism"));
        assertTrue(((String) props.get("sasl.jaas.config")).contains("username=\"u\""));
    }

    @Test
    void noopSinkDoesNothing() {
        SetPublisher.NOOP.publish("t", "s", "jws", 1L); // must not throw
        SetPublisher.NOOP.close();
    }

    @Test
    void emitterFansOutToThePublisher() throws Exception {
        InMemorySsfStore store = new InMemorySsfStore();
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        List<Recorded> sent = new ArrayList<>();
        SetPublisher sink = (type, subj, jws, iat) -> sent.add(new Recorded(type, subj, jws));
        SsfEventEmitter emitter = new SsfEventEmitter(store, new SetMinter("RS256", new TestSigningKeyProvider("k")), cfg, sink);

        store.createStream(Stream.builder().id("s1").audience("https://r").deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED))
                .eventsDelivered(List.of(SsfEventTypes.CAEP_SESSION_REVOKED)).status(StreamStatus.ENABLED).build());
        SubjectId alice = SubjectId.email("alice@example.com");
        store.addSubject("s1", alice);

        emitter.sessionRevoked(alice, "logout");
        assertEquals(1, sent.size());
        // in this test the sink records (eventType, subjectKey, jws) into (topic, key, value)
        assertEquals(SsfEventTypes.CAEP_SESSION_REVOKED, sent.get(0).topic);
        assertEquals(alice.canonicalKey(), sent.get(0).key);
    }
}
