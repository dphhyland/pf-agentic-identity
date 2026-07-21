/*
 * The JSON envelope carrying a SET onto the Kafka topic.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.LinkedHashMap;
import java.util.Map;
import org.jose4j.json.JsonUtil;

/**
 * The value written to the Kafka topic for each emitted SET (the message key is the subject identifier).
 * Documented shape (see docs/ssf-transmitter.md):
 *
 * <pre>{@code {"type": "<event type URI>", "subject": "<subject key>", "set": "<compact JWS>", "iat": <epoch>}}</pre>
 *
 * The {@code set} field carries the full signed SET so a Kafka consumer can verify it independently against the
 * transmitter's {@code jwks_uri}.
 */
public final class KafkaEnvelope {

    private KafkaEnvelope() {
    }

    public static Map<String, Object> map(String eventType, String subjectKey, String setJws, long iat) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("type", eventType);
        m.put("subject", subjectKey);
        m.put("set", setJws);
        m.put("iat", iat);
        return m;
    }

    public static String json(String eventType, String subjectKey, String setJws, long iat) {
        return JsonUtil.toJson(map(eventType, subjectKey, setJws, iat));
    }
}
