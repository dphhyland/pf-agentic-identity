/*
 * What an operator asks the transmitter to sign: one event, one subject, checked before anything is minted.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The body of {@code POST /ssf/events:emit}, parsed and validated. Everything a SET will carry is decided
 * here, transport-free, so the rules are testable one at a time and the servlet only maps outcomes to
 * statuses. An {@link IllegalArgumentException} from {@link #parse} is a 400.
 *
 * <pre>
 * {
 *   "event_type": "https://schemas.openid.net/secevent/caep/event-type/credential-change",
 *   "subject":    {"format": "email", "email": "alice@example.com"},
 *   "event":      {"credential_type": "password", "change_type": "update", "reason_admin": "rotated"},
 *   "stream_id":  "optional - only this stream, which must exist and still has to subscribe"
 * }
 * </pre>
 *
 * <p>The rules are the CAEP 1.0 event definitions and the CAEP Interop Profile's tightening of them,
 * applied as refusals rather than warnings: a receiver certifying against the profile fails a SET the suite
 * only warns about, and this transmitter would rather not sign it. For the three interop events (§3):
 * {@code reason_admin} is required and is an object, so a bare sentence is tagged {@code en} and an absent
 * one is supplied; the subject is {@code email} or {@code iss_sub}, never {@code opaque}, which §2.5 keeps
 * for the verification event; {@code credential_type}, {@code change_type}, {@code previous_status} and
 * {@code current_status} take only their defined values. Other known event types are accepted with
 * whatever members the caller sends; the verification event is refused, it has its own endpoint.
 */
public record EmitRequest(String eventType, SubjectId subject, Map<String, Object> payload, String streamId) {

    private static final Set<String> INTEROP_SUBJECT_FORMATS = Set.of(SubjectId.FORMAT_EMAIL, SubjectId.FORMAT_ISS_SUB);

    public EmitRequest {
        payload = payload == null ? Map.of() : Map.copyOf(payload);
    }

    /**
     * @param body the request body as parsed JSON
     * @param now  epoch seconds, stamped as {@code event_timestamp} unless the caller supplied a number
     * @throws IllegalArgumentException for anything this transmitter will not sign
     */
    @SuppressWarnings("unchecked")
    public static EmitRequest parse(Map<String, Object> body, long now) {
        if (body == null) {
            throw new IllegalArgumentException("request body is required");
        }
        String eventType = requireEventType(body.get("event_type"));
        Object subjectJson = body.get("subject");
        if (!(subjectJson instanceof Map)) {
            throw new IllegalArgumentException("\"subject\" must be a subject identifier object");
        }
        SubjectId subject = SubjectId.fromMap((Map<String, Object>) subjectJson);
        Object eventJson = body.get("event");
        if (eventJson != null && !(eventJson instanceof Map)) {
            throw new IllegalArgumentException("\"event\" must be an object");
        }
        LinkedHashMap<String, Object> event = eventJson == null
                ? new LinkedHashMap<>() : new LinkedHashMap<>((Map<String, Object>) eventJson);
        Object streamId = body.get("stream_id");
        if (streamId != null && (!(streamId instanceof String) || ((String) streamId).isBlank())) {
            throw new IllegalArgumentException("\"stream_id\" must be a non-blank string");
        }

        stampTimestamp(event, now);
        checkInitiatingEntity(event);
        normaliseReason(event, "reason_admin");
        normaliseReason(event, "reason_user");
        if (SsfEventTypes.isCaepInterop(eventType)) {
            checkInteropSubject(subject);
            if (!event.containsKey("reason_admin")) {
                event.put("reason_admin", CaepRiscEvents.reasonAdmin("raised by the transmitter's operator"));
            }
            if (!event.containsKey("initiating_entity")) {
                event.put("initiating_entity", "admin");
            }
        }
        if (SsfEventTypes.CAEP_CREDENTIAL_CHANGE.equals(eventType)) {
            checkCredentialChange(event);
        } else if (SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE.equals(eventType)) {
            checkDeviceComplianceChange(event);
        }
        return new EmitRequest(eventType, subject, event, (String) streamId);
    }

    private static String requireEventType(Object value) {
        if (!(value instanceof String) || !SsfEventTypes.isKnown((String) value)) {
            throw new IllegalArgumentException("\"event_type\" must be an event type this transmitter supports");
        }
        if (SsfEventTypes.VERIFICATION.equals(value)) {
            throw new IllegalArgumentException("the verification event is raised through the verification endpoint");
        }
        return (String) value;
    }

    /** CAEP 1.0 §2: {@code event_timestamp} is a number of seconds. Supplied as anything else, refused. */
    private static void stampTimestamp(Map<String, Object> event, long now) {
        Object given = event.get("event_timestamp");
        if (given == null) {
            event.put("event_timestamp", now);
        } else if (!(given instanceof Number)) {
            throw new IllegalArgumentException("\"event_timestamp\" must be a number (seconds since the epoch)");
        }
    }

    private static void checkInitiatingEntity(Map<String, Object> event) {
        Object given = event.get("initiating_entity");
        if (given != null && !CaepRiscEvents.INITIATING_ENTITIES.contains(given)) {
            throw new IllegalArgumentException("\"initiating_entity\" must be one of "
                    + CaepRiscEvents.INITIATING_ENTITIES);
        }
    }

    /**
     * A reason arrives as a sentence, which is tagged {@code en}, or as the language-tagged object CAEP
     * defines, which must be non-empty with string values. An empty object is refused rather than dropped:
     * the caller asked for a reason and sent none.
     */
    @SuppressWarnings("unchecked")
    private static void normaliseReason(Map<String, Object> event, String key) {
        Object given = event.get(key);
        if (given == null) {
            return;
        }
        if (given instanceof String) {
            Map<String, Object> tagged = CaepRiscEvents.reasonAdmin((String) given);
            if (tagged == null) {
                throw new IllegalArgumentException("\"" + key + "\" must not be blank");
            }
            event.put(key, tagged);
            return;
        }
        if (!(given instanceof Map) || ((Map<String, Object>) given).isEmpty()) {
            throw new IllegalArgumentException("\"" + key + "\" must be a sentence or a non-empty object of "
                    + "BCP 47 language tag to text");
        }
        for (Map.Entry<String, Object> entry : ((Map<String, Object>) given).entrySet()) {
            if (!(entry.getValue() instanceof String) || ((String) entry.getValue()).isBlank()) {
                throw new IllegalArgumentException("\"" + key + "\"." + entry.getKey() + " must be text");
            }
        }
    }

    /** CAEP Interop Profile §2.5: {@code opaque} is for the verification event only. */
    private static void checkInteropSubject(SubjectId subject) {
        if (!INTEROP_SUBJECT_FORMATS.contains(subject.format())) {
            throw new IllegalArgumentException("a CAEP Interop event's subject must be " + INTEROP_SUBJECT_FORMATS
                    + ", not " + subject.format());
        }
    }

    private static void checkCredentialChange(Map<String, Object> event) {
        requireOneOf(event, "credential_type", CaepRiscEvents.CREDENTIAL_TYPES);
        requireOneOf(event, "change_type", CaepRiscEvents.CHANGE_TYPES);
    }

    private static void checkDeviceComplianceChange(Map<String, Object> event) {
        requireOneOf(event, "previous_status", CaepRiscEvents.COMPLIANCE_STATUSES);
        requireOneOf(event, "current_status", CaepRiscEvents.COMPLIANCE_STATUSES);
    }

    private static void requireOneOf(Map<String, Object> event, String key, Set<String> allowed) {
        Object given = event.get(key);
        if (!(given instanceof String) || !allowed.contains(given)) {
            throw new IllegalArgumentException("\"" + key + "\" must be one of " + allowed);
        }
    }
}
