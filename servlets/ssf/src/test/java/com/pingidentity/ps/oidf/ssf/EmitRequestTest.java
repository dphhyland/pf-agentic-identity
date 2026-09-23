/*
 * What the transmitter will and will not sign when an operator asks.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EmitRequestTest {

    private static final long NOW = 1_700_000_000L;
    private static final Map<String, Object> ALICE = Map.of("format", "email", "email", "alice@example.com");

    private static Map<String, Object> body(String type, Map<String, Object> subject, Map<String, Object> event) {
        LinkedHashMap<String, Object> b = new LinkedHashMap<>();
        b.put("event_type", type);
        b.put("subject", subject);
        if (event != null) {
            b.put("event", event);
        }
        return b;
    }

    private static Map<String, Object> mutable(Map<String, Object> m) {
        return new HashMap<>(m);
    }

    private static String refused(Map<String, Object> body) {
        return assertThrows(IllegalArgumentException.class, () -> EmitRequest.parse(body, NOW)).getMessage();
    }

    // ─────────────────────────────── shape ───────────────────────────────

    @Test
    void aWellFormedInteropEventIsAcceptedAndCompleted() {
        EmitRequest r = EmitRequest.parse(body(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, ALICE,
                mutable(Map.of("credential_type", "password", "change_type", "update", "reason_admin", "rotated"))), NOW);

        assertEquals(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, r.eventType());
        assertEquals(SubjectId.email("alice@example.com"), r.subject());
        assertEquals(NOW, r.payload().get("event_timestamp"));
        assertEquals(Map.of("en", "rotated"), r.payload().get("reason_admin"));
        assertEquals("admin", r.payload().get("initiating_entity"));
        assertNull(r.streamId());
    }

    @Test
    void theBodyTheEventTypeAndTheSubjectAreRequired() {
        assertTrue(refused(null).contains("body"));
        assertTrue(refused(Map.of("subject", ALICE)).contains("event_type"));
        assertTrue(refused(body("https://schemas.example/not-an-event", ALICE, null)).contains("event_type"));
        assertTrue(refused(body(SsfEventTypes.RISC_ACCOUNT_ENABLED, null, null)).contains("subject"));
        assertTrue(refused(body(SsfEventTypes.RISC_ACCOUNT_ENABLED, Map.of("format", "email"), null)).contains("email"));
        LinkedHashMap<String, Object> eventNotAnObject = new LinkedHashMap<>(body(SsfEventTypes.RISC_ACCOUNT_ENABLED, ALICE, null));
        eventNotAnObject.put("event", "text");
        assertTrue(refused(eventNotAnObject).contains("event"));
    }

    @Test
    void theVerificationEventHasItsOwnEndpoint() {
        assertTrue(refused(body(SsfEventTypes.VERIFICATION, ALICE, null)).contains("verification endpoint"));
    }

    @Test
    void streamIdIsOptionalAndOtherwiseANonBlankString() {
        LinkedHashMap<String, Object> b = new LinkedHashMap<>(body(SsfEventTypes.RISC_ACCOUNT_ENABLED, ALICE, null));
        b.put("stream_id", "s1");
        assertEquals("s1", EmitRequest.parse(b, NOW).streamId());
        b.put("stream_id", " ");
        assertTrue(refused(b).contains("stream_id"));
        b.put("stream_id", 7);
        assertTrue(refused(b).contains("stream_id"));
    }

    // ─────────────────────────────── common CAEP members ───────────────────────────────

    @Test
    @Requirement("CAEP §2")
    void theTimestampIsStampedUnlessANumberWasSupplied() {
        assertEquals(NOW, EmitRequest.parse(body(SsfEventTypes.RISC_ACCOUNT_ENABLED, ALICE, null), NOW)
                .payload().get("event_timestamp"));
        assertEquals(5L, EmitRequest.parse(body(SsfEventTypes.RISC_ACCOUNT_ENABLED, ALICE,
                mutable(Map.of("event_timestamp", 5L))), NOW).payload().get("event_timestamp"));
        assertTrue(refused(body(SsfEventTypes.RISC_ACCOUNT_ENABLED, ALICE,
                mutable(Map.of("event_timestamp", "yesterday")))).contains("event_timestamp"));
    }

    @Test
    @Requirement("CAEP §2")
    void initiatingEntityTakesOnlyItsFourValues() {
        assertEquals("policy", EmitRequest.parse(body(SsfEventTypes.RISC_ACCOUNT_ENABLED, ALICE,
                mutable(Map.of("initiating_entity", "policy"))), NOW).payload().get("initiating_entity"));
        assertTrue(refused(body(SsfEventTypes.RISC_ACCOUNT_ENABLED, ALICE,
                mutable(Map.of("initiating_entity", "robot")))).contains("initiating_entity"));
        assertFalse(EmitRequest.parse(body(SsfEventTypes.RISC_ACCOUNT_ENABLED, ALICE, null), NOW)
                .payload().containsKey("initiating_entity"), "defaulted for interop events only");
        assertEquals("user", EmitRequest.parse(body(SsfEventTypes.CAEP_SESSION_REVOKED, ALICE,
                mutable(Map.of("initiating_entity", "user"))), NOW).payload().get("initiating_entity"),
                "an interop event keeps the entity it was given");
    }

    @Test
    @Requirement({"CAEP §2", "CAEPIOP §3.1"})
    void aReasonIsASentenceOrANonEmptyTaggedObject() {
        Map<String, Object> ok = mutable(Map.of("reason_admin", Map.of("en", "a", "fr", "b"), "reason_user", "yours"));
        EmitRequest r = EmitRequest.parse(body(SsfEventTypes.CAEP_SESSION_REVOKED, ALICE, ok), NOW);
        assertEquals(Map.of("en", "a", "fr", "b"), r.payload().get("reason_admin"));
        assertEquals(Map.of("en", "yours"), r.payload().get("reason_user"));

        assertTrue(refused(body(SsfEventTypes.CAEP_SESSION_REVOKED, ALICE, mutable(Map.of("reason_admin", " "))))
                .contains("blank"));
        assertTrue(refused(body(SsfEventTypes.CAEP_SESSION_REVOKED, ALICE, mutable(Map.of("reason_admin", Map.of()))))
                .contains("non-empty"));
        assertTrue(refused(body(SsfEventTypes.CAEP_SESSION_REVOKED, ALICE, mutable(Map.of("reason_admin", 3))))
                .contains("non-empty"));
        assertTrue(refused(body(SsfEventTypes.CAEP_SESSION_REVOKED, ALICE, mutable(Map.of("reason_admin", Map.of("en", 1)))))
                .contains("must be text"));
        assertTrue(refused(body(SsfEventTypes.CAEP_SESSION_REVOKED, ALICE, mutable(Map.of("reason_admin", Map.of("en", "")))))
                .contains("must be text"));
    }

    @Test
    @Requirement({"CAEPIOP §3.1", "CAEPIOP §3.3"})
    void anInteropEventWithoutAReasonGetsOneRatherThanGoingOutWithout() {
        Map<String, Object> p = EmitRequest.parse(body(SsfEventTypes.CAEP_SESSION_REVOKED, ALICE, null), NOW).payload();
        @SuppressWarnings("unchecked")
        Map<String, Object> reason = (Map<String, Object>) p.get("reason_admin");
        assertFalse(reason.isEmpty());
        assertTrue(reason.get("en") instanceof String);
    }

    // ─────────────────────────────── the interop profile's rules ───────────────────────────────

    @Test
    @Requirement("CAEPIOP §2.5")
    void anInteropEventsSubjectIsEmailOrIssSubAndNeverOpaque() {
        Map<String, Object> opaque = Map.of("format", "opaque", "id", "x");
        assertTrue(refused(body(SsfEventTypes.CAEP_SESSION_REVOKED, opaque, null)).contains("opaque"));
        assertTrue(refused(body(SsfEventTypes.CAEP_SESSION_REVOKED, Map.of("format", "phone_number", "phone_number", "+61"), null))
                .contains("phone_number"));
        assertEquals("iss_sub", EmitRequest.parse(body(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE,
                Map.of("format", "iss_sub", "iss", "https://op", "sub", "u"),
                mutable(Map.of("previous_status", "compliant", "current_status", "not-compliant"))), NOW).subject().format());
        // a RISC event is not profiled: opaque stays acceptable there
        assertEquals("opaque", EmitRequest.parse(body(SsfEventTypes.RISC_ACCOUNT_DISABLED, opaque, null), NOW).subject().format());
    }

    @Test
    @Requirement({"CAEP §3.3", "CAEPIOP §3.2"})
    void credentialChangeTakesOnlyDefinedTypesAndChanges() {
        for (String type : CaepRiscEvents.CREDENTIAL_TYPES) {
            for (String change : CaepRiscEvents.CHANGE_TYPES) {
                EmitRequest.parse(body(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, ALICE,
                        mutable(Map.of("credential_type", type, "change_type", change))), NOW);
            }
        }
        assertTrue(refused(body(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, ALICE, mutable(Map.of("change_type", "update"))))
                .contains("credential_type"));
        assertTrue(refused(body(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, ALICE,
                mutable(Map.of("credential_type", "credential", "change_type", "update")))).contains("credential_type"));
        assertTrue(refused(body(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, ALICE,
                mutable(Map.of("credential_type", "password", "change_type", "rotate")))).contains("change_type"));
        assertTrue(refused(body(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, ALICE,
                mutable(Map.of("credential_type", "password", "change_type", List.of("update"))))).contains("change_type"));
    }

    @Test
    @Requirement({"CAEP §3.5", "CAEPIOP §3.3"})
    void deviceComplianceChangeTakesOnlyTheTwoStatuses() {
        EmitRequest r = EmitRequest.parse(body(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE, ALICE,
                mutable(Map.of("previous_status", "compliant", "current_status", "not-compliant"))), NOW);
        assertEquals("not-compliant", r.payload().get("current_status"));
        assertTrue(refused(body(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE, ALICE,
                mutable(Map.of("current_status", "not-compliant")))).contains("previous_status"));
        assertTrue(refused(body(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE, ALICE,
                mutable(Map.of("previous_status", "compliant", "current_status", "unknown")))).contains("current_status"));
    }

    @Test
    void membersThisTransmitterDoesNotKnowPassThroughUntouched() {
        Map<String, Object> p = EmitRequest.parse(body(SsfEventTypes.CAEP_SESSION_REVOKED, ALICE,
                mutable(Map.of("txn", "abc", "ext", Map.of("k", "v")))), NOW).payload();
        assertEquals("abc", p.get("txn"));
        assertEquals(Map.of("k", "v"), p.get("ext"));
    }
}
