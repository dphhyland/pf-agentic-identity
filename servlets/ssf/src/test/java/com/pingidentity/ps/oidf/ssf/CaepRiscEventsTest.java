/*
 * CAEP/RISC event payload shapes.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CaepRiscEventsTest {

    /**
     * CAEP 1.0 §2 defines the reason as an object keyed by language tag, and CAEPIOP §3.1 wants it
     * non-empty on session-revoked. A plain sentence is tagged English; nothing is not sent at all.
     */
    @Test
    @Requirement({"CAEP §2", "CAEP §3.1", "CAEPIOP §3.1"})
    void sessionRevokedCarriesTimestampAndALanguageTaggedReason() {
        Map<String, Object> p = CaepRiscEvents.sessionRevoked(1000L, "admin revoke");
        assertEquals(1000L, p.get("event_timestamp"));
        assertEquals(Map.of("en", "admin revoke"), p.get("reason_admin"));
        assertFalse(CaepRiscEvents.sessionRevoked(1000L, (String) null).containsKey("reason_admin"));
        assertFalse(CaepRiscEvents.sessionRevoked(1000L, " ").containsKey("reason_admin"));
    }

    @Test
    @Requirement("CAEP §2")
    void aReasonThatArrivesTaggedIsSentAsGivenAndAnEmptyOneIsOmitted() {
        Map<String, Object> translated = Map.of("en", "revoked", "de", "widerrufen");
        assertEquals(translated, CaepRiscEvents.sessionRevoked(1L, translated).get("reason_admin"));
        assertFalse(CaepRiscEvents.sessionRevoked(1L, Map.of()).containsKey("reason_admin"));
        assertNull(CaepRiscEvents.reasonAdmin(null));
        assertEquals(Map.of("en", "x"), CaepRiscEvents.reasonAdmin("x"));
    }

    @Test
    @Requirement("CAEP §3.3")
    void credentialChangeCarriesTypeAndChange() {
        Map<String, Object> p = CaepRiscEvents.credentialChange(1000L, "password", "update");
        assertEquals("password", p.get("credential_type"));
        assertEquals("update", p.get("change_type"));
        assertEquals(1000L, p.get("event_timestamp"));
        assertFalse(p.containsKey("reason_admin"));
        assertEquals(Map.of("en", "rotated"),
                CaepRiscEvents.credentialChange(1000L, "password", "update", Map.of("en", "rotated")).get("reason_admin"));
    }

    @Test
    @Requirement({"CAEP §3.5", "CAEPIOP §3.3"})
    void deviceComplianceChangeCarriesBothStatusesAndTheReason() {
        Map<String, Object> p = CaepRiscEvents.deviceComplianceChange(1000L, "compliant", "not-compliant",
                Map.of("en", "disk encryption off"));
        assertEquals("compliant", p.get("previous_status"));
        assertEquals("not-compliant", p.get("current_status"));
        assertEquals(1000L, p.get("event_timestamp"));
        assertEquals(Map.of("en", "disk encryption off"), p.get("reason_admin"));
    }

    @Test
    void accountDisabledAndEnabled() {
        assertEquals("hijacking", CaepRiscEvents.accountDisabled(1000L, "hijacking").get("reason"));
        assertFalse(CaepRiscEvents.accountEnabled(1000L).containsKey("reason"));
    }

    @Test
    @Requirement("CAEP §3.4")
    void assuranceChangeDirection() {
        assertEquals("increase", CaepRiscEvents.assuranceLevelChange(1000L, "nist-aal1", "nist-aal2").get("change_direction"));
        assertEquals("decrease", CaepRiscEvents.assuranceLevelChange(1000L, "nist-aal2", "nist-aal1").get("change_direction"));
    }
}
