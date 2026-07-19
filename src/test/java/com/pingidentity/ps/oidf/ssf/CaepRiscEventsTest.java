/*
 * CAEP/RISC event payload shapes.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Map;
import org.junit.jupiter.api.Test;

class CaepRiscEventsTest {

    @Test
    void sessionRevokedCarriesTimestampAndOptionalReason() {
        Map<String, Object> p = CaepRiscEvents.sessionRevoked(1000L, "admin revoke");
        assertEquals(1000L, p.get("event_timestamp"));
        assertEquals("admin revoke", p.get("reason_admin"));
        assertFalse(CaepRiscEvents.sessionRevoked(1000L, null).containsKey("reason_admin"));
    }

    @Test
    void credentialChangeCarriesTypeAndChange() {
        Map<String, Object> p = CaepRiscEvents.credentialChange(1000L, "password", "update");
        assertEquals("password", p.get("credential_type"));
        assertEquals("update", p.get("change_type"));
        assertEquals(1000L, p.get("event_timestamp"));
    }

    @Test
    void accountDisabledAndEnabled() {
        assertEquals("hijacking", CaepRiscEvents.accountDisabled(1000L, "hijacking").get("reason"));
        assertFalse(CaepRiscEvents.accountEnabled(1000L).containsKey("reason"));
    }

    @Test
    void assuranceChangeDirection() {
        assertEquals("increase", CaepRiscEvents.assuranceLevelChange(1000L, "nist-aal1", "nist-aal2").get("change_direction"));
        assertEquals("decrease", CaepRiscEvents.assuranceLevelChange(1000L, "nist-aal2", "nist-aal1").get("change_direction"));
    }
}
