package com.pingidentity.ps.oidf.rar;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Locks the Phase-1b contract: the exact {@code Map} shape published by
 * {@code ClientAttestationUtils.attestationContext(result)} in {@code pf-oidf-modules} must be parsed here.
 */
class AttestationSubjectTest {

    @Test
    void parsesTheHookAttributeShape() {
        // Mirror of ClientAttestationUtils.attestationContext(result).
        Map<String, Object> attr = new LinkedHashMap<>();
        attr.put("sub", "https://rp.example.com");
        attr.put("client_id", "https://rp.example.com");
        attr.put("entitlement", List.of(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"))));
        attr.put("cnf_thumbprint", "abc123");

        AttestationSubject s = AttestationSubject.fromAttribute(attr);

        assertTrue(s.isPresent());
        assertEquals("https://rp.example.com", s.getSubject());
        assertEquals("https://rp.example.com", s.getClientId());
        assertEquals(1, s.getEntitlement().size());
        assertEquals("sales_agent", s.getEntitlement().get(0).get("type"));
        assertEquals("abc123", s.getCnfThumbprint());
    }

    @Test
    void nullAttributeYieldsEmpty() {
        AttestationSubject s = AttestationSubject.fromAttribute(null);
        assertFalse(s.isPresent());
        assertTrue(s.getEntitlement().isEmpty());
        assertTrue(s.getWorkload().isEmpty());
    }

    @Test
    void fallsBackToAuthorizationDetailsKey() {
        Map<String, Object> attr = Map.of("authorization_details", List.of(Map.of("type", "payment_initiation")));
        AttestationSubject s = AttestationSubject.fromAttribute(attr);
        assertEquals(1, s.getEntitlement().size());
        assertEquals("payment_initiation", s.getEntitlement().get(0).get("type"));
    }
}
