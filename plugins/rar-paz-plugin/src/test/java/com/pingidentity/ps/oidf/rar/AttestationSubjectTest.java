package com.pingidentity.ps.oidf.rar;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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

    @Test
    void parsesAgentIdWhenPresent() {
        // Mirror of ClientAttestationUtils.attestationContext(result) with an agent_id minted (Phase 2.6).
        Map<String, Object> attr = new LinkedHashMap<>();
        attr.put("sub", "https://rp.example.com");
        attr.put("client_id", "https://rp.example.com");
        attr.put("agent_id", "agent-id-1");

        AttestationSubject s = AttestationSubject.fromAttribute(attr);
        assertEquals("agent-id-1", s.getAgentId());
    }

    @Test
    void parsesTheAttesterIssuerAndTheVerifiedSubjectTokenSubject() {
        Map<String, Object> attr = new LinkedHashMap<>();
        attr.put("client_id", "https://rp.example.com");
        attr.put("iss", "https://attester.example");
        attr.put(AttestationSubject.VERIFIED_SUBJECT_TOKEN_KEY, "alice");
        AttestationSubject s = AttestationSubject.fromAttribute(attr);
        assertEquals("https://attester.example", s.getAttesterIssuer());
        assertEquals("alice", s.getVerifiedSubjectTokenSubject());
        assertEquals("agent-9", s.withAgentId("agent-9").getAgentId());
        assertEquals("https://attester.example", s.withAgentId("agent-9").getAttesterIssuer());

        AttestationSubject blank = AttestationSubject.fromAttribute(Map.of("iss", " ", "sub", ""));
        assertNull(blank.getAttesterIssuer());
        assertNull(blank.getSubject());
        assertNull(AttestationSubject.empty().getVerifiedSubjectTokenSubject());
    }

    /**
     * Whether a context is there at all, and the fingerprint of the RAR model set the filter checked the request
     * with (S1b publishes it, S1c compares it). A context that is not a map is there and says nothing.
     */
    @Test
    void readsWhetherAContextIsThereAndItsModelsFingerprint() {
        String fingerprint = "ab".repeat(32);
        AttestationSubject published = AttestationSubject.fromAttribute(Map.of("client_id", "c",
                AttestationSubject.RAR_MODELS_FINGERPRINT_KEY, fingerprint, "workload", Map.of("spiffe_id", "spiffe://x/y")));
        assertTrue(published.isContextPresent());
        assertEquals(Map.of("spiffe_id", "spiffe://x/y"), published.getWorkload());
        assertEquals(fingerprint, published.getRarModelsFingerprint());
        assertEquals(fingerprint, published.withAgentId("agent-1").getRarModelsFingerprint());
        assertTrue(published.withAgentId("agent-1").isContextPresent());

        for (Object absent : new Object[] {null, " ", 42}) {
            Map<String, Object> attr = new LinkedHashMap<>();
            attr.put("client_id", "c");
            attr.put(AttestationSubject.RAR_MODELS_FINGERPRINT_KEY, absent);
            AttestationSubject s = AttestationSubject.fromAttribute(attr);
            assertTrue(s.isContextPresent());
            assertNull(s.getRarModelsFingerprint(), String.valueOf(absent));
        }

        assertFalse(AttestationSubject.fromAttribute(null).isContextPresent());
        assertFalse(AttestationSubject.empty().isContextPresent());
        AttestationSubject unreadable = AttestationSubject.fromAttribute("not a map");
        assertTrue(unreadable.isContextPresent());
        assertNull(unreadable.getRarModelsFingerprint());
        assertNull(unreadable.getClientId());
        assertFalse(new AttestationSubject("s", "c", List.of(), Map.of(), null).isContextPresent(),
                "a subject built by hand, as the builders' tests do, is not a published context");
    }

    @Test
    void agentIdIsNullWhenNotPublished() {
        Map<String, Object> attr = Map.of("sub", "https://rp.example.com", "client_id", "https://rp.example.com");
        AttestationSubject s = AttestationSubject.fromAttribute(attr);
        assertNull(s.getAgentId());
    }
}
