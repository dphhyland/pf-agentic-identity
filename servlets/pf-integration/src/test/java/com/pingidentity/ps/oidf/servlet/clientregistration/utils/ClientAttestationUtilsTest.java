package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * {@link ClientAttestationUtils#actingPartySub} — the RFC 8693 acting-party sub fallback (Phase 2.8),
 * extracted as a pure function specifically so it is unit-testable without mocking PF's
 * request/attribute types. The rest of {@link ClientAttestationUtils} has no test coverage of its own
 * (no Mockito dependency in this module, no HttpServletRequest/AttributeValue mocking precedent).
 */
class ClientAttestationUtilsTest {

    @Test
    void prefersAgentIdWhenPresent() {
        assertEquals("agent-id-1", ClientAttestationUtils.actingPartySub("agent-id-1", "https://rp.example.com"));
    }

    @Test
    void fallsBackToClientIdWhenAgentIdIsNull() {
        assertEquals("https://rp.example.com", ClientAttestationUtils.actingPartySub(null, "https://rp.example.com"));
    }

    @Test
    void fallsBackToClientIdWhenAgentIdIsBlank() {
        assertEquals("https://rp.example.com", ClientAttestationUtils.actingPartySub("   ", "https://rp.example.com"));
        assertEquals("https://rp.example.com", ClientAttestationUtils.actingPartySub("", "https://rp.example.com"));
    }
}
