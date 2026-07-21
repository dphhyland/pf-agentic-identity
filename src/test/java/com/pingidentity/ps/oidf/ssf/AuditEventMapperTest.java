/*
 * Audit-event mapping: success+subject gates, the default vocabulary, and auditEventMap overrides.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class AuditEventMapperTest {

    private final AuditEventMapper mapper = new AuditEventMapper();

    @Test
    void sloSuccessWithSubjectMapsToSessionRevoked() {
        Optional<AuditEventMapper.Mapped> m = mapper.map("SLO", "success", "bob");
        assertTrue(m.isPresent());
        assertEquals(AuditEventMapper.Action.SESSION_REVOKED, m.get().action());
        assertEquals("bob", m.get().subject());
        assertEquals("SLO", m.get().auditEvent());
    }

    @Test
    void failuresInProgressAndBlankSubjectsNeverMap() {
        assertTrue(mapper.map("SLO", "failure", "bob").isEmpty());       // e.g. invalid id_token_hint
        assertTrue(mapper.map("SLO", "inprogress", "bob").isEmpty());
        assertTrue(mapper.map("SLO", "success", "").isEmpty());          // pre-authn audit lines
        assertTrue(mapper.map("SLO", "success", null).isEmpty());
        assertTrue(mapper.map("SLO", null, "bob").isEmpty());
        assertTrue(mapper.map(null, "success", "bob").isEmpty());
    }

    @Test
    void unmappedEventsAreIgnored() {
        assertTrue(mapper.map("SSO", "success", "bob").isEmpty());       // sign-ON is not a revocation signal
        assertTrue(mapper.map("OAuth", "success", "client-1").isEmpty());
        assertTrue(mapper.map("AUTHN_ATTEMPT", "success", "bob").isEmpty());
    }

    @Test
    void eventNameAndStatusAreCaseInsensitive() {
        assertTrue(mapper.map("slo", "SUCCESS", "bob").isPresent());
    }

    @Test
    void overrideAddsRemovesAndRemaps() {
        AuditEventMapper m = new AuditEventMapper("PWD_CHANGE=credential-change, SLO=, SSO=session-revoked");
        assertEquals(AuditEventMapper.Action.CREDENTIAL_CHANGE, m.map("PWD_CHANGE", "success", "bob").get().action());
        assertTrue(m.map("SLO", "success", "bob").isEmpty());            // removed default
        assertEquals(AuditEventMapper.Action.SESSION_REVOKED, m.map("SSO", "success", "bob").get().action());
        assertEquals(AuditEventMapper.Action.SESSION_REVOKED,            // untouched default survives
                m.map("SRI_REVOKED", "success", "bob").get().action());
    }

    @Test
    void unknownOverrideActionIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> new AuditEventMapper("SLO=explode"));
    }
}
