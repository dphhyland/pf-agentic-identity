package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.Test;

/** {@link ClientAttestation#fromVerifiedClaims} — agent_id parsing (Phase 2.6). */
class ClientAttestationTest {

    private static JwtClaims baseClaims() {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("https://attester.example.com");
        claims.setSubject("https://rp.example.com");
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600));
        claims.setClaim("cnf", Map.of("jwk", Map.of("kty", "EC")));
        return claims;
    }

    @Test
    void agentIdIsNullWhenTheClaimIsAbsent() throws Exception {
        ClientAttestation attestation = ClientAttestation.fromVerifiedClaims(baseClaims(), "raw.jwt");
        assertNull(attestation.agentId());
    }

    @Test
    void agentIdIsParsedWhenPresent() throws Exception {
        JwtClaims claims = baseClaims();
        claims.setClaim("agent_id", "agent-id-1");
        ClientAttestation attestation = ClientAttestation.fromVerifiedClaims(claims, "raw.jwt");
        assertEquals("agent-id-1", attestation.agentId());
    }

    @Test
    void agentIdDoesNotAffectClientIdOrOtherFields() throws Exception {
        JwtClaims claims = baseClaims();
        claims.setClaim("agent_id", "agent-id-2");
        ClientAttestation attestation = ClientAttestation.fromVerifiedClaims(claims, "raw.jwt");
        assertEquals("https://rp.example.com", attestation.clientId());
        assertEquals("https://attester.example.com", attestation.attesterIssuer());
    }
}
