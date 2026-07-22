package com.pingidentity.ps.oidf.common;

import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class ClientAttestationSdJwtTest {

    private JwtClaims issuer(Object authorizationDetails) {
        JwtClaims c = new JwtClaims();
        c.setIssuer("https://attester.example.com");
        c.setSubject("https://rp.example.com");
        c.setClaim("cnf", Map.of("jwk", Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def")));
        c.setExpirationTimeMinutesInTheFuture(10);
        c.setClaim("authorization_details", authorizationDetails);
        return c;
    }

    @Test
    void buildsAttestationFromDisclosedEntitlement() throws Exception {
        Map<String, Object> entry = Map.of("type", "sales_agent", "sales_regions", List.of("EMEA", "APAC"));
        String d = SdJwt.arrayDisclosure("salt", entry);
        JwtClaims issuer = issuer(List.of(Map.of("...", SdJwt.digest(d))));

        ClientAttestation att = ClientAttestation.fromSdJwt(issuer, List.of(d), "raw");

        assertEquals("https://rp.example.com", att.clientId());
        assertEquals("https://attester.example.com", att.attesterIssuer());
        assertFalse(att.cnfJwk().isEmpty());
        assertEquals(1, att.authorizationDetails().size());
        assertEquals("sales_agent", att.authorizationDetails().get(0).get("type"));
    }

    @Test
    void undisclosedEntitlementEntriesAreAbsent() throws Exception {
        Map<String, Object> emea = Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"));
        Map<String, Object> amer = Map.of("type", "sales_agent", "sales_regions", List.of("AMER"));
        String dEmea = SdJwt.arrayDisclosure("s1", emea);
        String dAmer = SdJwt.arrayDisclosure("s2", amer);
        JwtClaims issuer = issuer(List.of(Map.of("...", SdJwt.digest(dEmea)), Map.of("...", SdJwt.digest(dAmer))));

        // client discloses only the EMEA entitlement to this AS
        ClientAttestation att = ClientAttestation.fromSdJwt(issuer, List.of(dEmea), "raw");

        assertEquals(1, att.authorizationDetails().size());
        assertEquals(List.of("EMEA"), att.authorizationDetails().get(0).get("sales_regions"));
    }
}
