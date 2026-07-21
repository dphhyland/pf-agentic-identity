package com.pingidentity.ps.oidf.common;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SdJwtTest {

    @Test
    void reconstructsDisclosedObjectProperty() {
        String d = SdJwt.objectDisclosure("salt1", "software_id", "pf-oidf-demo");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "https://attester.example.com");
        payload.put("_sd_alg", "sha-256");
        payload.put("_sd", List.of(SdJwt.digest(d)));

        Map<String, Object> out = SdJwt.reconstruct(payload, List.of(d));

        assertEquals("pf-oidf-demo", out.get("software_id"));
        assertEquals("https://attester.example.com", out.get("iss"));
        assertFalse(out.containsKey("_sd"));
        assertFalse(out.containsKey("_sd_alg"));
    }

    @Test
    void reconstructsDisclosedArrayElement() {
        Map<String, Object> entry = Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"));
        String d = SdJwt.arrayDisclosure("salt2", entry);
        Map<String, Object> payload = new LinkedHashMap<>();
        List<Object> authz = new ArrayList<>();
        authz.add(Map.of("...", SdJwt.digest(d)));
        payload.put("authorization_details", authz);

        Map<String, Object> out = SdJwt.reconstruct(payload, List.of(d));

        List<?> outAuthz = (List<?>) out.get("authorization_details");
        assertEquals(1, outAuthz.size());
        assertEquals("sales_agent", ((Map<?, ?>) outAuthz.get(0)).get("type"));
    }

    @Test
    void omitsUndisclosedClaims() {
        String shown = SdJwt.objectDisclosure("s", "software_id", "x");
        String hidden = SdJwt.objectDisclosure("s", "instance_id", "secret-host-id");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("_sd", List.of(SdJwt.digest(shown), SdJwt.digest(hidden)));

        Map<String, Object> out = SdJwt.reconstruct(payload, List.of(shown)); // only 'shown' disclosed

        assertEquals("x", out.get("software_id"));
        assertFalse(out.containsKey("instance_id"));
    }

    @Test
    void rejectsDisclosureWithNoMatchingDigest() {
        String inSd = SdJwt.objectDisclosure("s", "a", "1");
        String stray = SdJwt.objectDisclosure("s", "b", "2");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("_sd", List.of(SdJwt.digest(inSd)));

        assertThrows(SdJwtException.class, () -> SdJwt.reconstruct(payload, List.of(inSd, stray)));
    }

    @Test
    void parseSplitsPresentation() {
        SdJwt.Parsed p = SdJwt.parse("ISS~D1~D2~");
        assertEquals("ISS", p.issuerJwt());
        assertEquals(2, p.disclosures().size());
        assertNull(p.kbJwt());

        SdJwt.Parsed p2 = SdJwt.parse("ISS~D1~KB");
        assertEquals("KB", p2.kbJwt());
        assertEquals(1, p2.disclosures().size());
    }
}
