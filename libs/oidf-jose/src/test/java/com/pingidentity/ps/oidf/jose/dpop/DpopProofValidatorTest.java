package com.pingidentity.ps.oidf.jose.dpop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.Test;

class DpopProofValidatorTest {
    private static final String HTU = "https://op.example.com/as/token.oauth2";
    private final DpopProofValidator validator = new DpopProofValidator(Set.of("ES256"), 60, 300L);

    private static JwtClaims dpopClaims(String htm, String htu, String jti) {
        JwtClaims c = new JwtClaims();
        if (htm != null) {
            c.setClaim("htm", htm);
        }
        if (htu != null) {
            c.setClaim("htu", htu);
        }
        if (jti != null) {
            c.setJwtId(jti);
        }
        c.setIssuedAtToNow();
        return c;
    }

    @Test
    void validProofIsAccepted() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("i1");
        String dpop = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", dpopClaims("POST", HTU, "j1"));
        DpopProof proof = validator.validate(dpop, "POST", HTU);
        assertEquals("j1", proof.jti());
        assertEquals("POST", proof.htm());
        assertNotNull(proof.jwk());
    }

    @Test
    void htuIgnoresQueryAndFragment() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("i1");
        String dpop = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", dpopClaims("POST", HTU + "?x=1#frag", "j1"));
        assertNotNull(validator.validate(dpop, "POST", HTU));
    }

    @Test
    void wrongMethodRejected() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("i1");
        String dpop = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", dpopClaims("GET", HTU, "j1"));
        assertThrows(Exception.class, () -> validator.validate(dpop, "POST", HTU));
    }

    @Test
    void wrongUriRejected() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("i1");
        String dpop = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", dpopClaims("POST", "https://evil.example.com/token", "j1"));
        assertThrows(Exception.class, () -> validator.validate(dpop, "POST", HTU));
    }

    @Test
    void wrongTypRejected() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("i1");
        String dpop = TestJwts.signWithJwkHeader(key, "ES256", "jwt", dpopClaims("POST", HTU, "j1"));
        assertThrows(Exception.class, () -> validator.validate(dpop, "POST", HTU));
    }

    @Test
    void missingJtiRejected() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("i1");
        String dpop = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", dpopClaims("POST", HTU, null));
        assertThrows(Exception.class, () -> validator.validate(dpop, "POST", HTU));
    }

    @Test
    void staleProofRejected() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("i1");
        JwtClaims c = dpopClaims("POST", HTU, "j1");
        c.setIssuedAt(NumericDate.fromSeconds(NumericDate.now().getValue() - 1000L));
        String dpop = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", c);
        assertThrows(Exception.class, () -> validator.validate(dpop, "POST", HTU));
    }

    @Test
    void tamperedSignatureRejected() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("i1");
        String dpop = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", dpopClaims("POST", HTU, "j1"));
        // Mutate a character within the payload segment, which changes the JWS signing input.
        int firstDot = dpop.indexOf('.');
        int secondDot = dpop.indexOf('.', firstDot + 1);
        int idx = (firstDot + secondDot) / 2;
        char c = dpop.charAt(idx);
        String tampered = dpop.substring(0, idx) + (c == 'a' ? 'b' : 'a') + dpop.substring(idx + 1);
        assertThrows(Exception.class, () -> validator.validate(tampered, "POST", HTU));
    }

    @Test
    void disallowedAlgorithmRejected() throws Exception {
        PublicJsonWebKey rsa = TestJwts.rsa("i1");
        String dpop = TestJwts.signWithJwkHeader(rsa, "RS256", "dpop+jwt", dpopClaims("POST", HTU, "j1"));
        assertThrows(Exception.class, () -> validator.validate(dpop, "POST", HTU)); // validator only permits ES256
    }

    /**
     * RFC 9449 §4.3, item 8: "The htm claim matches the HTTP method of the current request." RFC 9110 §9.1: "The method
     * token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method
     * names." Finding F-0226: this was compared without regard to case.
     */
    @Test
    @Requirement("RFC9449 §4.3")
    void theMethodIsComparedExactly() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("i1");
        String lower = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", dpopClaims("post", HTU, "j1"));
        Exception e = assertThrows(IllegalArgumentException.class, () -> validator.validate(lower, "POST", HTU));
        assertEquals("DPoP 'htm' mismatch: got 'post', expected 'POST'", e.getMessage());
        String upper = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", dpopClaims("POST", HTU, "j2"));
        assertThrows(IllegalArgumentException.class, () -> validator.validate(upper, "post", HTU));
        assertEquals("POST", validator.validate(upper, "POST", HTU).htm());
    }

    /** Every other way a proof is refused, and the members a proof may leave out. */
    @Test
    @Requirement("RFC9449 §4.3")
    void everyOtherRefusalAndTheOptionalMembers() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> new DpopProofValidator(Set.of(), 60, 300L));
        assertThrows(IllegalArgumentException.class, () -> new DpopProofValidator(null, 60, 300L));
        assertThrows(IllegalArgumentException.class, () -> validator.validate(null, "POST", HTU));
        assertThrows(IllegalArgumentException.class, () -> validator.validate(" ", "POST", HTU));

        PublicJsonWebKey key = TestJwts.ec("i1");
        // No jwk header, and one that is not an object.
        String noJwk = unsigned("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\"}", "{}");
        assertEquals("DPoP proof is missing the 'jwk' header",
                assertThrows(IllegalArgumentException.class, () -> validator.validate(noJwk, "POST", HTU)).getMessage());
        String stringJwk = unsigned("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":\"x\"}", "{}");
        assertThrows(IllegalArgumentException.class, () -> validator.validate(stringJwk, "POST", HTU));

        // Signed by another key than the one in the header.
        String signed = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", dpopClaims("POST", HTU, "j1"));
        String[] parts = signed.split("\\.");
        String other = TestJwts.signWithJwkHeader(TestJwts.ec("i2"), "ES256", "dpop+jwt", dpopClaims("POST", HTU, "j1"));
        String swapped = parts[0] + "." + parts[1] + "." + other.split("\\.")[2];
        assertEquals("DPoP proof signature did not verify",
                assertThrows(IllegalArgumentException.class, () -> validator.validate(swapped, "POST", HTU)).getMessage());

        // No iat.
        JwtClaims noIat = dpopClaims("POST", HTU, "j1");
        noIat.unsetClaim("iat");
        String withoutIat = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", noIat);
        assertEquals("DPoP proof is missing 'iat'",
                assertThrows(IllegalArgumentException.class, () -> validator.validate(withoutIat, "POST", HTU)).getMessage());

        // Too far in the future.
        JwtClaims future = dpopClaims("POST", HTU, "j1");
        future.setIssuedAt(NumericDate.fromSeconds(NumericDate.now().getValue() + 120L));
        String early = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", future);
        assertEquals("DPoP 'iat' is too far in the future",
                assertThrows(IllegalArgumentException.class, () -> validator.validate(early, "POST", HTU)).getMessage());

        // nonce and ath are carried when present; htm and htu are skipped when the caller gives none; a max age of 0
        // checks only the future side.
        JwtClaims full = dpopClaims("PATCH", "https://elsewhere.example/x", "j9");
        full.setClaim("nonce", "n1");
        full.setClaim("ath", "a1");
        full.setIssuedAt(NumericDate.fromSeconds(NumericDate.now().getValue() - 100_000L));
        String withAll = TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", full);
        DpopProof proof = new DpopProofValidator(Set.of("ES256"), 60, 0L).validate(withAll, null, null);
        assertEquals("n1", proof.nonce());
        assertEquals("a1", proof.ath());
        assertEquals("PATCH", proof.htm());
        assertEquals("https://elsewhere.example/x", proof.htu());
        assertEquals(withAll, proof.raw());
        assertEquals(full.getIssuedAt().getValue(), proof.iatEpochSeconds());
        DpopProof bare = validator.validate(signed, "POST", HTU);
        assertNull(bare.nonce());
        assertNull(bare.ath());
    }

    private static String unsigned(String header, String payload) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".c2ln";
    }
}
