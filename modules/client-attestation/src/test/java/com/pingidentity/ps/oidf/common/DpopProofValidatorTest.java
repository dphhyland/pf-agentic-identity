package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
}
