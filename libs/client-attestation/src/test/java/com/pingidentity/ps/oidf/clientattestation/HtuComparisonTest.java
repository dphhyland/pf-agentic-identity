package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.Set;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * How a DPoP proof's {@code htu} is compared with the endpoint it must name.
 *
 * <p>RFC 9449 §4.3, item 9: "The htu claim matches the HTTP URI value for the HTTP request in which the JWT was
 * received, ignoring any query and fragment parts." And after the list: "To reduce the likelihood of false
 * negatives, servers SHOULD employ syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based
 * normalization (Section 6.2.3 of [RFC3986]) before comparing the htu claim."
 *
 * <p>RFC 3986 §6.2.2.1: "the hexadecimal digits within a percent-encoding triplet (e.g., "%3a" versus "%3A") are
 * case-insensitive and therefore should be normalized to use uppercase letters for the digits A-F" and "the scheme
 * and host are case-insensitive and therefore should be normalized to lowercase"; §6.2.2.2: URIs "should be
 * normalized by decoding any percent-encoded octet that corresponds to an unreserved character"; §6.2.2.3: "URI
 * normalizers should remove dot-segments by applying the remove_dot_segments algorithm to the path"; §6.2.3: "a
 * URI that uses the generic syntax for authority with an empty path should be normalized to a path of "/".
 * Likewise, an explicit ":port", for which the port is empty or the default for the scheme, is equivalent to one
 * where the port and its ":" delimiter are elided". Nothing else is normalised away: "The other generic syntax
 * components are assumed to be case-sensitive" (§6.2.2.1).
 */
class HtuComparisonTest {
    private static final String ENDPOINT = "https://as.example.com/as/token.oauth2";

    private static void same(String htu) {
        assertDoesNotThrow(() -> DpopProofValidator.requireHtu(htu, ENDPOINT), htu);
    }

    private static void different(String htu) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> DpopProofValidator.requireHtu(htu, ENDPOINT), htu);
        assertTrue(e.getMessage().contains("DPoP 'htu' mismatch"), e.getMessage());
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void theEndpointItselfMatches() {
        same(ENDPOINT);
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void queryAndFragmentAreIgnored() {
        same(ENDPOINT + "?x=1");
        same(ENDPOINT + "#frag");
        same(ENDPOINT + "?x=1#frag");
        same(ENDPOINT + "?");
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void theSchemeAndHostAreCaseInsensitive() {
        same("HTTPS://AS.Example.COM/as/token.oauth2");
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void anEmptyOrDefaultPortIsNoPort() {
        same("https://as.example.com:443/as/token.oauth2");
        same("https://as.example.com:/as/token.oauth2");
        assertEquals("http://as.example.com/x", DpopProofValidator.normalizeHtu("http://as.example.com:80/x"));
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void anyOtherPortCounts() {
        different("https://as.example.com:8443/as/token.oauth2");
        assertEquals("http://as.example.com:443/x", DpopProofValidator.normalizeHtu("http://as.example.com:443/x"));
        assertEquals("https://as.example.com:80/x", DpopProofValidator.normalizeHtu("https://as.example.com:80/x"));
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void anEmptyPathIsSlash() {
        assertEquals(DpopProofValidator.normalizeHtu("https://as.example.com/"),
                DpopProofValidator.normalizeHtu("https://as.example.com"));
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void percentEncodedUnreservedCharactersAreDecoded() {
        same("https://as.example.com/as/%74oken.oauth2");                 // t
        same("https://as.example.com/%61%73/token%2Eoauth2");              // a s .
        assertEquals("https://h.example/aZ09-._~",
                DpopProofValidator.normalizeHtu("https://h.example/%61%5A%30%39%2D%2E%5F%7E"));
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void otherPercentEncodingsKeepTheirMeaningInUpperCase() {
        assertEquals(DpopProofValidator.normalizeHtu("https://h.example/a%2Fb"),
                DpopProofValidator.normalizeHtu("https://h.example/a%2fb"));
        assertEquals("https://h.example/a%2Fb", DpopProofValidator.normalizeHtu("https://h.example/a%2fb"));
        // An encoded "/" is data, not a separator: it is not the path "/a/b".
        different("https://as.example.com/as%2Ftoken.oauth2");
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void dotSegmentsAreRemoved() {
        same("https://as.example.com/as/./token.oauth2");
        same("https://as.example.com/x/../as/token.oauth2");
        same("https://as.example.com/../as/token.oauth2");
        // Decoded first, so an encoded dot segment is one.
        same("https://as.example.com/x/%2E%2E/as/token.oauth2");
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void theUserInfoAPathOfAnotherCaseAndATrailingSlashAllCount() {
        different("https://someone@as.example.com/as/token.oauth2");
        different("https://as.example.com/AS/token.oauth2");
        different("https://as.example.com/as/token.oauth2/");
        assertEquals("https://us%3Aer@h.example/", DpopProofValidator.normalizeHtu("https://us%3aer@h.example"));
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void anotherServerSchemeOrPathIsRefused() {
        different("https://other-bank.example/as/token.oauth2");
        different("http://as.example.com/as/token.oauth2");
        different("https://as.example.com/as/par.oauth2");
        different("https://as.example.com.other-bank.example/as/token.oauth2");
    }

    /** An htu that is not an absolute http or https URI with a host names no endpoint of this server. */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void anHtuThatIsNotAnAbsoluteHttpUriIsRefused() {
        different("/as/token.oauth2");
        different("urn:example:token");
        different("ftp://as.example.com/as/token.oauth2");
        different("https:///as/token.oauth2");
        different("https://as.example.com/as/token oauth2");
        different("https://as.example.com/as/%zztoken.oauth2");
        assertNull(DpopProofValidator.normalizeHtu(null));
    }

    @Test
    void anExpectedEndpointThatIsNotAnAbsoluteHttpUriIsThisServersMisconfiguration() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> DpopProofValidator.requireHtu(ENDPOINT, "/as/token.oauth2"));
        assertTrue(e.getMessage().contains("expected DPoP 'htu' is not an absolute"), e.getMessage());
    }

    /** RFC 3986 §5.2.4's own two examples, and each of its steps A to E. */
    @Test
    void removeDotSegmentsIsTheRfcsAlgorithm() {
        assertEquals("/a/g", DpopProofValidator.removeDotSegments("/a/b/c/./../../g"));
        assertEquals("mid/6", DpopProofValidator.removeDotSegments("mid/content=5/../6"));
        assertEquals("a", DpopProofValidator.removeDotSegments("../a"));        // A
        assertEquals("a", DpopProofValidator.removeDotSegments("./a"));         // A
        assertEquals("/a", DpopProofValidator.removeDotSegments("/./a"));       // B
        assertEquals("/", DpopProofValidator.removeDotSegments("/."));          // B
        assertEquals("/b", DpopProofValidator.removeDotSegments("/a/../b"));    // C
        assertEquals("/", DpopProofValidator.removeDotSegments("/a/.."));       // C
        assertEquals("/", DpopProofValidator.removeDotSegments("/.."));         // C, nothing to remove
        assertEquals("", DpopProofValidator.removeDotSegments("."));            // D
        assertEquals("", DpopProofValidator.removeDotSegments(".."));           // D
        assertEquals("//a/.b/..c", DpopProofValidator.removeDotSegments("//a/.b/..c")); // E, empty segments kept
        assertEquals("", DpopProofValidator.removeDotSegments(""));
    }

    /** Through the validator: the comparison is the one {@link DpopProofValidator#validate} applies. */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void theValidatorComparesTheSameWay() throws Exception {
        DpopProofValidator validator = new DpopProofValidator(Set.of("ES256"), 60, 300L);
        PublicJsonWebKey key = TestJwts.ec("i1");

        assertEquals("j1", validator.validate(proof(key, "HTTPS://as.example.com:443/as/./token.oauth2?q#f", "j1"),
                "POST", ENDPOINT).jti());
        assertThrows(IllegalArgumentException.class,
                () -> validator.validate(proof(key, "https://someone@as.example.com/as/token.oauth2", "j2"), "POST", ENDPOINT));
    }

    private static String proof(PublicJsonWebKey key, String htu, String jti) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setClaim("htm", "POST");
        c.setClaim("htu", htu);
        c.setJwtId(jti);
        c.setIssuedAtToNow();
        return TestJwts.signWithJwkHeader(key, "ES256", "dpop+jwt", c);
    }
}
