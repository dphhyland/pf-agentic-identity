/*
 * The two FAPI 2.0 decisions, on JWTs built by hand so that each is wrong in exactly one way.
 */
package com.pingidentity.ps.oidf.servlet.fapi2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.servlet.fapi2.Fapi2RequestPolicy.Violation;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * None of these JWTs is signed, and none needs to be: the policy never looks at a signature, and says
 * why. What it must never do is let through something it could not read, so the unreadable cases
 * matter as much as the wrong ones.
 */
class Fapi2RequestPolicyTest {

    private static final String ISSUER = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = ISSUER + "/as/token.oauth2";

    static String jwt(String headerJson, String payloadJson) {
        return b64(headerJson) + "." + b64(payloadJson) + "." + b64("not-a-signature");
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String assertionWithAud(String audJson) {
        return jwt("{\"alg\":\"PS256\"}", "{\"iss\":\"c\",\"sub\":\"c\",\"aud\":" + audJson + "}");
    }

    // ─────────────────────────────── client assertion audience ───────────────────────────────

    @Test
    @Requirement("FAPI2-SP §5.3.2.1(2.8)")
    void theIssuerAsAStringIsTheOnlyAudienceAccepted() {
        assertNull(Fapi2RequestPolicy.checkClientAssertion(assertionWithAud("\"" + ISSUER + "\""), ISSUER));
    }

    /** The three the OpenID conformance suite sends, each of which PingFederate 13.0.3 accepts. */
    @Test
    @Requirement("FAPI2-SP §5.3.2.1(2.8)")
    void theAudiencesPingFederateWouldHaveAcceptedAreRefused() {
        for (String aud : List.of(
                "\"" + TOKEN_ENDPOINT + "\"",
                "\"" + ISSUER + "/as/par.oauth2\"",
                "[\"" + ISSUER + "\",\"" + TOKEN_ENDPOINT + "\"]")) {
            Violation v = Fapi2RequestPolicy.checkClientAssertion(assertionWithAud(aud), ISSUER);
            assertNotNull(v, aud);
            assertEquals("invalid_client", v.error);
        }
    }

    /** "As a string": the right value in an array of one is still an array. */
    @Test
    @Requirement("FAPI2-SP §5.3.2.1(2.8)")
    void theIssuerAloneInAnArrayIsRefused() {
        assertNotNull(Fapi2RequestPolicy.checkClientAssertion(assertionWithAud("[\"" + ISSUER + "\"]"), ISSUER));
    }

    @Test
    @Requirement("FAPI2-SP §5.3.2.1(2.8)")
    void anIssuerThatOnlyResemblesThisOneIsRefused() {
        for (String aud : List.of("\"" + ISSUER + "/\"", "\"" + ISSUER.toUpperCase() + "\"", "\"https://as.example.com.evil.test\"",
                "\"\"", "null", "42")) {
            assertNotNull(Fapi2RequestPolicy.checkClientAssertion(assertionWithAud(aud), ISSUER), aud);
        }
        assertNotNull(Fapi2RequestPolicy.checkClientAssertion(jwt("{\"alg\":\"PS256\"}", "{\"iss\":\"c\"}"), ISSUER),
                "no aud at all");
    }

    /**
     * Refused, not passed on for PingFederate to read its own way: that is the whole defence against an
     * assertion the two would parse differently.
     */
    @Test
    void anAssertionThatCannotBeReadIsRefused() {
        for (String assertion : List.of("", "   ", "not-a-jwt", "a.b", "a.b.c.d.e",
                b64("{}") + ".%%%." + b64("s"),
                b64("{}") + "." + b64("not json") + "." + b64("s"),
                b64("{}") + "." + b64("[\"an\",\"array\"]") + "." + b64("s"))) {
            Violation v = Fapi2RequestPolicy.checkClientAssertion(assertion, ISSUER);
            assertNotNull(v, assertion);
            assertEquals("invalid_client", v.error);
        }
        assertNotNull(Fapi2RequestPolicy.checkClientAssertion(null, ISSUER));
    }

    /**
     * Two {@code aud} members, one of them right. Whichever a parser keeps, another parser may keep the
     * other, so neither order may pass - and the second is the one that would, if this policy read the
     * last member and whatever verifies the assertion afterwards read the first.
     */
    @Test
    @Requirement("FAPI2-SP §5.3.2.1(2.8)")
    void anAssertionWithTwoAudiencesIsRefusedWhicheverComesLast() {
        String issuer = "\"aud\":\"" + ISSUER + "\"";
        String tokenEndpoint = "\"aud\":\"" + TOKEN_ENDPOINT + "\"";
        assertNotNull(Fapi2RequestPolicy.checkClientAssertion(jwt("{\"alg\":\"PS256\"}", "{" + issuer + "," + tokenEndpoint + "}"), ISSUER));
        assertNotNull(Fapi2RequestPolicy.checkClientAssertion(jwt("{\"alg\":\"PS256\"}", "{" + tokenEndpoint + "," + issuer + "}"), ISSUER));
    }

    /** With no issuer to compare against, nothing matches - the failure is a refusal, never a pass. */
    @Test
    void anUnknownIssuerRefusesEverything() {
        assertNotNull(Fapi2RequestPolicy.checkClientAssertion(assertionWithAud("\"" + ISSUER + "\""), null));
    }

    // ─────────────────────────────── whose request it is ───────────────────────────────

    /** The sub, because that is who PingFederate will try to authenticate the assertion as. */
    @Test
    void anAssertionBelongsToItsSubject() {
        assertEquals("bank-app", Fapi2RequestPolicy.subjectOf(jwt("{\"alg\":\"PS256\"}", "{\"iss\":\"someone-else\",\"sub\":\"bank-app\"}")));
        for (String payload : List.of("{}", "{\"sub\":\"\"}", "{\"sub\":\"  \"}", "{\"sub\":42}", "{\"sub\":[\"bank-app\"]}")) {
            assertNull(Fapi2RequestPolicy.subjectOf(jwt("{\"alg\":\"PS256\"}", payload)), payload);
        }
        assertNull(Fapi2RequestPolicy.subjectOf("not-a-jwt"));
        assertNull(Fapi2RequestPolicy.subjectOf(null));
    }

    @Test
    void aJwtAccessTokenNamesItsClientUnderEitherScheme() {
        String token = jwt("{\"alg\":\"PS256\",\"typ\":\"at+jwt\"}", "{\"client_id\":\"bank-app\",\"sub\":\"alice\"}");
        assertEquals("bank-app", Fapi2RequestPolicy.clientOfAccessToken("DPoP " + token));
        assertEquals("bank-app", Fapi2RequestPolicy.clientOfAccessToken("  Bearer   " + token + " "));
    }

    /** Null is an answer - "this request does not say" - and what the filter does with it is its business. */
    @Test
    void aTokenThatNamesNoClientNamesNoClient() {
        for (String authorization : new String[] { null, "", "DPoP", "an-opaque-reference-token", "DPoP an-opaque-reference-token",
                "DPoP " + jwt("{\"alg\":\"PS256\"}", "{\"sub\":\"alice\"}"),
                "DPoP " + jwt("{\"alg\":\"PS256\"}", "{\"client_id\":\" \"}"),
                "DPoP " + jwt("{\"alg\":\"PS256\"}", "{\"client_id\":[\"bank-app\"]}") }) {
            assertNull(Fapi2RequestPolicy.clientOfAccessToken(authorization), String.valueOf(authorization));
        }
    }

    // ─────────────────────────────── DPoP proof algorithm ───────────────────────────────

    @Test
    @Requirement("FAPI2-SP §5.4.1(2.1.2.2)")
    void aProofSignedWithAPermittedAlgorithmPasses() {
        for (String alg : List.of("PS256", "ES256", "EdDSA")) {
            assertNull(Fapi2RequestPolicy.checkDpopProof(jwt("{\"typ\":\"dpop+jwt\",\"alg\":\"" + alg + "\"}", "{}")), alg);
        }
    }

    @Test
    @Requirement("FAPI2-SP §5.4.1(2.1.2.2)")
    void aProofSignedWithAnythingElseIsRefused() {
        for (String alg : List.of("RS256", "RS384", "PS384", "ES384", "HS256", "none", "ps256", "")) {
            Violation v = Fapi2RequestPolicy.checkDpopProof(jwt("{\"typ\":\"dpop+jwt\",\"alg\":\"" + alg + "\"}", "{}"));
            assertNotNull(v, alg);
            assertEquals("invalid_dpop_proof", v.error);
        }
        assertNotNull(Fapi2RequestPolicy.checkDpopProof(jwt("{\"typ\":\"dpop+jwt\"}", "{}")), "no alg");
        assertNotNull(Fapi2RequestPolicy.checkDpopProof(jwt("{\"alg\":[\"PS256\"]}", "{}")), "alg is not a string");
        assertNotNull(Fapi2RequestPolicy.checkDpopProof("not-a-jwt"));
        assertNotNull(Fapi2RequestPolicy.checkDpopProof(null));
    }

    /**
     * The conformance suite fails a server whose error_description holds a character JSON must escape,
     * so these are written without any; this keeps the next one written that way too.
     */
    @Test
    void noDescriptionNeedsEscaping() {
        for (Violation v : List.of(
                Fapi2RequestPolicy.checkClientAssertion("not-a-jwt", ISSUER),
                Fapi2RequestPolicy.checkClientAssertion(assertionWithAud("\"" + TOKEN_ENDPOINT + "\""), ISSUER),
                Fapi2RequestPolicy.checkDpopProof("not-a-jwt"),
                Fapi2RequestPolicy.checkDpopProof(jwt("{\"alg\":\"RS256\"}", "{}")))) {
            assertFalse(v.description.contains("\"") || v.description.contains("\\"), v.description);
            assertEquals(v.description, new String(v.description.getBytes(StandardCharsets.US_ASCII), StandardCharsets.US_ASCII));
        }
    }
}
