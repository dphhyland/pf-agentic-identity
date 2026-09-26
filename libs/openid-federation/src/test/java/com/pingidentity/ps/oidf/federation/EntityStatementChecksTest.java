package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import java.time.Clock;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * Each OpenID Federation 1.0 §3.2 step that reads the statement itself, with a statement that passes and
 * one that fails it.
 */
class EntityStatementChecksTest {
    private static final String TA = "https://ta.example";
    private static final String LEAF = "https://rp.example";
    private static final String OP = "https://op.example";
    private static final PublicJsonWebKey KEY = Keys.ec("k1");
    private static final Map<String, Object> JWKS = Keys.publicJwks(KEY);

    private static Map<String, Object> configuration() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", LEAF);
        claims.put("sub", LEAF);
        claims.put("iat", 1_700_000_000L);
        claims.put("exp", 1_700_003_600L);
        claims.put("jwks", JWKS);
        claims.put("authority_hints", List.of(TA));
        return claims;
    }

    private static Map<String, Object> subordinate() {
        Map<String, Object> claims = configuration();
        claims.put("iss", TA);
        claims.remove("authority_hints");
        return claims;
    }

    private static void check(Map<String, Object> claims) {
        check(Map.of(), claims, null);
    }

    private static void check(Map<String, Object> header, Map<String, Object> claims, String registrationAudience) {
        JwtClaims jwtClaims = new JwtClaims();
        claims.forEach(jwtClaims::setClaim);
        EntityStatementChecks.check(header, jwtClaims, registrationAudience);
    }

    private static TrustChainValidationException refused(Map<String, Object> claims) {
        return assertThrows(TrustChainValidationException.class, () -> check(claims));
    }

    private static Map<String, Object> with(Map<String, Object> claims, String name, Object value) {
        claims.put(name, value);
        return claims;
    }

    private static void assertRefused(Kind kind, Map<String, Object> claims) {
        TrustChainValidationException e = refused(claims);
        assertEquals(kind, e.kind(), e.getMessage());
    }

    @Test
    void wellFormedStatementsPass() {
        check(configuration());
        check(subordinate());
    }

    // ---- identifiers and times ------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §3.2(2.5)", "OIDFED §3.1.1(1.2)"})
    void theIssuerIsARequiredEntityIdentifier() {
        Map<String, Object> missing = configuration();
        missing.remove("iss");
        assertRefused(Kind.MISSING_CLAIM, missing);
        assertRefused(Kind.SYNTAX, with(configuration(), "iss", "http://rp.example"));
        assertRefused(Kind.SYNTAX, with(configuration(), "iss", "https://rp.example?x=1"));
        assertRefused(Kind.SYNTAX, with(configuration(), "iss", 42));
    }

    @Test
    @Requirement({"OIDFED §3.2(2.4)", "OIDFED §3.1.1(1.4)"})
    void theSubjectIsARequiredEntityIdentifier() {
        Map<String, Object> missing = configuration();
        missing.remove("sub");
        assertRefused(Kind.MISSING_CLAIM, missing);
        assertRefused(Kind.SYNTAX, with(configuration(), "sub", "rp.example"));
    }

    @Test
    @Requirement({"OIDFED §3.1.1(1.6)", "OIDFED §3.1.1(1.8)"})
    void iatAndExpAreRequiredNumbers() {
        for (String name : List.of("iat", "exp")) {
            Map<String, Object> missing = configuration();
            missing.remove(name);
            assertRefused(Kind.MISSING_CLAIM, missing);
            assertRefused(Kind.SYNTAX, with(configuration(), name, "soon"));
        }
    }

    // ---- keys -----------------------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §3.2(2.9)", "OIDFED §3.1.1(1.10)"})
    void everyStatementCarriesAUsableSetOfFederationEntityKeys() {
        Map<String, Object> missing = subordinate();
        missing.remove("jwks");
        assertRefused(Kind.MISSING_CLAIM, missing);
        assertRefused(Kind.SYNTAX, with(configuration(), "jwks", "keys"));
        assertRefused(Kind.SYNTAX, with(configuration(), "jwks", Map.of("keys", List.of())));
        Map<String, Object> noKid = new HashMap<>(Keys.publicJwk(KEY));
        noKid.remove("kid");
        assertRefused(Kind.SYNTAX, with(configuration(), "jwks", Map.of("keys", List.of(noKid))));
        assertRefused(Kind.SYNTAX, with(configuration(), "jwks", Map.of("keys", List.of(Keys.publicJwk(KEY), Keys.publicJwk(KEY)))));
        assertRefused(Kind.SYNTAX, with(configuration(), "jwks", Map.of("keys", List.of(Keys.privateJwk(KEY)))));
        assertRefused(Kind.SYNTAX, with(configuration(), "jwks", Map.of("keys", List.of(Map.of("kty", "oct", "kid", "s", "k", "c2VjcmV0")))));
    }

    // ---- crit -----------------------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §3.2(2.13)", "OIDFED §13.4(1)"})
    void aCriticalClaimThisImplementationDoesNotUnderstandRefusesTheStatement() {
        TrustChainValidationException e = refused(with(with(configuration(), "crit", List.of("jurisdiction")), "jurisdiction", "AU"));
        assertEquals(Kind.CRIT, e.kind());
        assertTrue(e.getMessage().contains("jurisdiction"), e.getMessage());
    }

    @Test
    @Requirement({"OIDFED §3.1.1(1.14)", "OIDFED §3.2(2.13)"})
    void aCriticalClaimAnImplementationDoesUnderstandIsAccepted() {
        JwtClaims claims = new JwtClaims();
        with(with(configuration(), "crit", List.of("jurisdiction")), "jurisdiction", "AU").forEach(claims::setClaim);
        EntityStatementChecks.check(Map.of(), claims, null, java.util.Set.of("jurisdiction"));
    }

    @Test
    @Requirement({"OIDFED §3.1.1(1.14)", "OIDFED §13.4(1)"})
    void critListsOnlyExtensionClaimsInANonEmptyArray() {
        assertRefused(Kind.SYNTAX, with(configuration(), "crit", List.of("exp")));
        assertRefused(Kind.SYNTAX, with(configuration(), "crit", List.of()));
        assertRefused(Kind.SYNTAX, with(configuration(), "crit", "jurisdiction"));
        assertRefused(Kind.SYNTAX, with(configuration(), "crit", List.of(7)));
    }

    // ---- which claims go where ----------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §3.2(2.14)", "OIDFED §3.2(2.15)", "OIDFED §3.2(2.20)", "OIDFED §3.2(2.21)", "OIDFED §3.2(2.22)"})
    void configurationOnlyClaimsAreRefusedInASubordinateStatement() {
        for (String name : List.of("authority_hints", "trust_anchor_hints", "trust_marks", "trust_mark_issuers", "trust_mark_owners")) {
            TrustChainValidationException e = refused(with(subordinate(), name, List.of(TA)));
            assertEquals(Kind.SYNTAX, e.kind(), name);
            assertTrue(e.getMessage().contains(name), e.getMessage());
        }
    }

    @Test
    @Requirement({"OIDFED §3.2(2.17)", "OIDFED §3.2(2.18)", "OIDFED §3.2(2.19)", "OIDFED §3.2(2.23)"})
    void subordinateOnlyClaimsAreRefusedInAnEntityConfiguration() {
        for (String name : List.of("metadata_policy", "metadata_policy_crit", "constraints", "source_endpoint")) {
            TrustChainValidationException e = refused(with(configuration(), name, Map.of()));
            assertEquals(Kind.SYNTAX, e.kind(), name);
            assertTrue(e.getMessage().contains(name), e.getMessage());
        }
    }

    // ---- claim syntax -------------------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §3.2(2.14)", "OIDFED §3.1.2(1.2)"})
    void authorityHintsAreANonEmptyArrayOfEntityIdentifiers() {
        assertRefused(Kind.SYNTAX, with(configuration(), "authority_hints", List.of()));
        assertRefused(Kind.SYNTAX, with(configuration(), "authority_hints", TA));
        assertRefused(Kind.SYNTAX, with(configuration(), "authority_hints", List.of("not an id")));
        assertRefused(Kind.SYNTAX, with(configuration(), "authority_hints", List.of(1)));
    }

    @Test
    @Requirement({"OIDFED §3.2(2.15)", "OIDFED §3.1.2(1.4)"})
    void trustAnchorHintsAreANonEmptyArrayOfEntityIdentifiers() {
        check(with(configuration(), "trust_anchor_hints", List.of(TA)));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_anchor_hints", List.of()));
    }

    @Test
    @Requirement({"OIDFED §3.2(2.16)", "OIDFED §5(3)", "OIDFED §3.1.1(1.12)"})
    void metadataIsAnObjectOfObjectsWithoutNullValues() {
        check(with(configuration(), "metadata", Map.of("openid_relying_party", Map.of())));
        assertRefused(Kind.SYNTAX, with(configuration(), "metadata", List.of()));
        assertRefused(Kind.SYNTAX, with(configuration(), "metadata", Map.of("openid_relying_party", "rp")));
        Map<String, Object> nullParameter = new HashMap<>();
        nullParameter.put("client_name", null);
        assertRefused(Kind.SYNTAX, with(configuration(), "metadata", Map.of("openid_relying_party", nullParameter)));
    }

    @Test
    @Requirement("OIDFED §3.2(2.17)")
    void metadataPolicyMustBeAValidPolicy() {
        check(with(subordinate(), "metadata_policy", Map.of("openid_relying_party", Map.of("contacts", Map.of("essential", true)))));
        assertRefused(Kind.SYNTAX, with(subordinate(), "metadata_policy", List.of()));
        assertRefused(Kind.SYNTAX, with(subordinate(), "metadata_policy", Map.of("openid_relying_party", "strict")));
        TrustChainValidationException e = refused(with(subordinate(), "metadata_policy",
                Map.of("openid_relying_party", Map.of("contacts", Map.of("essential", "yes")))));
        assertEquals(Kind.POLICY, e.kind());
        assertEquals(FederationError.INVALID_METADATA, e.error());
    }

    @Test
    @Requirement({"OIDFED §3.2(2.18)", "OIDFED §3.1.3(1.6)"})
    void metadataPolicyCritNamesOnlyAdditionalOperatorsAndThisImplementationUnderstandsNone() {
        assertRefused(Kind.CRIT, with(subordinate(), "metadata_policy_crit", List.of("regexp")));
        assertRefused(Kind.CRIT, with(subordinate(), "metadata_policy_crit", List.of("regexp", "intersects")));
        assertRefused(Kind.SYNTAX, with(subordinate(), "metadata_policy_crit", List.of("subset_of")));
        assertRefused(Kind.SYNTAX, with(subordinate(), "metadata_policy_crit", List.of()));
        assertRefused(Kind.SYNTAX, with(subordinate(), "metadata_policy_crit", Map.of("openid_relying_party", List.of("regexp"))));
        assertRefused(Kind.SYNTAX, with(subordinate(), "metadata_policy_crit", List.of(1)));
    }

    @Test
    @Requirement("OIDFED §3.2(2.19)")
    void constraintsMustBeSyntacticallyCorrect() {
        check(with(subordinate(), "constraints", Map.of("max_path_length", 1)));
        TrustChainValidationException e = refused(with(subordinate(), "constraints", Map.of("max_path_length", -1)));
        assertEquals(Kind.SYNTAX, e.kind());
        assertTrue(e.getMessage().startsWith("constraints:"), e.getMessage());
    }

    @Test
    @Requirement({"OIDFED §3.2(2.20)", "OIDFED §3.1.2(1.6)"})
    void eachTrustMarkNamesTheTypeItsJwtCarries() {
        String mark = Statements.spec(Statements.TRUST_MARK_TYP).claim("iss", TA).claim("sub", LEAF)
                .claim("trust_mark_type", "https://marks.example/certified").sign(KEY, Clock.systemUTC());
        check(with(configuration(), "trust_marks", List.of(Map.of("trust_mark_type", "https://marks.example/certified", "trust_mark", mark))));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_marks", Map.of()));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_marks", List.of(Map.of("trust_mark", mark))));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_marks", List.of("mark")));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_marks",
                List.of(Map.of("trust_mark_type", "https://marks.example/certified", "trust_mark", 7))));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_marks",
                List.of(Map.of("trust_mark_type", "https://marks.example/other", "trust_mark", mark))));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_marks",
                List.of(Map.of("trust_mark_type", "https://marks.example/certified", "trust_mark", "not-a-jwt"))));
    }

    @Test
    @Requirement("OIDFED §3.2(2.21)")
    void trustMarkIssuersMapTypesToArraysOfEntityIdentifiers() {
        check(with(configuration(), "trust_mark_issuers", Map.of("https://marks.example/certified", List.of(TA))));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_mark_issuers", List.of(TA)));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_mark_issuers", Map.of("t", TA)));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_mark_issuers", Map.of("t", List.of("nope"))));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_mark_issuers", Map.of("t", List.of(7))));
    }

    @Test
    @Requirement("OIDFED §3.2(2.22)")
    void trustMarkOwnersNameASubjectAndItsKeys() {
        check(with(configuration(), "trust_mark_owners", Map.of("t", Map.of("sub", TA, "jwks", JWKS))));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_mark_owners", List.of()));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_mark_owners", Map.of("t", Map.of("jwks", JWKS))));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_mark_owners", Map.of("t", Map.of("sub", "owner", "jwks", JWKS))));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_mark_owners", Map.of("t", "owner")));
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_mark_owners", Map.of("t", Map.of("sub", TA, "jwks", Map.of()))));
    }

    @Test
    @Requirement("OIDFED §3.2(2.23)")
    void sourceEndpointIsAUrl() {
        check(with(subordinate(), "source_endpoint", TA + "/fetch"));
        check(with(subordinate(), "source_endpoint", "http://ta.example/fetch"));
        assertRefused(Kind.SYNTAX, with(subordinate(), "source_endpoint", "https:/fetch"));
        assertRefused(Kind.SYNTAX, with(subordinate(), "source_endpoint", "fetch"));
        assertRefused(Kind.SYNTAX, with(subordinate(), "source_endpoint", "ftp://ta.example/fetch"));
        assertRefused(Kind.SYNTAX, with(subordinate(), "source_endpoint", "https://ta example/fetch"));
        assertRefused(Kind.SYNTAX, with(subordinate(), "source_endpoint", 7));
    }

    // ---- registration-only claims and headers -----------------------------------------------------------

    @Test
    @Requirement("OIDFED §3.2(2.27)")
    void trustAnchorIsRefusedInAChainStatement() {
        assertRefused(Kind.SYNTAX, with(configuration(), "trust_anchor", TA));
    }

    @Test
    @Requirement({"OIDFED §3.2(2.26)", "OIDFED §12.2.1(4.12)"})
    void audAppearsOnlyInARegistrationRequestAndNamesOnlyTheOp() {
        check(Map.of(), with(configuration(), "aud", OP), OP);
        check(Map.of(), with(configuration(), "aud", List.of(OP + "/")), OP);
        assertThrows(TrustChainValidationException.class, () -> check(Map.of(), with(configuration(), "aud", List.of(OP, TA)), OP));
        assertThrows(TrustChainValidationException.class, () -> check(Map.of(), with(configuration(), "aud", TA), OP));
        assertThrows(TrustChainValidationException.class, () -> check(Map.of(), with(configuration(), "aud", List.of(7)), OP));
        assertThrows(TrustChainValidationException.class, () -> check(Map.of(), with(configuration(), "aud", List.of(TA)), OP));
        assertRefused(Kind.SYNTAX, with(configuration(), "aud", OP));
        assertThrows(TrustChainValidationException.class, () -> check(Map.of(), with(subordinate(), "aud", OP), OP));
    }

    @Test
    @Requirement({"OIDFED §4.3(2)", "OIDFED §4.4(2)"})
    void chainHeadersAreRefusedOnStatementsInAChain() {
        for (String name : List.of("trust_chain", "peer_trust_chain")) {
            TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                    () -> check(Map.of(name, List.of("x")), subordinate(), null));
            assertEquals(Kind.SYNTAX, e.kind());
            assertThrows(TrustChainValidationException.class, () -> check(Map.of(name, List.of("x")), configuration(), OP));
        }
    }

    @Test
    @Requirement({"OIDFED §3.2(2.24)", "OIDFED §3.2(2.25)", "OIDFED §12.2.1(2.8)"})
    void aRegistrationRequestsTrustChainHeaderBeginsWithItsOwnConfiguration() {
        String own = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", LEAF).claim("sub", LEAF).claim("jwks", JWKS)
                .sign(KEY, Clock.systemUTC());
        String other = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", TA).claim("sub", LEAF).claim("jwks", JWKS)
                .sign(KEY, Clock.systemUTC());
        Map<String, Object> request = with(configuration(), "aud", OP);

        check(Map.of("trust_chain", List.of(own, other), "peer_trust_chain", List.of(other)), request, OP);
        for (Object bad : List.of("chain", List.of(), List.of(7), List.of(other), List.of("not-a-jwt"))) {
            assertThrows(TrustChainValidationException.class, () -> check(Map.of("trust_chain", bad), request, OP), String.valueOf(bad));
        }
    }
}
