package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.HttpGetClient;

/**
 * OpenID Federation 1.0 §3, second paragraph: Entity Statement JWTs MUST carry
 * {@code typ: entity-statement+jwt}, and a statement with no {@code typ} or a different one MUST be
 * rejected. The explicit type is what stops a JWT minted for some other purpose under a federation
 * key - an ID token, a client attestation - being replayed as a statement in a chain (RFC 8725 §3.11).
 *
 * <p>Every statement that takes part in a trust decision is covered: the leaf's Entity Configuration,
 * an intermediate's Subordinate Statement about the leaf, the intermediate's own Entity Configuration,
 * the anchor's Subordinate Statement about the intermediate, and the anchor's Entity Configuration that
 * the gateway reads - for its keys and for its {@code federation_fetch_endpoint}. Each position is
 * tried with the header missing and with a plausible wrong value, and each rejection has to name
 * {@code typ}, so a case cannot pass because the chain broke for some unrelated reason. The control
 * case proves the same federation resolves when every header is right.
 */
class TrustChainValidatorEntityStatementTypeTest {
    private static final String LEAF = "https://agent.example.com";
    private static final String INTERMEDIATE = "https://intermediate.example.com";
    private static final String ANCHOR = "https://anchor.example.com";
    private static final String TYP = "entity-statement+jwt";
    /** The generic value a JOSE library writes when nobody set one explicitly. */
    private static final String WRONG_TYP = "JWT";

    /** A statement in the three-level federation, by the role it plays in the chain. */
    private enum Position { LEAF_CONFIG, INTERMEDIATE_ABOUT_LEAF, INTERMEDIATE_CONFIG, ANCHOR_ABOUT_INTERMEDIATE, ANCHOR_CONFIG }

    private PublicJsonWebKey leafKey;
    private PublicJsonWebKey intermediateKey;
    private PublicJsonWebKey anchorKey;

    @BeforeEach
    void keys() throws Exception {
        leafKey = ec("leaf-1");
        intermediateKey = ec("intermediate-1");
        anchorKey = ec("anchor-1");
    }

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwk.setKeyId(kid);
        return jwk;
    }

    private static Map<String, Object> jwks(PublicJsonWebKey key) {
        return Map.of("keys", List.of(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
    }

    /** @param typ the header value, or {@code null} to leave the header off entirely */
    private static String statement(PublicJsonWebKey signingKey, String typ, String iss, String sub,
                                    Map<String, Object> claims) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 3600L));
        claims.forEach(c::setClaim);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(signingKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        if (typ != null) {
            jws.setHeader("typ", typ);
        }
        jws.setKeyIdHeaderValue(signingKey.getKeyId());
        return jws.getCompactSerialization();
    }

    private static String fetchUrl(String issuer, String subject) {
        return issuer + "/fetch?sub=" + URLEncoder.encode(subject, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(issuer, StandardCharsets.UTF_8);
    }

    private static HttpGetClient serving(Map<String, String> responses) {
        return (url, accept) -> {
            String jwt = responses.get(url);
            if (jwt == null) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };
    }

    /**
     * Leaf, intermediate and anchor, every statement signed with the right key, each served where the
     * gateway looks for it. {@code typs} overrides the header per position; absent positions get
     * {@link #TYP}, and a {@code null} value removes the header.
     */
    private Map<Position, String> federation(Map<Position, String> typs) throws Exception {
        Map<Position, String> t = new EnumMap<>(Position.class);
        for (Position p : Position.values()) {
            t.put(p, typs.containsKey(p) ? typs.get(p) : TYP);
        }
        Map<Position, String> statements = new EnumMap<>(Position.class);
        statements.put(Position.LEAF_CONFIG, statement(leafKey, t.get(Position.LEAF_CONFIG), LEAF, LEAF, Map.of(
                "jwks", jwks(leafKey),
                "authority_hints", List.of(INTERMEDIATE),
                "metadata", Map.of("openid_relying_party", Map.of("client_name", "agent")))));
        statements.put(Position.INTERMEDIATE_ABOUT_LEAF, statement(intermediateKey, t.get(Position.INTERMEDIATE_ABOUT_LEAF),
                INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey))));
        statements.put(Position.INTERMEDIATE_CONFIG, statement(intermediateKey, t.get(Position.INTERMEDIATE_CONFIG),
                INTERMEDIATE, INTERMEDIATE, Map.of(
                        "jwks", jwks(intermediateKey),
                        "authority_hints", List.of(ANCHOR),
                        "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", INTERMEDIATE + "/fetch")))));
        statements.put(Position.ANCHOR_ABOUT_INTERMEDIATE, statement(anchorKey, t.get(Position.ANCHOR_ABOUT_INTERMEDIATE),
                ANCHOR, INTERMEDIATE, Map.of("jwks", jwks(intermediateKey))));
        statements.put(Position.ANCHOR_CONFIG, statement(anchorKey, t.get(Position.ANCHOR_CONFIG), ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(anchorKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch")))));
        return statements;
    }

    private static TrustChainValidator validatorOver(Map<Position, String> statements) {
        Map<String, String> responses = new HashMap<>();
        responses.put(LEAF + "/.well-known/openid-federation", statements.get(Position.LEAF_CONFIG));
        responses.put(fetchUrl(INTERMEDIATE, LEAF), statements.get(Position.INTERMEDIATE_ABOUT_LEAF));
        responses.put(INTERMEDIATE + "/.well-known/openid-federation", statements.get(Position.INTERMEDIATE_CONFIG));
        responses.put(fetchUrl(ANCHOR, INTERMEDIATE), statements.get(Position.ANCHOR_ABOUT_INTERMEDIATE));
        responses.put(ANCHOR + "/.well-known/openid-federation", statements.get(Position.ANCHOR_CONFIG));
        return new TrustChainValidator(new HttpTrustControllerGateway(serving(responses), ANCHOR), ANCHOR);
    }

    /** The chain as a caller supplies it: every statement but the anchor's own configuration. */
    private static List<String> suppliedChain(Map<Position, String> statements) {
        return List.of(
                statements.get(Position.LEAF_CONFIG),
                statements.get(Position.INTERMEDIATE_ABOUT_LEAF),
                statements.get(Position.INTERMEDIATE_CONFIG),
                statements.get(Position.ANCHOR_ABOUT_INTERMEDIATE));
    }

    private static Map<Position, String> typAt(Position position, String typ) {
        Map<Position, String> typs = new EnumMap<>(Position.class);
        typs.put(position, typ);
        return typs;
    }

    /** validate() throws, and throws about typ - not about a key, a hint or a missing stub. Quoted, because "typ" alone is inside "type". */
    private static void assertRejectedForTyp(TrustChainValidator validator, List<String> chain) {
        Exception e = assertThrows(Exception.class, () -> validator.validate(chain, LEAF, LEAF));
        assertTrue(String.valueOf(e.getMessage()).contains("'typ'"),
                "rejected, but not for the typ header: " + e);
    }

    // --- control ---------------------------------------------------------------------------------

    @Test
    void theFederationResolvesWhenEveryStatementIsExplicitlyTyped() throws Exception {
        Map<Position, String> statements = federation(Map.of());
        assertEquals(ANCHOR, validatorOver(statements).validate(List.of(), LEAF, LEAF).trustAnchorIssuer());
        assertEquals(ANCHOR, validatorOver(statements).validate(suppliedChain(statements), LEAF, LEAF).trustAnchorIssuer());
    }

    /**
     * RFC 7515 §4.1.9 lets the {@code application/} prefix be left off a media type in {@code typ};
     * the spelled-out form names the same type and is not "a different typ value".
     */
    @Test
    @Requirement("OIDFED §3(2)")
    void theApplicationPrefixedSpellingIsTheSameType() throws Exception {
        Map<Position, String> typs = new EnumMap<>(Position.class);
        for (Position p : Position.values()) {
            typs.put(p, "application/" + TYP);
        }
        Map<Position, String> statements = federation(typs);
        assertEquals(ANCHOR, validatorOver(statements).validate(suppliedChain(statements), LEAF, LEAF).trustAnchorIssuer());
    }

    // --- the leaf's Entity Configuration -----------------------------------------------------------

    @Test
    @Requirement("OIDFED §3(2)")
    void aFetchedLeafConfigurationWithoutTypIsRejected() throws Exception {
        assertRejectedForTyp(validatorOver(federation(typAt(Position.LEAF_CONFIG, null))), List.of());
    }

    @Test
    @Requirement("OIDFED §3(2)")
    void aSuppliedLeafConfigurationWithADifferentTypIsRejected() throws Exception {
        Map<Position, String> statements = federation(typAt(Position.LEAF_CONFIG, WRONG_TYP));
        assertRejectedForTyp(validatorOver(statements), suppliedChain(statements));
    }

    // --- the intermediate's Subordinate Statement about the leaf -----------------------------------

    @Test
    @Requirement("OIDFED §3(2)")
    void anIntermediateSubordinateStatementWithoutTypIsRejected() throws Exception {
        Map<Position, String> statements = federation(typAt(Position.INTERMEDIATE_ABOUT_LEAF, null));
        assertRejectedForTyp(validatorOver(statements), suppliedChain(statements));
    }

    @Test
    @Requirement("OIDFED §3(2)")
    void aFetchedIntermediateSubordinateStatementWithADifferentTypIsRejected() throws Exception {
        assertRejectedForTyp(validatorOver(federation(typAt(Position.INTERMEDIATE_ABOUT_LEAF, WRONG_TYP))), List.of());
    }

    // --- the intermediate's own Entity Configuration -----------------------------------------------

    /**
     * An intermediate's configuration is only in the verified route when the walk reaches it before
     * the anchor's statement about the intermediate - here, because the caller did not supply that
     * statement and the walk goes through the configuration's {@code authority_hints} to fetch it.
     * (With the anchor's statement supplied, the walk steps straight to it and the configuration takes
     * no part in the chain at all.)
     */
    @Test
    @Requirement("OIDFED §3(2)")
    void anIntermediateConfigurationWithoutTypIsRejectedWhenTheRouteRunsThroughIt() throws Exception {
        Map<Position, String> statements = federation(typAt(Position.INTERMEDIATE_CONFIG, null));
        List<String> chain = List.of(
                statements.get(Position.LEAF_CONFIG),
                statements.get(Position.INTERMEDIATE_ABOUT_LEAF),
                statements.get(Position.INTERMEDIATE_CONFIG));
        assertRejectedForTyp(validatorOver(statements), chain);
    }

    /**
     * Fetched, the intermediate's configuration is what tells the gateway where the intermediate's
     * statement about the leaf lives. As with the anchor's, the walk turns the failure into "no route",
     * so the reason is asserted at the gateway.
     */
    @Test
    @Requirement("OIDFED §3(2)")
    void anIntermediateConfigurationWithADifferentTypIsNotAFetchEndpointDirectory() throws Exception {
        Map<Position, String> statements = federation(typAt(Position.INTERMEDIATE_CONFIG, WRONG_TYP));
        assertThrows(Exception.class, () -> validatorOver(statements).validate(List.of(), LEAF, LEAF));

        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(serving(Map.of(
                INTERMEDIATE + "/.well-known/openid-federation", statements.get(Position.INTERMEDIATE_CONFIG),
                fetchUrl(INTERMEDIATE, LEAF), statements.get(Position.INTERMEDIATE_ABOUT_LEAF))), ANCHOR);
        Exception e = assertThrows(Exception.class, () -> gateway.fetchSubordinateStatement(INTERMEDIATE, LEAF));
        assertTrue(e.getMessage().contains("'typ'"), "rejected, but not for the typ header: " + e);
    }

    // --- the anchor's Subordinate Statement about the intermediate ---------------------------------

    @Test
    @Requirement("OIDFED §3(2)")
    void theAnchorSubordinateStatementWithoutTypIsRejected() throws Exception {
        assertRejectedForTyp(validatorOver(federation(typAt(Position.ANCHOR_ABOUT_INTERMEDIATE, null))), List.of());
    }

    @Test
    @Requirement("OIDFED §3(2)")
    void aSuppliedAnchorSubordinateStatementWithADifferentTypIsRejected() throws Exception {
        Map<Position, String> statements = federation(typAt(Position.ANCHOR_ABOUT_INTERMEDIATE, WRONG_TYP));
        assertRejectedForTyp(validatorOver(statements), suppliedChain(statements));
    }

    // --- the anchor's Entity Configuration, read by the gateway ------------------------------------

    /**
     * With the whole chain supplied, the only time the anchor's configuration is read is for the keys
     * the anchor's statement is verified against - so this isolates that read.
     */
    @Test
    @Requirement("OIDFED §3(2)")
    void theAnchorConfigurationWithoutTypIsRejectedAsTheSourceOfTheAnchorKeys() throws Exception {
        Map<Position, String> statements = federation(typAt(Position.ANCHOR_CONFIG, null));
        assertRejectedForTyp(validatorOver(statements), suppliedChain(statements));
    }

    @Test
    @Requirement("OIDFED §3(2)")
    void theAnchorConfigurationWithADifferentTypIsRejectedAsTheSourceOfTheAnchorKeys() throws Exception {
        Map<Position, String> statements = federation(typAt(Position.ANCHOR_CONFIG, WRONG_TYP));
        assertRejectedForTyp(validatorOver(statements), suppliedChain(statements));
    }

    /**
     * With nothing supplied, the gateway also reads the anchor's configuration to find where to fetch
     * the anchor's statement from. The walk swallows fetch failures and reports "no route", so assert
     * on the gateway directly for the reason, and on the validator for the outcome.
     */
    @Test
    @Requirement("OIDFED §3(2)")
    void theAnchorConfigurationWithoutTypIsNotAFetchEndpointDirectory() throws Exception {
        Map<Position, String> statements = federation(typAt(Position.ANCHOR_CONFIG, null));
        assertThrows(Exception.class, () -> validatorOver(statements).validate(List.of(), LEAF, LEAF));

        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(serving(Map.of(
                ANCHOR + "/.well-known/openid-federation", statements.get(Position.ANCHOR_CONFIG),
                fetchUrl(ANCHOR, INTERMEDIATE), statements.get(Position.ANCHOR_ABOUT_INTERMEDIATE))), ANCHOR);
        Exception e = assertThrows(Exception.class, () -> gateway.fetchSubordinateStatement(ANCHOR, INTERMEDIATE));
        assertTrue(e.getMessage().contains("'typ'"), "rejected, but not for the typ header: " + e);
    }

    @Test
    @Requirement("OIDFED §3(2)")
    void theGatewayRefusesAMistypedEntityConfigurationWhicheverWayItIsAskedFor() throws Exception {
        Map<Position, String> statements = federation(typAt(Position.ANCHOR_CONFIG, WRONG_TYP));
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(serving(Map.of(
                ANCHOR + "/.well-known/openid-federation", statements.get(Position.ANCHOR_CONFIG))), ANCHOR);
        assertTrue(assertThrows(Exception.class, () -> gateway.fetchEntityConfiguration()).getMessage().contains("'typ'"));
        assertTrue(assertThrows(Exception.class, () -> gateway.fetchEntityConfigurationOf(ANCHOR)).getMessage().contains("'typ'"));
    }

    @Test
    void theGatewayReadsATypedEntityConfigurationWhicheverWayItIsAskedFor() throws Exception {
        Map<Position, String> statements = federation(Map.of());
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(serving(Map.of(
                ANCHOR + "/.well-known/openid-federation", statements.get(Position.ANCHOR_CONFIG))), ANCHOR);
        assertEquals(ANCHOR, gateway.fetchEntityConfiguration().getSubject());
        assertEquals(ANCHOR, gateway.fetchEntityConfigurationOf(ANCHOR).getSubject());
    }

    /**
     * A gateway that implements only the abstract fetches - as the fixture-driven chain tests do - gets
     * the check from the interface's default Entity Configuration reads, not just from the HTTP gateway.
     */
    @Test
    @Requirement("OIDFED §3(2)")
    void aMinimalGatewayStillRejectsAnUntypedAnchorConfiguration() throws Exception {
        Map<Position, String> statements = federation(typAt(Position.ANCHOR_CONFIG, null));
        TrustControllerGateway minimal = new TrustControllerGateway() {
            @Override public JwtClaims fetchEntityConfiguration() {
                throw new UnsupportedOperationException();
            }
            @Override public List<String> fetchMembers() {
                return List.of();
            }
            @Override public String fetchEntityStatement(String issuer) {
                return ANCHOR.equals(issuer) ? statements.get(Position.ANCHOR_CONFIG) : null;
            }
            @Override public String fetchSubordinateStatement(String authorityIssuer, String subject) {
                return null;
            }
        };
        Exception e = assertThrows(Exception.class,
                () -> new TrustChainValidator(minimal, ANCHOR).validate(suppliedChain(statements), LEAF, LEAF));
        assertTrue(e.getMessage().contains("'typ'"), "rejected, but not for the typ header: " + e);
        assertTrue(assertThrows(Exception.class, () -> minimal.fetchEntityConfigurationOf(ANCHOR)).getMessage().contains("'typ'"));
        assertTrue(assertThrows(Exception.class, () -> minimal.fetchEntityConfigurationOf(ANCHOR, null)).getMessage().contains("'typ'"));
    }

    @Test
    @Requirement("OIDFED §3(2)")
    void aMinimalGatewayStillReadsATypedConfiguration() throws Exception {
        Map<Position, String> statements = federation(Map.of());
        TrustControllerGateway minimal = new TrustControllerGateway() {
            @Override public JwtClaims fetchEntityConfiguration() {
                throw new UnsupportedOperationException();
            }
            @Override public List<String> fetchMembers() {
                return List.of();
            }
            @Override public String fetchEntityStatement(String issuer) {
                return statements.get(Position.ANCHOR_CONFIG);
            }
            @Override public String fetchSubordinateStatement(String authorityIssuer, String subject) {
                return null;
            }
        };
        assertEquals(ANCHOR, minimal.fetchEntityConfigurationOf(ANCHOR).getSubject());
        assertEquals(ANCHOR, minimal.fetchEntityConfigurationOf(ANCHOR, null).getSubject());
        assertEquals(ANCHOR, new TrustChainValidator(minimal, ANCHOR).validate(suppliedChain(statements), LEAF, LEAF).trustAnchorIssuer());
    }
}
