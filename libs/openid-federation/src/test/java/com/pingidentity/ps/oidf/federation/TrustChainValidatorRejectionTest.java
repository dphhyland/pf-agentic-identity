package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.jose.HttpGetClient;

/**
 * The signature/trust rejection paths {@link TrustChainValidatorPolicyTest} (metadata_policy) and
 * {@link TrustChainValidatorFetchBoundsTest} (fetch ceilings, SSRF-shaped identifiers) don't cover:
 * a tampered or wrong-key-signed statement, a chain whose hints never reach the configured anchor, a
 * disallowed signing algorithm, and an ambiguous self-signed leaf in a caller-supplied chain. Every case
 * here must end in {@code validate()} throwing — a chain that should be refused must never resolve.
 */
class TrustChainValidatorRejectionTest {
    private static final String LEAF = "https://agent.example.com";
    private static final String ANCHOR = "https://anchor.example.com";

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwk.setKeyId(kid);
        return jwk;
    }

    private static RsaJsonWebKey rsa(String kid) throws Exception {
        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId(kid);
        return jwk;
    }

    private static Map<String, Object> jwks(PublicJsonWebKey key) {
        return Map.of("keys", List.of(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
    }

    private static String statement(PublicJsonWebKey signingKey, String alg, String iss, String sub,
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
        jws.setAlgorithmHeaderValue(alg);
        jws.setHeader("typ", "entity-statement+jwt");
        jws.setKeyIdHeaderValue(signingKey.getKeyId());
        return jws.getCompactSerialization();
    }

    private static String statement(PublicJsonWebKey signingKey, String iss, String sub,
                                    Map<String, Object> claims) throws Exception {
        return statement(signingKey, "ES256", iss, sub, claims);
    }

    /** Flips one character inside the JWS payload segment, invalidating the signature without changing shape. */
    private static String tamper(String jwt) {
        int firstDot = jwt.indexOf('.');
        int secondDot = jwt.indexOf('.', firstDot + 1);
        int idx = (firstDot + secondDot) / 2;
        char c = jwt.charAt(idx);
        return jwt.substring(0, idx) + (c == 'a' ? 'b' : 'a') + jwt.substring(idx + 1);
    }

    @Test
    void tamperedTrustAnchorStatementIsRejected() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of(
                "jwks", jwks(leafKey), "authority_hints", List.of(ANCHOR)));
        String anchorConfig = statement(anchorKey, ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(anchorKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch"))));
        String subordinate = statement(anchorKey, ANCHOR, LEAF, Map.of("jwks", jwks(leafKey)));

        Map<String, String> responses = new HashMap<>();
        responses.put(LEAF + "/.well-known/openid-federation", leafConfig);
        // The anchor's own entity configuration, tampered after signing: still well-formed JWS shape,
        // but the signature no longer matches what it purports to say.
        responses.put(ANCHOR + "/.well-known/openid-federation", tamper(anchorConfig));
        responses.put(ANCHOR + "/fetch?sub=" + URLEncoder.encode(LEAF, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(ANCHOR, StandardCharsets.UTF_8), subordinate);
        HttpGetClient http = (url, accept) -> {
            String jwt = responses.get(url);
            if (jwt == null) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };

        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(http, ANCHOR), ANCHOR);
        assertThrows(Exception.class, () -> validator.validate(List.of(), LEAF, LEAF));
    }

    @Test
    void subordinateStatementVouchingForTheWrongKeyIsRejected() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey wrongKey = ec("not-the-leafs-key");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        // Signed by the real leaf key ...
        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of(
                "jwks", jwks(leafKey), "authority_hints", List.of(ANCHOR)));
        String anchorConfig = statement(anchorKey, ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(anchorKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch"))));
        // ... but the anchor's subordinate statement vouches for a DIFFERENT key entirely. A validator
        // that trusted this would let an attacker who does not hold the leaf's key impersonate it.
        String subordinate = statement(anchorKey, ANCHOR, LEAF, Map.of("jwks", jwks(wrongKey)));

        Map<String, String> responses = new HashMap<>();
        responses.put(LEAF + "/.well-known/openid-federation", leafConfig);
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig);
        responses.put(ANCHOR + "/fetch?sub=" + URLEncoder.encode(LEAF, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(ANCHOR, StandardCharsets.UTF_8), subordinate);
        HttpGetClient http = (url, accept) -> {
            String jwt = responses.get(url);
            if (jwt == null) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };

        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(http, ANCHOR), ANCHOR);
        assertThrows(Exception.class, () -> validator.validate(List.of(), LEAF, LEAF));
    }

    @Test
    void aChainWhoseHintsNeverReachTheConfiguredAnchorIsRejected() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        String notTheAnchor = "https://other-authority.example.com";
        // The leaf only ever names an authority that is not, and does not lead to, the configured anchor.
        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of(
                "jwks", jwks(leafKey), "authority_hints", List.of(notTheAnchor)));

        Map<String, String> responses = new HashMap<>();
        responses.put(LEAF + "/.well-known/openid-federation", leafConfig);
        HttpGetClient http = (url, accept) -> {
            String jwt = responses.get(url);
            if (jwt == null) {
                // The unrecognised authority is simply unreachable from this validator's point of view.
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };

        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(http, ANCHOR), ANCHOR);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> validator.validate(List.of(), LEAF, LEAF));
        assertTrue(e.getMessage().contains(ANCHOR), e.getMessage());
    }

    @Test
    void aDisallowedSigningAlgorithmIsRejectedEvenWithAValidSignature() throws Exception {
        PublicJsonWebKey leafKey = rsa("leaf-rsa-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        // A genuinely valid RS256 signature ...
        String leafConfig = statement(leafKey, "RS256", LEAF, LEAF, Map.of(
                "jwks", jwks(leafKey), "authority_hints", List.of(ANCHOR)));
        String anchorConfig = statement(anchorKey, ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(anchorKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch"))));
        String subordinate = statement(anchorKey, ANCHOR, LEAF, Map.of("jwks", jwks(leafKey)));

        Map<String, String> responses = new HashMap<>();
        responses.put(LEAF + "/.well-known/openid-federation", leafConfig);
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig);
        responses.put(ANCHOR + "/fetch?sub=" + URLEncoder.encode(LEAF, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(ANCHOR, StandardCharsets.UTF_8), subordinate);
        HttpGetClient http = (url, accept) -> {
            String jwt = responses.get(url);
            if (jwt == null) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };

        // ... but this AS's policy accepts only ES256. The signature being valid must not be enough.
        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(http, ANCHOR), ANCHOR, Set.of("ES256"));
        assertThrows(Exception.class, () -> validator.validate(List.of(), LEAF, LEAF));
    }

    @Test
    void anAmbiguousSelfSignedLeafInASuppliedChainIsRejected() throws Exception {
        PublicJsonWebKey keyA = ec("leaf-key-a");
        PublicJsonWebKey keyB = ec("leaf-key-b");
        // Two different self-signed entity configurations for the same subject, both present in the
        // caller-supplied trust_chain. Nothing distinguishes which one is authoritative.
        String configA = statement(keyA, LEAF, LEAF, Map.of(
                "jwks", jwks(keyA), "authority_hints", List.of(ANCHOR)));
        String configB = statement(keyB, LEAF, LEAF, Map.of(
                "jwks", jwks(keyB), "authority_hints", List.of(ANCHOR)));

        HttpGetClient http = (url, accept) -> {
            throw new IllegalArgumentException("must not need to fetch anything: " + url);
        };
        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(http, ANCHOR), ANCHOR);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> validator.validate(List.of(configA, configB), LEAF, LEAF));
        assertTrue(e.getMessage().toLowerCase(java.util.Locale.ROOT).contains("ambiguous"), e.getMessage());
    }
}
