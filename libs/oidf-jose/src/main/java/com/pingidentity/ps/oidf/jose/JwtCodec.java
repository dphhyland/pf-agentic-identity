package com.pingidentity.ps.oidf.jose;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.security.Key;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;

/**
 * Thin helpers over jose4j for the JWT verification patterns the federation and
 * attestation code needs: unverified claim inspection, verification against an
 * inline JWKS or a resolved key set, PoP verification against a bound key, and
 * {@code typ} header handling.
 */
public final class JwtCodec {

    private JwtCodec() {
    }

    public static JwtClaims parseUnverifiedClaims(String jwt) throws Exception {
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();
        return consumer.processToClaims(jwt);
    }

    public static JwtClaims verifyAgainstInlineJwks(String jwt, Map<String, Object> jwks, String expectedIssuer) throws Exception {
        return verifyAgainstInlineJwks(jwt, jwks, expectedIssuer, Set.of());
    }

    public static JwtClaims verifyAgainstInlineJwks(String jwt, Map<String, Object> jwks, String expectedIssuer, Set<String> acceptedAlgorithms) throws Exception {
        String jwksJson = JsonUtil.toJson(jwks);
        List<JsonWebKey> keys = new JsonWebKeySet(jwksJson).getJsonWebKeys();
        return verifyAgainstKeys(jwt, keys, expectedIssuer, acceptedAlgorithms);
    }

    /**
     * Verifies a self-contained statement JWT (entity statement, client attestation, ...) against a
     * resolved set of issuer keys. Requires {@code iss}/{@code sub}/{@code exp} (as entity statements
     * and client attestations do) and applies a 60s clock skew. Audience is not validated here.
     */
    public static JwtClaims verifyAgainstKeys(String jwt, List<JsonWebKey> keys, String expectedIssuer, Set<String> acceptedAlgorithms) throws Exception {
        JwksVerificationKeyResolver resolver = new JwksVerificationKeyResolver(keys);
        JwtConsumerBuilder builder = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(60)
                .setRequireSubject()
                .setExpectedIssuer(expectedIssuer)
                .setSkipDefaultAudienceValidation()
                .setVerificationKeyResolver(resolver);
        if (acceptedAlgorithms != null && !acceptedAlgorithms.isEmpty()) {
            builder.setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, acceptedAlgorithms.toArray(new String[0])));
        }
        return builder.build().processToClaims(jwt);
    }

    /**
     * Verifies a Client Attestation PoP JWT against the public key bound in the attestation's
     * {@code cnf} claim. Per draft-ietf-oauth-attestation-based-client-auth, a PoP JWT carries
     * {@code aud}, {@code jti} and {@code iat} (but no {@code exp}); freshness of {@code iat} is the
     * caller's responsibility. The signing algorithm is constrained to the supplied asymmetric set,
     * which excludes {@code none} and MACs.
     */
    public static JwtClaims verifyAttestationPop(String jwt, Key popPublicKey, Set<String> acceptedAlgorithms, Set<String> acceptedAudiences, int allowedClockSkewSeconds) throws Exception {
        JwtConsumerBuilder builder = new JwtConsumerBuilder()
                .setVerificationKey(popPublicKey)
                .setAllowedClockSkewInSeconds(allowedClockSkewSeconds)
                .setRequireJwtId()
                .setRequireIssuedAt();
        if (acceptedAudiences != null && !acceptedAudiences.isEmpty()) {
            builder.setExpectedAudience(acceptedAudiences.toArray(new String[0]));
        } else {
            builder.setSkipDefaultAudienceValidation();
        }
        if (acceptedAlgorithms != null && !acceptedAlgorithms.isEmpty()) {
            builder.setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, acceptedAlgorithms.toArray(new String[0])));
        }
        return builder.build().processToClaims(jwt);
    }

    /** Returns the {@code typ} header value, or {@code null} if absent. */
    public static String getType(Map<String, Object> headers) {
        Object typ = headers == null ? null : headers.get("typ");
        return typ == null ? null : String.valueOf(typ);
    }

    /**
     * Requires the {@code typ} header to equal {@code expectedTyp} (case-insensitive, tolerating an
     * optional {@code application/} prefix as permitted by RFC 7515 / the explicit typing BCP).
     */
    public static void requireType(Map<String, Object> headers, String expectedTyp) {
        String actual = getType(headers);
        if (actual == null || actual.isBlank()) {
            throw new IllegalArgumentException("Missing required 'typ' header (expected '" + expectedTyp + "')");
        }
        String normalized = actual.startsWith("application/") ? actual.substring("application/".length()) : actual;
        if (!normalized.equalsIgnoreCase(expectedTyp)) {
            throw new IllegalArgumentException("Unexpected 'typ' header: got '" + actual + "', expected '" + expectedTyp + "'");
        }
    }

    public static Map<String, Object> getJwtHeaders(String jwt) throws JoseException, IOException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwt);
        String rawHeadersJson = jws.getHeaders().getFullHeaderAsJsonString();
        return toHeaderMap(rawHeadersJson);
    }

    private static Map<String, Object> toHeaderMap(String rawHeadersJson) throws IOException {
        return new ObjectMapper().readValue(rawHeadersJson, new TypeReference<Map<String, Object>>() {});
    }
}
