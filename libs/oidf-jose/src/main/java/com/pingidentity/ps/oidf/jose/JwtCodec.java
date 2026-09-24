package com.pingidentity.ps.oidf.jose;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;

/**
 * Thin helpers over jose4j for the JWT verification patterns the federation and
 * attestation code needs: unverified claim inspection, verification against an
 * inline JWKS or a resolved key set, PoP verification against a bound key, and
 * {@code typ} header handling.
 *
 * <p>Every rejection leaves here as a {@link JwtVerificationException}, never as a jose4j exception:
 * jose4j's messages carry the whole token or its claims, and callers log and echo messages.
 */
public final class JwtCodec {
    private static final Log LOGGER = LogFactory.getLog(JwtCodec.class);

    private JwtCodec() {
    }

    public static JwtClaims parseUnverifiedClaims(String jwt) throws Exception {
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();
        try {
            return consumer.processToClaims(jwt);
        } catch (InvalidJwtException e) {
            throw translate(e);
        }
    }

    public static JwtClaims verifyAgainstInlineJwks(String jwt, Map<String, Object> jwks, String expectedIssuer) throws JwtVerificationException {
        return verifyAgainstInlineJwks(jwt, jwks, expectedIssuer, Set.of());
    }

    public static JwtClaims verifyAgainstInlineJwks(String jwt, Map<String, Object> jwks, String expectedIssuer, Set<String> acceptedAlgorithms) throws JwtVerificationException {
        return verifyAgainstInlineJwks(jwt, jwks, expectedIssuer, acceptedAlgorithms, VerificationPolicy.legacy());
    }

    /**
     * Verifies against a JWK Set carried inline (a statement's {@code jwks} claim). With a policy that
     * requires {@code kid} the set is read as Federation Entity Keys ({@link Jwks#parseFederationKeySet}):
     * public, asymmetric, each with a unique {@code kid} - a symmetric key in an inline set would let
     * anyone who can read the set forge an HMAC-signed statement.
     */
    public static JwtClaims verifyAgainstInlineJwks(String jwt, Map<String, Object> jwks, String expectedIssuer,
            Set<String> acceptedAlgorithms, VerificationPolicy policy) throws JwtVerificationException {
        VerificationPolicy effective = policy == null ? VerificationPolicy.legacy() : policy;
        List<JsonWebKey> keys;
        try {
            keys = effective.requireKid() ? Jwks.parseFederationKeySet(jwks)
                    : new JsonWebKeySet(JsonUtil.toJson(jwks)).getJsonWebKeys();
        } catch (JoseException | IllegalArgumentException e) {
            throw new JwtVerificationException(JwtVerificationException.Reason.KEY, "the issuer's key set is not usable");
        }
        return verifyAgainstKeys(jwt, keys, expectedIssuer, acceptedAlgorithms, effective);
    }

    /**
     * Verifies a self-contained statement JWT (entity statement, client attestation, ...) against a
     * resolved set of issuer keys. Requires {@code iss}/{@code sub}/{@code exp} (as entity statements
     * and client attestations do) and applies a 60s clock skew. Audience is not validated here.
     */
    public static JwtClaims verifyAgainstKeys(String jwt, List<JsonWebKey> keys, String expectedIssuer, Set<String> acceptedAlgorithms) throws JwtVerificationException {
        return verifyAgainstKeys(jwt, keys, expectedIssuer, acceptedAlgorithms, VerificationPolicy.legacy());
    }

    /**
     * As {@link #verifyAgainstKeys(String, List, String, Set)}, plus the {@link VerificationPolicy}:
     * when it requires {@code kid} the key is selected by an exact match before any verification is
     * attempted (never by jose4j's key-type heuristics); when it requires {@code iat}, a missing or
     * future {@code iat} is refused; when it names a {@code typ}, any other type is refused before the
     * signature is looked at.
     */
    public static JwtClaims verifyAgainstKeys(String jwt, List<JsonWebKey> keys, String expectedIssuer,
            Set<String> acceptedAlgorithms, VerificationPolicy policy) throws JwtVerificationException {
        VerificationPolicy effective = policy == null ? VerificationPolicy.legacy() : policy;
        Map<String, Object> headers = null;
        if (effective.expectedTyp() != null || effective.requireKid()) {
            headers = getJwtHeaders(jwt);
        }
        if (effective.expectedTyp() != null) {
            try {
                requireType(headers, effective.expectedTyp());
            } catch (IllegalArgumentException e) {
                throw new JwtVerificationException(JwtVerificationException.Reason.TYP, "expected " + effective.expectedTyp());
            }
        }
        JwtConsumerBuilder builder = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(effective.clockSkewSeconds())
                .setRequireSubject()
                .setExpectedIssuer(expectedIssuer)
                .setSkipDefaultAudienceValidation();
        if (effective.clock() != null) {
            builder.setEvaluationTime(NumericDate.fromSeconds(effective.clock().instant().getEpochSecond()));
        }
        if (effective.requireKid()) {
            JsonWebKey selected = selectByKid(keys, requireKid(headers));
            builder.setVerificationKey(verificationKeyOf(selected));
        } else {
            builder.setVerificationKeyResolver(new JwksVerificationKeyResolver(keys == null ? List.of() : keys));
        }
        if (effective.requireIssuedAt()) {
            builder.setRequireIssuedAt();
        }
        if (acceptedAlgorithms != null && !acceptedAlgorithms.isEmpty()) {
            builder.setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, acceptedAlgorithms.toArray(new String[0])));
        }
        JwtClaims claims;
        try {
            claims = builder.build().processToClaims(jwt);
        } catch (InvalidJwtException e) {
            throw translate(e);
        }
        if (effective.requireIssuedAt()) {
            requireIssuedAtInPast(claims, effective.clockSkewSeconds(), effective.effectiveClock());
        }
        return claims;
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
        try {
            return builder.build().processToClaims(jwt);
        } catch (InvalidJwtException e) {
            throw translate(e);
        }
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

    public static Map<String, Object> getJwtHeaders(String jwt) throws JwtVerificationException {
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(jwt);
            String rawHeadersJson = jws.getHeaders().getFullHeaderAsJsonString();
            return toHeaderMap(rawHeadersJson);
        } catch (JoseException | IOException | RuntimeException e) {
            throw new JwtVerificationException(JwtVerificationException.Reason.MALFORMED, "header");
        }
    }

    /**
     * The protected header of a compact JWS (three parts) or JWE (five parts), read without verifying or
     * decrypting anything. For a JWE this is all that can be read before decryption: {@code alg},
     * {@code enc}, {@code kid}, {@code typ} and any {@code trust_chain} header the sender placed there.
     */
    public static Map<String, Object> compactProtectedHeader(String compact) throws JwtVerificationException {
        if (compact == null) {
            throw new JwtVerificationException(JwtVerificationException.Reason.MALFORMED, "header");
        }
        String[] parts = compact.split("\\.", -1);
        if (parts.length != 3 && parts.length != 5) {
            throw new JwtVerificationException(JwtVerificationException.Reason.MALFORMED, "not a compact JWS or JWE");
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(parts[0]);
            return toHeaderMap(new String(decoded, StandardCharsets.UTF_8));
        } catch (IOException | IllegalArgumentException e) {
            throw new JwtVerificationException(JwtVerificationException.Reason.MALFORMED, "header");
        }
    }

    /** True for a five-part compact serialization (a JWE); false for anything else. */
    public static boolean isCompactJwe(String compact) {
        return compact != null && compact.split("\\.", -1).length == 5;
    }

    /**
     * The {@code kid} header, required to be a non-empty string (OpenID Federation 1.0 §3.2: "MUST be a
     * non-zero length string").
     */
    public static String requireKid(Map<String, Object> headers) throws JwtVerificationException {
        Object kid = headers == null ? null : headers.get("kid");
        if (!(kid instanceof String) || ((String) kid).isEmpty()) {
            throw new JwtVerificationException(JwtVerificationException.Reason.KEY, "the kid header is missing or empty");
        }
        return (String) kid;
    }

    /**
     * The one key whose {@code kid} exactly equals {@code kid}. None, or more than one, is a refusal: the
     * {@code kid} is how a verifier chooses the key, so an ambiguous choice is not a choice.
     */
    public static JsonWebKey selectByKid(List<JsonWebKey> keys, String kid) throws JwtVerificationException {
        JsonWebKey match = null;
        if (keys != null) {
            for (JsonWebKey key : keys) {
                if (kid.equals(key.getKeyId())) {
                    if (match != null) {
                        throw new JwtVerificationException(JwtVerificationException.Reason.KEY, "more than one key has this kid");
                    }
                    match = key;
                }
            }
        }
        if (match == null) {
            throw new JwtVerificationException(JwtVerificationException.Reason.KEY);
        }
        return match;
    }

    /**
     * Requires {@code iat} to be present and not later than now plus {@code skewSeconds} (OpenID
     * Federation 1.0 §3.2 / §10.2: "The current time MUST be after the time represented by the iat").
     */
    public static void requireIssuedAtInPast(JwtClaims claims, int skewSeconds, Clock clock) throws JwtVerificationException {
        NumericDate iat;
        try {
            iat = claims == null ? null : claims.getIssuedAt();
        } catch (MalformedClaimException e) {
            throw new JwtVerificationException(JwtVerificationException.Reason.MALFORMED, "iat");
        }
        if (iat == null) {
            throw new JwtVerificationException(JwtVerificationException.Reason.MISSING_CLAIM, "iat");
        }
        long now = (clock == null ? Clock.systemUTC() : clock).instant().getEpochSecond();
        if (iat.getValue() > now + skewSeconds) {
            throw new JwtVerificationException(JwtVerificationException.Reason.NOT_YET_VALID, "iat");
        }
    }

    private static Key verificationKeyOf(JsonWebKey key) throws JwtVerificationException {
        if (!(key instanceof PublicJsonWebKey)) {
            // A symmetric key selected by kid would let whoever can read the key set sign as the issuer.
            throw new JwtVerificationException(JwtVerificationException.Reason.KEY, "only asymmetric keys verify here");
        }
        return ((PublicJsonWebKey) key).getPublicKey();
    }

    /**
     * For code that drives jose4j itself: the caller-safe form of a jose4j rejection, to log or return in
     * place of jose4j's own message (which carries the token or its claims).
     */
    public static JwtVerificationException safe(InvalidJwtException e) {
        return translate(e);
    }

    /**
     * Maps a jose4j rejection onto a {@link JwtVerificationException} without copying a single character
     * of jose4j's message, which carries the token or its claims.
     */
    static JwtVerificationException translate(InvalidJwtException e) {
        List<Integer> codes = new ArrayList<>();
        List<ErrorCodeValidator.Error> details = e.getErrorDetails();
        if (details != null) {
            for (ErrorCodeValidator.Error error : details) {
                codes.add(error.getErrorCode());
            }
        }
        JwtVerificationException translated = translate(codes, e.getCause());
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("JWT rejected: reason=" + translated.code() + " jose4j_error_codes=" + codes
                    + " cause=" + (e.getCause() == null ? "none" : e.getCause().getClass().getSimpleName()));
        }
        return translated;
    }

    static JwtVerificationException translate(List<Integer> codes, Throwable cause) {
        JwtVerificationException.Reason reason;
        String detail = null;
        if (codes.contains(ErrorCodes.EXPIRED)) {
            reason = JwtVerificationException.Reason.EXPIRED;
        } else if (codes.contains(ErrorCodes.NOT_YET_VALID) || codes.contains(ErrorCodes.ISSUED_AT_INVALID_FUTURE)) {
            reason = JwtVerificationException.Reason.NOT_YET_VALID;
        } else if (codes.contains(ErrorCodes.SIGNATURE_INVALID)) {
            reason = JwtVerificationException.Reason.SIGNATURE;
        } else if (codes.contains(ErrorCodes.SIGNATURE_MISSING)) {
            reason = JwtVerificationException.Reason.SIGNATURE;
            detail = "unsigned";
        } else if (codes.contains(ErrorCodes.ISSUER_INVALID)) {
            reason = JwtVerificationException.Reason.ISSUER;
        } else if (codes.contains(ErrorCodes.AUDIENCE_INVALID)) {
            reason = JwtVerificationException.Reason.AUDIENCE;
        } else if (codes.contains(ErrorCodes.SUBJECT_INVALID)) {
            reason = JwtVerificationException.Reason.SUBJECT;
        } else if (codes.contains(ErrorCodes.TYPE_INVALID) || codes.contains(ErrorCodes.TYPE_MISSING)) {
            reason = JwtVerificationException.Reason.TYP;
        } else if ((detail = missingClaim(codes)) != null) {
            reason = JwtVerificationException.Reason.MISSING_CLAIM;
        } else if (codes.contains(ErrorCodes.JSON_INVALID) || codes.contains(ErrorCodes.MALFORMED_CLAIM)) {
            reason = JwtVerificationException.Reason.MALFORMED;
        } else if (codes.contains(ErrorCodes.EXPIRATION_TOO_FAR_IN_FUTURE) || codes.contains(ErrorCodes.ISSUED_AT_INVALID_PAST)) {
            reason = JwtVerificationException.Reason.OTHER;
            detail = "lifetime";
        } else {
            reason = reasonFromCause(cause);
        }
        return new JwtVerificationException(reason, detail, codes);
    }

    private static String missingClaim(List<Integer> codes) {
        if (codes.contains(ErrorCodes.ISSUER_MISSING)) {
            return "iss";
        }
        if (codes.contains(ErrorCodes.SUBJECT_MISSING)) {
            return "sub";
        }
        if (codes.contains(ErrorCodes.EXPIRATION_MISSING)) {
            return "exp";
        }
        if (codes.contains(ErrorCodes.ISSUED_AT_MISSING)) {
            return "iat";
        }
        if (codes.contains(ErrorCodes.NOT_BEFORE_MISSING)) {
            return "nbf";
        }
        if (codes.contains(ErrorCodes.JWT_ID_MISSING)) {
            return "jti";
        }
        if (codes.contains(ErrorCodes.AUDIENCE_MISSING)) {
            return "aud";
        }
        return null;
    }

    private static JwtVerificationException.Reason reasonFromCause(Throwable cause) {
        for (Throwable t = cause; t != null; t = t.getCause()) {
            if (t instanceof InvalidAlgorithmException) {
                return JwtVerificationException.Reason.ALGORITHM;
            }
            if (t instanceof UnresolvableKeyException) {
                return JwtVerificationException.Reason.KEY;
            }
            if (t instanceof JoseException) {
                return JwtVerificationException.Reason.MALFORMED;
            }
        }
        return JwtVerificationException.Reason.OTHER;
    }

    private static Map<String, Object> toHeaderMap(String rawHeadersJson) throws IOException {
        return new ObjectMapper().readValue(rawHeadersJson, new TypeReference<Map<String, Object>>() {});
    }
}
