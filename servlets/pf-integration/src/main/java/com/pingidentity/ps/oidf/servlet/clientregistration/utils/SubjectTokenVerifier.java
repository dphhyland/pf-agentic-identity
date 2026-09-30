/*
 * A token-exchange subject token, verified as one this PingFederate signed.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import java.util.Map;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;

/**
 * A token-exchange {@code subject_token} (RFC 8693 §2.1), verified as one this PingFederate signed: its signature
 * against PingFederate's signing keys ({@code JwksEndpointKeyAccessor.getSigningJsonWebKeySet()}, the SDK's accessor in
 * 13.1.3, javap 2026-09-30), its {@code iss} the issuer PingFederate resolves for the request, and an {@code exp} that
 * has not passed (F-0074, plan item S4c).
 *
 * <p>The same keys sign more than tokens - attestations, federation statements and Security Event Tokens can be
 * signed with them too - so a token whose {@code typ} says it is one of those is refused: only a JWT with no
 * {@code typ}, {@code JWT} or {@code at+jwt} (RFC 9068 §2.1) is taken as a token that names a person. A token that
 * does not verify contributes nothing: no subject, no {@code act} chain.
 */
public final class SubjectTokenVerifier {
    private static final Log LOGGER = LogFactory.getLog(SubjectTokenVerifier.class);

    /** Asymmetric only: a MAC-protected token could be made by anyone holding a client secret. */
    static final Set<String> ALGORITHMS = Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512");
    /** The {@code typ} values of a token that names a person; absent is one of them. */
    static final Set<String> TOKEN_TYPES = Set.of("jwt", "at+jwt", "application/at+jwt");
    /** The clock skew allowed on {@code exp}, in seconds. */
    static final int CLOCK_SKEW_SECONDS = 30;

    /** PingFederate's signing keys. */
    @FunctionalInterface
    public interface KeySource {
        JsonWebKeySet signingKeys() throws Exception;
    }

    private final KeySource keys;

    public SubjectTokenVerifier(KeySource keys) {
        this.keys = keys;
    }

    /** The verifier over this PingFederate's own signing keys. */
    public static SubjectTokenVerifier pingFederate() {
        return new SubjectTokenVerifier(() -> com.pingidentity.access.JwksEndpointKeyAccessor.newInstance().getSigningJsonWebKeySet());
    }

    /**
     * {@code token}'s claims when it verifies as a token {@code issuer} signed; null otherwise, and for a blank token or
     * issuer. Never throws.
     */
    public JwtClaims verify(String token, String issuer) {
        if (token == null || token.isBlank() || issuer == null || issuer.isBlank()) {
            return null;
        }
        try {
            JsonWebKeySet jwks = this.keys.signingKeys();
            if (jwks == null || jwks.getJsonWebKeys().isEmpty()) {
                return null;
            }
            JwtConsumer consumer = new JwtConsumerBuilder()
                    .setVerificationKeyResolver(new JwksVerificationKeyResolver(jwks.getJsonWebKeys()))
                    .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                            ALGORITHMS.toArray(new String[0])))
                    .setExpectedIssuer(issuer)
                    .setRequireExpirationTime()
                    .setRequireSubject()
                    .setSkipDefaultAudienceValidation()
                    .setAllowedClockSkewInSeconds(CLOCK_SKEW_SECONDS)
                    .build();
            JwtContext context = consumer.process(token);
            String typ = context.getJoseObjects().get(0).getHeader("typ");
            if (typ != null && !TOKEN_TYPES.contains(typ.toLowerCase(java.util.Locale.ROOT))) {
                LOGGER.info((Object) ("subject_token refused: typ " + typ + " is not a token that names a person"));
                return null;
            }
            return context.getJwtClaims();
        } catch (org.jose4j.jwt.consumer.InvalidJwtException e) {
            // jose4j's message carries the token; only the reason's code is logged.
            LOGGER.info((Object) ("subject_token did not verify as this PingFederate's ("
                    + com.pingidentity.ps.oidf.jose.JwtCodec.safe(e).code() + ")"));
            return null;
        } catch (Exception | LinkageError | java.util.ServiceConfigurationError e) {
            LOGGER.info((Object) ("subject_token could not be verified (" + e.getClass().getSimpleName() + ")"));
            return null;
        }
    }

    /** {@code claims}' {@code sub}, or null. */
    static String subject(JwtClaims claims) {
        Object sub = claims == null ? null : claims.getClaimValue("sub");
        return sub instanceof String s && !s.isBlank() ? s : null;
    }

    /** {@code claims}' {@code act} as an object, a string-encoded one parsed, or null. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> act(JwtClaims claims) {
        Object act = claims == null ? null : claims.getClaimValue("act");
        try {
            if (act instanceof String s && !s.isBlank()) {
                act = org.jose4j.json.JsonUtil.parseJson(s);
            }
        } catch (org.jose4j.lang.JoseException e) {
            return null;
        }
        return act instanceof Map ? (Map<String, Object>) act : null;
    }
}
