/*
 * Validates a DPoP-bound, delegated access token at the resource server.
 */
package com.pingidentity.ps.oidf.rs;

import com.pingidentity.ps.oidf.common.DpopProof;
import com.pingidentity.ps.oidf.common.DpopProofValidator;
import com.pingidentity.ps.oidf.common.Jwks;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * What a resource server must check before believing an agent is acting for a human.
 *
 * <p>Four things, in order, and the third is the one people skip:
 *
 * <ol>
 *   <li>the access token is signed by the authorisation server and unexpired;</li>
 *   <li>the DPoP proof is well-formed, fresh, and covers this method and URL;</li>
 *   <li><strong>the proof's key is the key the token is bound to</strong> —
 *       {@code cnf.jkt} must equal the RFC 7638 thumbprint of the proof's {@code jwk}. Validating a
 *       DPoP proof without this check accepts any well-formed proof from anyone, which is the entire
 *       point of sender-constraining missed;</li>
 *   <li>the RFC 8693 {@code act} chain names an agent instance, and only its outermost actor is used.</li>
 * </ol>
 *
 * <p>Replay is the caller's to own, as it is in {@link DpopProofValidator}: this class reports the
 * proof's {@code jti} and the caller decides what cache it belongs in. A resource server that skips
 * that accepts a captured proof for as long as it stays fresh.
 */
public final class DelegatedTokenValidator {

    private static final Set<String> PERMITTED_ALGORITHMS = Set.of("ES256", "RS256", "PS256");

    private final List<JsonWebKey> authorizationServerKeys;
    private final String expectedIssuer;
    private final String expectedAudience;
    private final DpopProofValidator dpop;
    private final long allowedClockSkewSeconds;

    public DelegatedTokenValidator(List<JsonWebKey> authorizationServerKeys, String expectedIssuer,
                                   String expectedAudience) {
        this(authorizationServerKeys, expectedIssuer, expectedAudience,
                new DpopProofValidator(PERMITTED_ALGORITHMS, 60, 300L), 60L);
    }

    public DelegatedTokenValidator(List<JsonWebKey> authorizationServerKeys, String expectedIssuer,
                                   String expectedAudience, DpopProofValidator dpop,
                                   long allowedClockSkewSeconds) {
        this.authorizationServerKeys = List.copyOf(
                Objects.requireNonNull(authorizationServerKeys, "authorizationServerKeys"));
        this.expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer");
        this.expectedAudience = Objects.requireNonNull(expectedAudience, "expectedAudience");
        this.dpop = Objects.requireNonNull(dpop, "dpop");
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    /**
     * Validates a request.
     *
     * @param accessToken the bearer of the {@code DPoP} authorization scheme — never {@code Bearer}
     * @param dpopProof   the {@code DPoP} header
     * @param method      the HTTP method, for {@code htm}
     * @param url         the request URL, for {@code htu}
     */
    public Result validate(String accessToken, String dpopProof, String method, String url)
            throws RsException {
        if (accessToken == null || accessToken.isBlank()) {
            throw new RsException("invalid_token", 401, "no access token presented");
        }
        if (dpopProof == null || dpopProof.isBlank()) {
            // A missing proof is not "fall back to bearer" — on this path there is no bearer mode.
            throw new RsException("invalid_token", 401,
                    "no DPoP proof presented; this resource accepts only sender-constrained tokens");
        }

        JwtClaims claims = verifyAccessToken(accessToken);

        DpopProof proof;
        try {
            proof = this.dpop.validate(dpopProof, method, url);
        } catch (Exception e) {
            throw new RsException("invalid_dpop_proof", 401, "DPoP proof rejected: " + e.getMessage());
        }

        // The check that makes sender-constraining mean anything.
        String boundThumbprint = confirmationThumbprint(claims);
        String presentedThumbprint;
        try {
            presentedThumbprint = Jwks.thumbprint(proof.jwk());
        } catch (Exception e) {
            throw new RsException("invalid_dpop_proof", 401, "DPoP proof key is not a well-formed JWK");
        }
        if (!boundThumbprint.equals(presentedThumbprint)) {
            throw new RsException("invalid_token", 401,
                    "the access token is bound to a different key than the DPoP proof presents");
        }

        // RFC 9449 §4.3: when a proof accompanies an access token it MUST carry ath, the hash of that
        // token. Without this a proof captured for one token is replayable against any other token
        // bound to the same key — the key binding alone does not tie proof to token.
        String expectedAth = accessTokenHash(accessToken);
        if (proof.ath() == null || proof.ath().isBlank()) {
            throw new RsException("invalid_dpop_proof", 401,
                    "DPoP proof carries no 'ath', so it is not bound to this access token");
        }
        if (!expectedAth.equals(proof.ath())) {
            throw new RsException("invalid_dpop_proof", 401,
                    "DPoP proof 'ath' is for a different access token");
        }

        Map<String, Object> claimMap = claims.getClaimsMap();
        ActChain.Parsed act = ActChain.parse(claimMap);

        return new Result(claims.getClaimValueAsString("sub"), act, proof.jti(),
                scopes(claims), claimMap);
    }

    private JwtClaims verifyAccessToken(String accessToken) throws RsException {
        JsonWebSignature jws = new JsonWebSignature();
        String kid;
        String algorithm;
        try {
            jws.setCompactSerialization(accessToken);
            kid = jws.getKeyIdHeaderValue();
            algorithm = jws.getAlgorithmHeaderValue();
        } catch (Exception e) {
            throw new RsException("invalid_token", 401, "access token is not a well-formed JWS");
        }
        if (algorithm == null || !PERMITTED_ALGORITHMS.contains(algorithm)) {
            throw new RsException("invalid_token", 401,
                    "access token algorithm " + algorithm + " is not permitted");
        }
        JsonWebKey key = selectKey(kid);
        if (key == null) {
            throw new RsException("invalid_token", 401,
                    "no authorisation server key matches the token kid: " + kid);
        }
        try {
            jws.setKey(((PublicJsonWebKey) key).getPublicKey());
            jws.setAlgorithmConstraints(
                    new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, algorithm));
            if (!jws.verifySignature()) {
                throw new RsException("invalid_token", 401, "access token signature did not verify");
            }
        } catch (RsException e) {
            throw e;
        } catch (Exception e) {
            throw new RsException("invalid_token", 401, "access token signature could not be verified");
        }

        JwtClaims claims;
        try {
            claims = JwtClaims.parse(jws.getUnverifiedPayload());
        } catch (Exception e) {
            throw new RsException("invalid_token", 401, "access token payload is not valid JWT claims");
        }
        try {
            if (!this.expectedIssuer.equals(claims.getIssuer())) {
                throw new RsException("invalid_token", 401, "access token issuer is not the expected AS");
            }
            List<String> audiences = claims.getAudience();
            if (audiences == null || !audiences.contains(this.expectedAudience)) {
                throw new RsException("invalid_token", 401, "access token audience is not this resource");
            }
            long now = NumericDate.now().getValue();
            if (claims.getExpirationTime() == null
                    || claims.getExpirationTime().getValue() + this.allowedClockSkewSeconds < now) {
                throw new RsException("invalid_token", 401, "access token has expired");
            }
        } catch (RsException e) {
            throw e;
        } catch (Exception e) {
            throw new RsException("invalid_token", 401, "access token claims are malformed");
        }
        return claims;
    }

    @SuppressWarnings("unchecked")
    private static String confirmationThumbprint(JwtClaims claims) throws RsException {
        Object cnf = claims.getClaimValue("cnf");
        if (!(cnf instanceof Map)) {
            throw new RsException("invalid_token", 401,
                    "access token carries no cnf, so it is not sender-constrained");
        }
        Object jkt = ((Map<String, Object>) cnf).get("jkt");
        if (!(jkt instanceof String text) || text.isBlank()) {
            throw new RsException("invalid_token", 401, "access token cnf carries no jkt");
        }
        return text;
    }

    private JsonWebKey selectKey(String kid) {
        for (JsonWebKey key : this.authorizationServerKeys) {
            if (key instanceof PublicJsonWebKey && (kid == null || kid.equals(key.getKeyId()))) {
                return key;
            }
        }
        return null;
    }

    /** RFC 9449 {@code ath}: base64url(SHA-256(access token)), over the ASCII of the compact form. */
    static String accessTokenHash(String accessToken) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static List<String> scopes(JwtClaims claims) {
        String scope = claims.getClaimValueAsString("scope");
        return scope == null || scope.isBlank() ? List.of() : List.of(scope.trim().split("\\s+"));
    }

    /** A validated request. */
    public record Result(String subject, ActChain.Parsed act, String dpopJti, List<String> scopes,
                         Map<String, Object> claims) {

        /** Whether an agent is acting here at all, as opposed to a human calling directly. */
        public boolean isDelegated() {
            return !this.act.isEmpty();
        }

        /** The acting agent instance, when delegated. The only actor that may be authorised on. */
        public Optional<String> actingInstance() {
            return this.act.currentActor().map(ActChain.Actor::subject);
        }

        /** What a demo endpoint can safely echo: no device data, no raw token. */
        public Map<String, Object> describe() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("subject", this.subject);
            out.put("delegated", isDelegated());
            out.put("acting_instance", actingInstance().orElse(null));
            out.put("prior_actors", this.act.priorActors().stream().map(ActChain.Actor::subject).toList());
            out.put("scopes", this.scopes);
            out.put("act_legacy_string_form", this.act.legacyStringForm());
            return out;
        }
    }

    /** A refusal, with the OAuth error code a {@code WWW-Authenticate} header should carry. */
    public static class RsException extends Exception {
        private static final long serialVersionUID = 1L;

        private final String error;
        private final int status;

        public RsException(String error, int status, String message) {
            super(message);
            this.error = error;
            this.status = status;
        }

        public String error() {
            return this.error;
        }

        public int status() {
            return this.status;
        }
    }
}
