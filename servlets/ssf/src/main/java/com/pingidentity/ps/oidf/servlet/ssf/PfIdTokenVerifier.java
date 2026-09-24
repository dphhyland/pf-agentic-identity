package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.access.JwksEndpointKeyAccessor;
import com.pingidentity.ps.oidf.ssf.SubjectId;
import java.util.List;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;

/**
 * Turns a logout token into a subject only if this PingFederate signed it.
 *
 * <p>The signal this feeds ({@code caep.session-revoked}) is signed by this transmitter, so a receiver
 * cannot tell whether the transmitter was <em>told</em> whose session ended. That makes the subject's
 * provenance the whole security property: an unverified token, or a bare {@code sub} parameter, would
 * let any caller aim a revocation signal at any user.
 *
 * <p>Expiry is deliberately not enforced — an {@code id_token_hint} presented at logout is routinely
 * past its expiry, and its age says nothing about who it identifies. The signature, the algorithm and
 * the issuer are what matter, and those are enforced.
 *
 * <p>The issuer is what stops "signed by PF's keys" from meaning "any JWT PF ever signed": the same
 * key set signs access tokens, SETs and id tokens for every virtual issuer this PF serves. A verifier
 * with no expected issuer has no issuer check at all, so it refuses every token rather than accept
 * every one — the production factory always supplies the issuer PF reports for the request.
 */
final class PfIdTokenVerifier implements LogoutEventFilter.IdTokenVerifier {

    private static final Log LOGGER = LogFactory.getLog(PfIdTokenVerifier.class);

    /** Asymmetric only: an HMAC-signed token would be verifiable by anyone holding a client secret. */
    private static final Set<String> ACCEPTED_ALGORITHMS =
            Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512");

    private final KeySource keys;
    private final String expectedIssuer;

    /** Where PF's signing keys come from. Separated so tests need no PF runtime. */
    interface KeySource {
        JsonWebKeySet signingKeys() throws Exception;
    }

    PfIdTokenVerifier(KeySource keys, String expectedIssuer) {
        this.keys = keys;
        this.expectedIssuer = expectedIssuer;
    }

    /**
     * The production verifier: PF's signing keys, and the issuer PF reports for {@code request} — the
     * same {@code OAuthIssuerUtils} lookup the token-endpoint filters use, so a virtual-host issuer is
     * honoured. Both are PF-runtime singletons that cannot be reached outside a booted server, which is
     * why {@link #forDeployment} exists.
     */
    static PfIdTokenVerifier forThisDeployment(HttpServletRequest request) {
        return forDeployment(() -> JwksEndpointKeyAccessor.newInstance().getSigningJsonWebKeySet(),
                org.sourceid.oauth20.issuer.OAuthIssuerUtils.getInstance().getIssuerValue(request));
    }

    /** The production verifier over supplied PF lookups. */
    static PfIdTokenVerifier forDeployment(KeySource keys, String expectedIssuer) {
        return new PfIdTokenVerifier(keys, expectedIssuer);
    }

    @Override
    public SubjectId verifiedSubject(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            return null;
        }
        if (this.expectedIssuer == null || this.expectedIssuer.isBlank()) {
            // Fail closed. An absent issuer used to mean "no issuer check", which is the opposite of
            // what every javadoc on this path promised.
            LOGGER.warn((Object) "logout: no expected issuer is known for this PF; refusing to name a subject from the logout token");
            return null;
        }
        try {
            JsonWebKeySet jwks = this.keys.signingKeys();
            if (jwks == null || jwks.getJsonWebKeys().isEmpty()) {
                LOGGER.warn((Object) "logout: PF exposed no signing keys; cannot verify the logout token");
                return null;
            }
            JwtConsumerBuilder builder = new JwtConsumerBuilder()
                    .setVerificationKeyResolver(new JwksVerificationKeyResolver(jwks.getJsonWebKeys()))
                    .setJwsAlgorithmConstraints(new AlgorithmConstraints(
                            AlgorithmConstraints.ConstraintType.PERMIT,
                            ACCEPTED_ALGORITHMS.toArray(new String[0])))
                    .setRequireSubject()
                    .setSkipDefaultAudienceValidation()
                    // A hint presented at logout is routinely expired; its age does not affect who it
                    // names, and refusing it would just push callers back to the unverified sub param.
                    .setEvaluationTime(org.jose4j.jwt.NumericDate.fromSeconds(0))
                    .setAllowedClockSkewInSeconds(Integer.MAX_VALUE)
                    .setExpectedIssuer(this.expectedIssuer);
            JwtConsumer consumer = builder.build();
            JwtClaims claims = consumer.processToClaims(jwt);
            String sub = claims.getClaimValueAsString("sub");
            String iss = claims.getIssuer();
            if (sub == null || sub.isBlank()) {
                return null;
            }
            return iss == null || iss.isBlank()
                    ? SubjectId.opaque(sub)
                    : SubjectId.issSub(iss, sub);
        }
        catch (org.jose4j.jwt.consumer.InvalidJwtException e) {
            // jose4j's own message carries the whole id_token_hint - a token naming the user - so only the
            // reason is logged, never the text.
            LOGGER.info((Object) ("logout: token did not verify against PF's signing keys ("
                    + com.pingidentity.ps.oidf.jose.JwtCodec.safe(e).code() + ")"));
            return null;
        }
        catch (Exception e) {
            LOGGER.info((Object) ("logout: token did not verify against PF's signing keys ("
                    + e.getClass().getSimpleName() + ")"));
            return null;
        }
    }

    /** Test seam. */
    static PfIdTokenVerifier withKeys(JsonWebKeySet jwks, String expectedIssuer) {
        return new PfIdTokenVerifier(() -> jwks, expectedIssuer);
    }

    static List<String> acceptedAlgorithms() {
        return List.copyOf(ACCEPTED_ALGORITHMS);
    }
}
