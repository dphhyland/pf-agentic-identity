package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.access.JwksEndpointKeyAccessor;
import com.pingidentity.ps.oidf.ssf.SubjectId;
import java.util.List;
import java.util.Set;
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

    static PfIdTokenVerifier forThisDeployment() {
        return new PfIdTokenVerifier(() -> JwksEndpointKeyAccessor.newInstance().getSigningJsonWebKeySet(), null);
    }

    @Override
    public SubjectId verifiedSubject(String jwt) {
        if (jwt == null || jwt.isBlank()) {
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
                    .setAllowedClockSkewInSeconds(Integer.MAX_VALUE);
            if (this.expectedIssuer != null) {
                builder.setExpectedIssuer(this.expectedIssuer);
            }
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
        catch (Exception e) {
            LOGGER.info((Object) ("logout: token did not verify against PF's signing keys: " + e.getMessage()));
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
