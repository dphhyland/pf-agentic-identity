package au.com.idpartners.gm.servlet;

import com.pingidentity.access.JwksEndpointKeyAccessor;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import java.util.Map;
import java.util.logging.Logger;

/**
 * Verifies an access token against PingFederate's own signing keys.
 *
 * <p>Running inside PingFederate removes the entire trust problem the sidecar has. The
 * sidecar must fetch a JWKS over TLS from a URL it is configured with, decide whether to
 * trust that certificate, and be told separately which issuer to expect -- three settings
 * that can disagree with each other and with reality. Here the keys come straight out of
 * the server that minted the token, so there is nothing to configure and nothing to get
 * wrong.
 *
 * <p>The issuer is not checked, deliberately: a token verified against this server's own
 * signing keys was, necessarily, issued by this server. The audience is another matter --
 * this server mints tokens for many audiences, and one intended for a different API must
 * not be accepted here just because we signed it.
 */
public final class PfTokenVerifier {

    private static final Logger LOG = Logger.getLogger(PfTokenVerifier.class.getName());

    private final JwksEndpointKeyAccessor keys;
    private final String expectedAudience;

    /**
     * @param expectedAudience the aud this API answers to, e.g. the access token
     *                         manager's "Audience Claim Value". When null or blank the
     *                         audience is not checked, which accepts any token this
     *                         server signed regardless of who it was minted for.
     */
    public PfTokenVerifier(String expectedAudience) {
        this(JwksEndpointKeyAccessor.newInstance(), expectedAudience);
    }

    PfTokenVerifier(JwksEndpointKeyAccessor keys, String expectedAudience) {
        this.keys = keys;
        this.expectedAudience = expectedAudience;
        if (expectedAudience == null || expectedAudience.isBlank()) {
            LOG.warning("No expected audience configured: any token this server signed will "
                    + "be accepted, including one minted for a different API. Set the "
                    + "audience init-param to the access token manager's Audience Claim Value.");
        }
    }

    /** Thrown when a token is absent, malformed, expired, or not signed by this server. */
    public static class InvalidTokenException extends Exception {
        InvalidTokenException(String message, Throwable cause) {
            super(message, cause);
        }

        InvalidTokenException(String message) {
            super(message);
        }
    }

    /**
     * Verifies the token's signature and expiry and returns its claims.
     *
     * @throws InvalidTokenException on anything short of a valid, current, correctly
     *                               signed token
     */
    public TokenClaims verify(String jwt) throws InvalidTokenException {
        if (jwt == null || jwt.isBlank()) {
            throw new InvalidTokenException("no token presented");
        }

        JsonWebKeySet jwks = keys.getSigningJsonWebKeySet();
        if (jwks == null || jwks.getJsonWebKeys().isEmpty()) {
            // Not the caller's fault, and not something to fail open over.
            throw new InvalidTokenException("PingFederate published no signing keys");
        }

        // No setRequireSubject(): a client_credentials token legitimately has none.
        // The subject of an evaluation comes from the grant (section 8.4.1), not from
        // the token, so demanding one here would lock out every client that is not
        // mid-session with a user -- which is most of an Open Banking ecosystem.
        JwtConsumerBuilder builder = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30);

        // jose4j will not silently ignore an aud it was given no opinion about, which
        // is the right default: it forces the choice to be made here, explicitly.
        if (expectedAudience != null && !expectedAudience.isBlank()) {
            builder.setExpectedAudience(expectedAudience);
        } else {
            builder.setSkipDefaultAudienceValidation();
        }

        JwtConsumer consumer = builder
                .setJwsAlgorithmConstraints(
                        org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT,
                        AlgorithmIdentifiers.RSA_USING_SHA256,
                        AlgorithmIdentifiers.RSA_USING_SHA384,
                        AlgorithmIdentifiers.RSA_USING_SHA512)
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(jwks.getJsonWebKeys()))
                .build();

        try {
            Map<String, Object> payload = consumer.processToClaims(jwt).getClaimsMap();
            return TokenClaims.from(payload);
        } catch (InvalidJwtException e) {
            throw new InvalidTokenException("token rejected: " + e.getMessage(), e);
        }
    }
}
