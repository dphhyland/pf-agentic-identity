/*
 * Verifies a PingOne OIDC ID token as evidence that a human authenticated.
 */
package com.pingidentity.ps.oidf.enrolment;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * The production {@link UserAuthenticationVerifier}: a PingOne ID token, verified offline against the
 * environment's JWKS.
 *
 * <p>An ID token is used rather than a callback to PingOne because this runs on the enrolment path and,
 * via {@link EnrolmentService#refreshUserVerification}, on the time-box refresh path. Offline
 * verification means neither depends on PingOne being reachable at that instant.
 *
 * <p>Three checks are stricter than the minimum, each for a reason:
 *
 * <ul>
 *   <li><strong>{@code auth_time} is required.</strong> It is what the server-side time-box measures
 *       from. Falling back to {@code iat} would let a client hold an old authentication and present it
 *       inside a freshly minted token — exactly the window the time-box exists to close.</li>
 *   <li><strong>An unrecognised {@code acr} maps to the lowest assurance</strong>, never the highest.
 *       PingOne puts the applied sign-on policy name in {@code acr}, so an unknown value means the user
 *       came through a policy nobody vetted. Note this environment advertises no
 *       {@code acr_values_supported}, so the mapping is deployment configuration and cannot be
 *       discovered.</li>
 *   <li><strong>RS256 only</strong> — the only algorithm this environment's discovery document
 *       advertises. Pinning it closes algorithm substitution rather than trusting the header.</li>
 * </ul>
 *
 * <p>The token carries no {@code amr} — it is absent from {@code claims_supported} — so {@code acr} is
 * the sole assurance signal available here.
 */
public final class PingOneIdTokenVerifier implements UserAuthenticationVerifier {

    private static final Log LOGGER = LogFactory.getLog(PingOneIdTokenVerifier.class);
    private static final String PERMITTED_ALGORITHM = "RS256";
    private static final long DEFAULT_JWKS_CACHE_SECONDS = 900L;

    private final String issuer;
    private final String audience;
    private final JwksSource jwks;
    private final Map<String, UserAuthentication.AssuranceLevel> assuranceByAcr;
    private final long allowedClockSkewSeconds;

    /**
     * @param issuer         the OIDC issuer, e.g.
     *                       {@code https://auth.pingone.asia/<envId>/as}
     * @param audience       the client id of the application the token was issued to
     * @param assuranceByAcr maps a PingOne sign-on policy name to the assurance it actually represents.
     *                       Anything absent is treated as {@link UserAuthentication.AssuranceLevel#AAL1}
     */
    public PingOneIdTokenVerifier(String issuer, String audience, JwksSource jwks,
                                  Map<String, UserAuthentication.AssuranceLevel> assuranceByAcr) {
        this(issuer, audience, jwks, assuranceByAcr, 60L);
    }

    public PingOneIdTokenVerifier(String issuer, String audience, JwksSource jwks,
                                  Map<String, UserAuthentication.AssuranceLevel> assuranceByAcr,
                                  long allowedClockSkewSeconds) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.audience = Objects.requireNonNull(audience, "audience");
        this.jwks = Objects.requireNonNull(jwks, "jwks");
        this.assuranceByAcr = Map.copyOf(Objects.requireNonNull(assuranceByAcr, "assuranceByAcr"));
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    /** Builds one against a live PingOne environment, resolving the JWKS over HTTPS. */
    public static PingOneIdTokenVerifier forEnvironment(
            String issuer, String audience, Map<String, UserAuthentication.AssuranceLevel> assuranceByAcr) {
        return new PingOneIdTokenVerifier(issuer, audience,
                new HttpJwksSource(issuer + "/jwks", DEFAULT_JWKS_CACHE_SECONDS), assuranceByAcr);
    }

    @Override
    public UserAuthentication verify(String idToken) throws EnrolmentException {
        if (idToken == null || idToken.isBlank()) {
            throw EnrolmentException.userAuthenticationFailed("no ID token presented");
        }

        JsonWebSignature jws = new JsonWebSignature();
        String kid;
        try {
            jws.setCompactSerialization(idToken);
            if (!PERMITTED_ALGORITHM.equals(jws.getAlgorithmHeaderValue())) {
                throw EnrolmentException.userAuthenticationFailed(
                        "ID token algorithm is " + jws.getAlgorithmHeaderValue() + ", expected RS256");
            }
            kid = jws.getKeyIdHeaderValue();
        } catch (EnrolmentException e) {
            throw e;
        } catch (Exception e) {
            throw EnrolmentException.userAuthenticationFailed("ID token is not a well-formed compact JWS");
        }

        JsonWebKey key = this.jwks.find(kid);
        if (key == null) {
            throw EnrolmentException.userAuthenticationFailed(
                    "no PingOne signing key matches the ID token kid: " + kid);
        }
        try {
            jws.setKey(((PublicJsonWebKey) key).getPublicKey());
            jws.setAlgorithmConstraints(new AlgorithmConstraints(
                    AlgorithmConstraints.ConstraintType.PERMIT, PERMITTED_ALGORITHM));
            if (!jws.verifySignature()) {
                throw EnrolmentException.userAuthenticationFailed("ID token signature did not verify");
            }
        } catch (EnrolmentException e) {
            throw e;
        } catch (Exception e) {
            throw EnrolmentException.userAuthenticationFailed("ID token signature could not be verified");
        }

        JwtClaims claims;
        try {
            claims = JwtClaims.parse(jws.getUnverifiedPayload());
        } catch (Exception e) {
            throw EnrolmentException.userAuthenticationFailed("ID token payload is not valid JWT claims");
        }

        try {
            if (!this.issuer.equals(claims.getIssuer())) {
                throw EnrolmentException.userAuthenticationFailed(
                        "ID token issuer is " + claims.getIssuer() + ", expected " + this.issuer);
            }
            List<String> audiences = claims.getAudience();
            if (audiences == null || !audiences.contains(this.audience)) {
                throw EnrolmentException.userAuthenticationFailed(
                        "ID token audience does not include this application");
            }
            long now = NumericDate.now().getValue();
            if (claims.getExpirationTime() == null
                    || claims.getExpirationTime().getValue() + this.allowedClockSkewSeconds < now) {
                throw EnrolmentException.userAuthenticationFailed("ID token has expired");
            }
        } catch (EnrolmentException e) {
            throw e;
        } catch (Exception e) {
            throw EnrolmentException.userAuthenticationFailed("ID token claims are malformed");
        }

        // Required, not inferred: this timestamp is what the time-box is measured from.
        Instant authenticatedAt;
        try {
            if (!claims.hasClaim("auth_time")) {
                throw EnrolmentException.userAuthenticationFailed(
                        "ID token has no 'auth_time'; request it with max_age or as an essential claim, "
                                + "because the user-verification window is measured from it");
            }
            authenticatedAt = Instant.ofEpochSecond(
                    claims.getClaimValue("auth_time", Number.class).longValue());
        } catch (EnrolmentException e) {
            throw e;
        } catch (Exception e) {
            throw EnrolmentException.userAuthenticationFailed("ID token 'auth_time' is malformed");
        }
        if (authenticatedAt.isAfter(Instant.now().plusSeconds(this.allowedClockSkewSeconds))) {
            throw EnrolmentException.userAuthenticationFailed("ID token 'auth_time' is in the future");
        }

        String subject = claims.getClaimValueAsString("sub");
        if (subject == null || subject.isBlank()) {
            throw EnrolmentException.userAuthenticationFailed("ID token has no 'sub'");
        }

        String acr = claims.getClaimValueAsString("acr");
        // Guarded rather than passed straight to getOrDefault: the map is immutable, so a null key
        // throws. A token with no acr is the same case as an unrecognised one — lowest assurance.
        UserAuthentication.AssuranceLevel assurance = acr == null
                ? UserAuthentication.AssuranceLevel.AAL1
                : this.assuranceByAcr.getOrDefault(acr, UserAuthentication.AssuranceLevel.AAL1);
        if (acr != null && !this.assuranceByAcr.containsKey(acr)) {
            // Loud, because the usual cause is a sign-on policy change that silently downgrades every
            // enrolment behind it.
            LOGGER.warn((Object) ("ID token acr '" + acr + "' is not in the configured assurance map; "
                    + "treating it as " + UserAuthentication.AssuranceLevel.AAL1));
        }

        // PingOne does not put the passkey credential id in the ID token. The enrolment evidence record
        // wants it, so it is looked up separately via the Management API rather than invented here.
        return new UserAuthentication(subject, authenticatedAt, assurance, null, null);
    }

    /** Where the verifier gets PingOne's signing keys. A seam so tests need no network. */
    public interface JwksSource {
        /** The key with this {@code kid}, or null. Implementations should refetch on an unknown kid. */
        JsonWebKey find(String kid) throws EnrolmentException;
    }

    /**
     * Fetches and caches the environment's JWKS.
     *
     * <p>Refetches on an unknown {@code kid} rather than only on expiry, so a key rotation does not
     * cause a window of rejected logins — the usual way JWKS caching goes wrong.
     */
    public static final class HttpJwksSource implements JwksSource {

        private final String jwksUri;
        private final long cacheSeconds;
        private final HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5)).build();
        private final AtomicReference<Cached> cache = new AtomicReference<>();

        public HttpJwksSource(String jwksUri, long cacheSeconds) {
            this.jwksUri = Objects.requireNonNull(jwksUri, "jwksUri");
            this.cacheSeconds = cacheSeconds;
        }

        @Override
        public JsonWebKey find(String kid) throws EnrolmentException {
            Cached current = this.cache.get();
            if (current != null && !current.isStale(this.cacheSeconds)) {
                JsonWebKey hit = select(current.keys, kid);
                if (hit != null) {
                    return hit;
                }
            }
            List<JsonWebKey> fetched = fetch();
            this.cache.set(new Cached(fetched, Instant.now()));
            return select(fetched, kid);
        }

        private List<JsonWebKey> fetch() throws EnrolmentException {
            try {
                HttpResponse<String> response = this.http.send(
                        HttpRequest.newBuilder(URI.create(this.jwksUri))
                                .timeout(Duration.ofSeconds(10)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw EnrolmentException.userAuthenticationFailed(
                            "PingOne JWKS returned HTTP " + response.statusCode());
                }
                return new JsonWebKeySet(response.body()).getJsonWebKeys();
            } catch (EnrolmentException e) {
                throw e;
            } catch (IOException | InterruptedException e) {
                Thread.currentThread().interrupt();
                throw EnrolmentException.userAuthenticationFailed(
                        "PingOne JWKS could not be fetched: " + e.getMessage());
            } catch (Exception e) {
                throw EnrolmentException.userAuthenticationFailed("PingOne JWKS is not a valid key set");
            }
        }

        private static JsonWebKey select(List<JsonWebKey> keys, String kid) {
            for (JsonWebKey key : keys) {
                if (key instanceof PublicJsonWebKey && (kid == null || kid.equals(key.getKeyId()))) {
                    return key;
                }
            }
            return null;
        }

        private record Cached(List<JsonWebKey> keys, Instant fetchedAt) {
            boolean isStale(long ttlSeconds) {
                return this.fetchedAt.plusSeconds(ttlSeconds).isBefore(Instant.now());
            }
        }
    }
}
