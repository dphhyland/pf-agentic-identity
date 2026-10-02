package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.access.JwksEndpointKeyAccessor;
import com.pingidentity.ps.oidf.platform.pf.internals.PfInternals;
import com.pingidentity.ps.oidf.signals.SubjectId;
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
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;

/**
 * Turns a logout's {@code id_token_hint} into a subject only if this PingFederate signed it, it is an ID token, and it
 * is recent (plan item H-SSF-6, finding F-0022).
 *
 * <p>The signal this feeds ({@code caep.session-revoked}) is signed by this transmitter, so a receiver
 * cannot tell whether the transmitter was <em>told</em> whose session ended. That makes the subject's
 * provenance the whole security property: an unverified token, or a bare {@code sub} parameter, would
 * let any caller aim a revocation signal at any user.
 *
 * <p>Expiry is deliberately not enforced — OpenID Connect RP-Initiated Logout 1.0 §2 (final, 12 September 2022): "The
 * OP SHOULD accept ID Tokens when the RP identified by the ID Token's aud claim and/or sid claim has a current session
 * or had a recent session at the OP, even when the exp time has passed." What bounds a hint instead is its {@code iat}:
 * one issued longer ago than {@code OIDF_SSF_LOGOUT_HINT_MAX_AGE_SECONDS} (default 24 hours), or in the future beyond
 * {@link #CLOCK_SKEW_SECONDS}, raises nothing, so a hint captured once is not a revocation signal for ever. The same
 * section has "the OP MUST validate that it was the issuer of the ID Token", which is what the signature and the issuer
 * check are.
 *
 * <p>The issuer is what stops "signed by PF's keys" from meaning "any JWT PF ever signed": the same
 * key set signs access tokens, SETs and id tokens for every virtual issuer this PF serves. A verifier
 * with no expected issuer has no issuer check at all, so it refuses every token rather than accept
 * every one — the production factory always supplies the issuer PF reports for the request, through platform-pf's
 * {@link PfInternals#issuer} (finding F-0215).
 *
 * <p>The type is the last check (checked on PingFederate 13.1.3 on 2026-10-01, where the access token of the same
 * login verified against the same keys and issuer, and the filter used to raise a signal for it): an ID token here is
 * a JWT with no {@code typ} header or {@code typ} {@code JWT}, with {@code iss}, {@code sub}, {@code aud}, {@code exp}
 * and {@code iat}, and none of the claims that mark the other JWTs PingFederate signs with the same keys. RFC 9068
 * §2.1: JWT access tokens "MUST include this media type in the "typ" header parameter" ({@code at+jwt}), and §2.2 makes
 * {@code client_id} "REQUIRED" in one; OpenID Connect Back-Channel Logout 1.0 (incorporating errata set 1, 15 December
 * 2023) §2.4 gives a logout token an {@code events} claim, "REQUIRED", and "It is RECOMMENDED that Logout Tokens be
 * explicitly typed" {@code logout+jwt}; a SET carries {@code events} too (RFC 8417 §2.2). PingFederate 13.1.3's own ID
 * token had no {@code typ}, and {@code aud}, {@code auth_time}, {@code exp}, {@code iat}, {@code iss}, {@code jti},
 * {@code nonce} and {@code sub}; its access token {@code typ at+jwt} with {@code client_id} and {@code scope}.
 */
final class PfIdTokenVerifier implements LogoutEventFilter.IdTokenVerifier {

    private static final Log LOGGER = LogFactory.getLog(PfIdTokenVerifier.class);

    /** Asymmetric only: an HMAC-signed token would be verifiable by anyone holding a client secret. */
    private static final Set<String> ACCEPTED_ALGORITHMS =
            Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512");

    /** Claims that mark a JWT as something other than an ID token: a logout token or SET, or an access token. */
    private static final List<String> NOT_ID_TOKEN_CLAIMS = List.of("events", "client_id", "scope");

    /** Claims an ID token has (OpenID Connect Core 1.0 §2 marks each REQUIRED). */
    private static final List<String> ID_TOKEN_CLAIMS = List.of("iss", "sub", "aud", "exp", "iat");

    /** How far in the future an {@code iat} may be before the hint is refused: clocks differ. */
    static final long CLOCK_SKEW_SECONDS = 300;

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
     * The production verifier: PF's signing keys, and the issuer PF reports for {@code request} through
     * {@link PfInternals#issuer}, so a virtual-host issuer is honoured. Both are PF-runtime singletons that cannot be
     * reached outside a booted server, which is why {@link #forDeployment} exists.
     */
    static PfIdTokenVerifier forThisDeployment(HttpServletRequest request) {
        return forDeployment(() -> JwksEndpointKeyAccessor.newInstance().getSigningJsonWebKeySet(),
                PfInternals.issuer(request));
    }

    /** The production verifier over supplied PF lookups. */
    static PfIdTokenVerifier forDeployment(KeySource keys, String expectedIssuer) {
        return new PfIdTokenVerifier(keys, expectedIssuer);
    }

    @Override
    public LogoutEventFilter.Hint verify(String jwt, long nowSeconds, long maxAgeSeconds) {
        if (jwt == null || jwt.isBlank()) {
            return null;
        }
        if (this.expectedIssuer == null || this.expectedIssuer.isBlank()) {
            // Fail closed. An absent issuer used to mean "no issuer check", which is the opposite of
            // what every javadoc on this path promised.
            LOGGER.warn((Object) "logout: no expected issuer is known for this PF; refusing to name a subject from the logout token");
            return LogoutEventFilter.Hint.refused(LogoutEventFilter.HINT_INVALID);
        }
        try {
            JsonWebKeySet jwks = this.keys.signingKeys();
            if (jwks == null || jwks.getJsonWebKeys().isEmpty()) {
                LOGGER.warn((Object) "logout: PF exposed no signing keys; cannot verify the logout token");
                return LogoutEventFilter.Hint.refused(LogoutEventFilter.HINT_INVALID);
            }
            JwtConsumer consumer = new JwtConsumerBuilder()
                    .setVerificationKeyResolver(new JwksVerificationKeyResolver(jwks.getJsonWebKeys()))
                    .setJwsAlgorithmConstraints(new AlgorithmConstraints(
                            AlgorithmConstraints.ConstraintType.PERMIT,
                            ACCEPTED_ALGORITHMS.toArray(new String[0])))
                    .setRequireSubject()
                    .setSkipDefaultAudienceValidation()
                    // A hint presented at logout is routinely expired (RP-Initiated Logout 1.0 §2); its iat bounds it.
                    .setEvaluationTime(org.jose4j.jwt.NumericDate.fromSeconds(0))
                    .setAllowedClockSkewInSeconds(Integer.MAX_VALUE)
                    .setExpectedIssuer(this.expectedIssuer)
                    .build();
            JwtContext context = consumer.process(jwt);
            JwtClaims claims = context.getJwtClaims();
            String typ = context.getJoseObjects().get(0).getHeader("typ");
            if (!isIdToken(typ, claims)) {
                LOGGER.info((Object) "logout: the id_token_hint verified but is not an ID token (an access token, a logout"
                        + " token or another JWT this PF signed); no session-revoked signal is raised for it");
                return LogoutEventFilter.Hint.refused(LogoutEventFilter.HINT_NOT_ID_TOKEN);
            }
            long iat = claims.getIssuedAt().getValue();
            if (iat > nowSeconds + CLOCK_SKEW_SECONDS || nowSeconds - iat > maxAgeSeconds) {
                LOGGER.info((Object) ("logout: the id_token_hint was issued " + (nowSeconds - iat) + " s ago, outside "
                        + LogoutEventFilter.MAX_AGE_SETTING + " (" + maxAgeSeconds + " s); no session-revoked signal is"
                        + " raised for it"));
                return LogoutEventFilter.Hint.refused(LogoutEventFilter.HINT_TOO_OLD);
            }
            String sub = claims.getSubject();
            String iss = claims.getIssuer();
            SubjectId subject = SubjectId.issSub(iss, sub);
            String sid = claims.getClaimValueAsString("sid");
            String session = sid != null && !sid.isBlank() ? "sid:" + iss + "|" + sid : "sub:" + subject.canonicalKey();
            return LogoutEventFilter.Hint.of(subject, session + "|" + iat, iat);
        }
        catch (org.jose4j.jwt.consumer.InvalidJwtException e) {
            // jose4j's own message carries the whole id_token_hint - a token naming the user - so only the
            // reason is logged, never the text.
            LOGGER.info((Object) ("logout: token did not verify against PF's signing keys ("
                    + com.pingidentity.ps.oidf.jose.JwtCodec.safe(e).code() + ")"));
            return LogoutEventFilter.Hint.refused(LogoutEventFilter.HINT_INVALID);
        }
        catch (Exception e) {
            LOGGER.info((Object) ("logout: token did not verify against PF's signing keys ("
                    + e.getClass().getSimpleName() + ")"));
            return LogoutEventFilter.Hint.refused(LogoutEventFilter.HINT_INVALID);
        }
    }

    /**
     * Whether a verified JWT is an ID token: no {@code typ} or {@code typ JWT}, every claim OpenID Connect Core 1.0 §2
     * requires of one, and none of {@link #NOT_ID_TOKEN_CLAIMS}.
     */
    static boolean isIdToken(String typ, JwtClaims claims) {
        if (typ != null && !"JWT".equalsIgnoreCase(typ)) {
            return false;
        }
        for (String claim : NOT_ID_TOKEN_CLAIMS) {
            if (claims.hasClaim(claim)) {
                return false;
            }
        }
        for (String claim : ID_TOKEN_CLAIMS) {
            if (!claims.hasClaim(claim)) {
                return false;
            }
        }
        return true;
    }

    /** Test seam. */
    static PfIdTokenVerifier withKeys(JsonWebKeySet jwks, String expectedIssuer) {
        return new PfIdTokenVerifier(() -> jwks, expectedIssuer);
    }

    static List<String> acceptedAlgorithms() {
        return List.copyOf(ACCEPTED_ALGORITHMS);
    }
}
