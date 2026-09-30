package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.Map;
import java.util.function.Consumer;
import jakarta.servlet.http.HttpServletRequest;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.Test;

/**
 * Whose session the transmitter says ended, and from which hints (plan item H-SSF-6, finding F-0022).
 *
 * <p>The emitted SET is signed by this transmitter, so a receiver cannot tell that the transmitter was
 * merely told whom to name. That made the subject's provenance the entire security property: on an
 * unauthenticated endpoint, an unverified token or a bare {@code sub} parameter let any caller aim a
 * {@code caep.session-revoked} at any user. A verified hint must also be an ID token and recent.
 */
class LogoutSubjectVerificationTest {

    private static final String PF_ISSUER = "https://as.example.com";

    static Settings settings(Map<String, String> env) {
        Catalogue catalogue = Catalogue.load(LogoutEventFilter.class.getClassLoader(), LogoutEventFilter.CATALOGUE);
        return Settings.of(catalogue, Sources.of(env::get, name -> null, name -> null));
    }

    private static final Settings DEFAULTS = settings(Map.of());

    static RsaJsonWebKey key(String kid) throws Exception {
        RsaJsonWebKey k = RsaJwkGenerator.generateJwk(2048);
        k.setKeyId(kid);
        return k;
    }

    /** An ID token as PingFederate 13.1.3 issues one (the rig, 2026-10-01): no typ, and these claims. */
    static String idToken(RsaJsonWebKey signer, String iss, String sub, long iat) throws Exception {
        return token(signer, null, c -> {
            c.setIssuer(iss);
            c.setSubject(sub);
            c.setAudience("some-client");
            c.setIssuedAt(NumericDate.fromSeconds(iat));
            c.setExpirationTime(NumericDate.fromSeconds(iat + 300));
            c.setClaim("auth_time", iat);
            c.setClaim("nonce", "n1");
            c.setGeneratedJwtId();
        });
    }

    static String token(RsaJsonWebKey signer, String typ, Consumer<JwtClaims> claims) throws Exception {
        JwtClaims c = new JwtClaims();
        claims.accept(c);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(signer.getRsaPrivateKey());
        jws.setKeyIdHeaderValue(signer.getKeyId());
        jws.setAlgorithmHeaderValue("RS256");
        if (typ != null) {
            jws.setHeader("typ", typ);
        }
        return jws.getCompactSerialization();
    }

    static long now() {
        return LogoutEventFilter.nowSeconds();
    }

    private static HttpServletRequest request(String idTokenHint, String subParam) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("id_token_hint")).thenReturn(idTokenHint);
        when(req.getParameter("sub")).thenReturn(subParam);
        return req;
    }

    private static LogoutEventFilter.Hint read(HttpServletRequest req, LogoutEventFilter.IdTokenVerifier verifier) {
        return LogoutEventFilter.readHint(req, verifier, DEFAULTS);
    }

    @Test
    void aTokenSignedByThisPfYieldsTheSubject() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        long iat = now() - 60;
        LogoutEventFilter.Hint hint = read(request(idToken(pfKey, PF_ISSUER, "alice", iat), null),
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER));

        assertNull(hint.refusal());
        assertEquals(SubjectId.issSub(PF_ISSUER, "alice"), hint.subject());
        assertEquals(iat, hint.issuedAt());
        assertTrue(hint.replayKey().endsWith("|" + iat), "the replay key is the session and the iat");
    }

    @Test
    void theReplayKeyIsTheSidWhenTheTokenHasOne() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        long iat = now();
        String withSid = token(pfKey, "JWT", c -> {
            c.setIssuer(PF_ISSUER);
            c.setSubject("alice");
            c.setAudience("rp");
            c.setIssuedAt(NumericDate.fromSeconds(iat));
            c.setExpirationTime(NumericDate.fromSeconds(iat + 300));
            c.setClaim("sid", "session-9");
        });
        LogoutEventFilter.Hint hint = read(request(withSid, null), PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER));
        assertEquals("sid:" + PF_ISSUER + "|session-9|" + iat, hint.replayKey());
    }

    /** OpenID Connect RP-Initiated Logout 1.0 §2: the OP "SHOULD accept ID Tokens ... even when the exp time has passed". */
    @Test
    @Requirement("OIDC-RPL §2")
    void anExpiredHintWithinTheAgeBoundStillIdentifiesTheSubject() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        long iat = now() - 3_600;   // an hour old, so its five-minute exp passed long ago
        LogoutEventFilter.Hint hint = read(request(idToken(pfKey, PF_ISSUER, "alice", iat), null),
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER));
        assertNotNull(hint.subject(), "an id_token_hint is routinely expired at logout");
    }

    @Test
    void aHintOlderThanTheBoundRaisesNothing() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        String old = idToken(pfKey, PF_ISSUER, "alice", now() - LogoutEventFilter.DEFAULT_MAX_AGE_SECONDS - 5);
        LogoutEventFilter.Hint hint = read(request(old, null), PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER));
        assertEquals(LogoutEventFilter.HINT_TOO_OLD, hint.refusal());
        assertNull(hint.subject());

        String future = idToken(pfKey, PF_ISSUER, "alice", now() + PfIdTokenVerifier.CLOCK_SKEW_SECONDS + 60);
        assertEquals(LogoutEventFilter.HINT_TOO_OLD,
                read(request(future, null), PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER)).refusal(),
                "an iat in the future is outside the bound too");
    }

    @Test
    void theAgeBoundIsASetting() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        Settings hour = settings(Map.of(LogoutEventFilter.MAX_AGE_SETTING, "3600"));
        String twoHours = idToken(pfKey, PF_ISSUER, "alice", now() - 7_200);
        assertEquals(LogoutEventFilter.HINT_TOO_OLD, LogoutEventFilter.readHint(request(twoHours, null),
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER), hour).refusal());
        assertEquals(3_600L, LogoutEventFilter.maxAgeSeconds(hour));
        assertEquals(LogoutEventFilter.DEFAULT_MAX_AGE_SECONDS, LogoutEventFilter.maxAgeSeconds(DEFAULTS));
        assertEquals(LogoutEventFilter.DEFAULT_MAX_AGE_SECONDS,
                LogoutEventFilter.maxAgeSeconds(settings(Map.of(LogoutEventFilter.MAX_AGE_SETTING, "a day"))),
                "a value that does not parse is the default, not no bound");
        assertEquals(LogoutEventFilter.DEFAULT_MAX_AGE_SECONDS,
                LogoutEventFilter.maxAgeSeconds(settings(Map.of(LogoutEventFilter.MAX_AGE_SETTING, "5"))),
                "below the catalogue's minimum is the default");
    }

    /**
     * The access token of the same login, signed with the same keys by the same issuer, raised a signal on the rig on
     * 2026-10-01 before this check. RFC 9068 §2.1: a JWT access token "MUST include this media type in the "typ" header
     * parameter"; §2.2: {@code client_id} "REQUIRED".
     */
    @Test
    void anAccessTokenPresentedAsTheHintRaisesNothing() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        long iat = now();
        String accessToken = token(pfKey, "at+jwt", c -> {
            c.setIssuer(PF_ISSUER);
            c.setSubject("alice");
            c.setClaim("client_id", "rp");
            c.setClaim("scope", "openid");
            c.setIssuedAt(NumericDate.fromSeconds(iat));
            c.setExpirationTime(NumericDate.fromSeconds(iat + 300));
        });
        assertEquals(LogoutEventFilter.HINT_NOT_ID_TOKEN,
                read(request(accessToken, null), PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER)).refusal());

        String untyped = token(pfKey, null, c -> {
            c.setIssuer(PF_ISSUER);
            c.setSubject("alice");
            c.setAudience("rp");
            c.setClaim("client_id", "rp");
            c.setIssuedAt(NumericDate.fromSeconds(iat));
            c.setExpirationTime(NumericDate.fromSeconds(iat + 300));
        });
        assertEquals(LogoutEventFilter.HINT_NOT_ID_TOKEN,
                read(request(untyped, null), PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER)).refusal(),
                "an untyped JWT with client_id is an access token too");
    }

    /**
     * OpenID Connect Back-Channel Logout 1.0 §2.4: a logout token's {@code events} claim is "REQUIRED", and "It is
     * RECOMMENDED that Logout Tokens be explicitly typed" {@code logout+jwt}.
     */
    @Test
    @Requirement("OIDC-BCL §2.4")
    void aLogoutTokenPresentedAsTheHintRaisesNothing() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        long iat = now();
        Consumer<JwtClaims> logoutClaims = c -> {
            c.setIssuer(PF_ISSUER);
            c.setSubject("alice");
            c.setAudience("rp");
            c.setIssuedAt(NumericDate.fromSeconds(iat));
            c.setExpirationTime(NumericDate.fromSeconds(iat + 300));
            c.setClaim("events", Map.of("http://schemas.openid.net/event/backchannel-logout", Map.of()));
        };
        PfIdTokenVerifier verifier = PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER);
        assertEquals(LogoutEventFilter.HINT_NOT_ID_TOKEN, read(request(token(pfKey, "logout+jwt", logoutClaims), null), verifier).refusal());
        assertEquals(LogoutEventFilter.HINT_NOT_ID_TOKEN, read(request(token(pfKey, null, logoutClaims), null), verifier).refusal(),
                "untyped, its events claim still marks it");
    }

    /** OpenID Connect Core 1.0 §2: iss, sub, aud, exp and iat are each REQUIRED in an ID token. */
    @Test
    @Requirement("OIDC-CORE §2")
    void aJwtWithoutTheIdTokenClaimsRaisesNothing() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        long iat = now();
        String noAud = token(pfKey, null, c -> {
            c.setIssuer(PF_ISSUER);
            c.setSubject("alice");
            c.setIssuedAt(NumericDate.fromSeconds(iat));
            c.setExpirationTime(NumericDate.fromSeconds(iat + 300));
        });
        assertEquals(LogoutEventFilter.HINT_NOT_ID_TOKEN,
                read(request(noAud, null), PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER)).refusal());
    }

    @Test
    void aTokenSignedBySomeoneElseIsRefused() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        RsaJsonWebKey attackerKey = key("pf-1");   // same kid, different key
        LogoutEventFilter.Hint hint = read(request(idToken(attackerKey, PF_ISSUER, "victim", now()), null),
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER));
        assertEquals(LogoutEventFilter.HINT_INVALID, hint.refusal(), "a token this PF did not sign must not name a subject");
        assertNull(hint.subject());
    }

    /** RP-Initiated Logout 1.0 §2: "the OP MUST validate that it was the issuer of the ID Token". */
    @Test
    @Requirement("OIDC-RPL §2")
    void aTokenFromAnotherIssuerIsRefused() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        assertEquals(LogoutEventFilter.HINT_INVALID, read(request(idToken(pfKey, "https://elsewhere.example", "victim", now()), null),
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER)).refusal());
    }

    @Test
    void noKeysOrAKeyLookupThatThrowsRefuses() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        String hint = idToken(pfKey, PF_ISSUER, "alice", now());
        assertEquals(LogoutEventFilter.HINT_INVALID, PfIdTokenVerifier.withKeys(new JsonWebKeySet(), PF_ISSUER)
                .verify(hint, now(), 60).refusal());
        assertEquals(LogoutEventFilter.HINT_INVALID, PfIdTokenVerifier.forDeployment(() -> {
            throw new IllegalStateException("PF is not there");
        }, PF_ISSUER).verify(hint, now(), 60).refusal());
        assertNull(PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER).verify(" ", now(), 60), "no token, no hint");
    }

    @Test
    void theEdgesOfTheVerifier() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        long iat = now();
        PfIdTokenVerifier verifier = PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER);
        assertNull(verifier.verify(null, iat, 60), "no token, no hint");
        assertEquals(LogoutEventFilter.HINT_INVALID, PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), " ")
                .verify(idToken(pfKey, PF_ISSUER, "alice", iat), iat, 60).refusal(), "a blank issuer is no issuer");
        assertEquals(LogoutEventFilter.HINT_INVALID, PfIdTokenVerifier.forDeployment(() -> null, PF_ISSUER)
                .verify(idToken(pfKey, PF_ISSUER, "alice", iat), iat, 60).refusal(), "no key set at all");
        String blankSid = token(pfKey, null, c -> {
            c.setIssuer(PF_ISSUER);
            c.setSubject("alice");
            c.setAudience("rp");
            c.setIssuedAt(NumericDate.fromSeconds(iat));
            c.setExpirationTime(NumericDate.fromSeconds(iat + 300));
            c.setClaim("sid", " ");
        });
        assertTrue(verifier.verify(blankSid, iat, 60).replayKey().startsWith("sub:"), "a blank sid is no sid");
        assertEquals(LogoutEventFilter.HINT_NOT_ID_TOKEN, verifier.verify(token(pfKey, "secevent+jwt", c -> {
            c.setIssuer(PF_ISSUER);
            c.setSubject("alice");
        }), iat, 60).refusal());
        String stringIat = token(pfKey, null, c -> {
            c.setIssuer(PF_ISSUER);
            c.setSubject("alice");
            c.setAudience("rp");
            c.setClaim("iat", "yesterday");
            c.setExpirationTime(NumericDate.fromSeconds(iat + 300));
        });
        assertEquals(LogoutEventFilter.HINT_INVALID, verifier.verify(stringIat, iat, 60).refusal(), "an iat that is not a number");
    }

    @Test
    void aBareSubParameterIsIgnoredByDefault() {
        LogoutEventFilter.IdTokenVerifier verifier = (jwt, now, maxAge) -> null;
        assertNull(read(request(null, "victim"), verifier),
                "THE spoofing path: an unauthenticated caller naming any subject must be ignored");
    }

    @Test
    void aBareSubParameterIsHonouredOnlyWhenExplicitlyAllowed() {
        Settings allowed = settings(Map.of("OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM", "true"));
        LogoutEventFilter.IdTokenVerifier verifier = (jwt, now, maxAge) -> LogoutEventFilter.Hint.refused(LogoutEventFilter.HINT_INVALID);

        LogoutEventFilter.Hint hint = LogoutEventFilter.readHint(request(null, "alice"), verifier, allowed);
        assertEquals(SubjectId.opaque("alice"), hint.subject(), "the dev-rig escape hatch still works when deliberately switched on");
        assertNull(hint.replayKey());
        assertEquals(SubjectId.opaque("bob"), LogoutEventFilter.readHint(request("not-a-jwt", "bob"), verifier, allowed).subject(),
                "a refused hint falls back to the sub parameter only when it is allowed");
        assertNull(LogoutEventFilter.readHint(request(null, " "), verifier, allowed));
    }

    /** Plan item ST-5: the switch is read through its catalogue, strictly; a value that does not parse takes nothing. */
    @Test
    void theSubParameterSwitchIsStrict() {
        java.util.function.Function<Map<String, String>, Boolean> read = env -> LogoutEventFilter.allowSubParameter(settings(env));
        assertTrue(read.apply(Map.of("OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM", "TRUE")));
        assertFalse(read.apply(Map.of()));
        assertFalse(read.apply(Map.of("OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM", "yes")), "refused in production: not taken");
        assertFalse(read.apply(Map.of("OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM", "yes", "OIDF_DEPLOYMENT_PROFILE", "development")),
                "a legacy spelling in development: false, as the old reader read it");
        assertFalse(read.apply(Map.of("OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM", "ture", "OIDF_DEPLOYMENT_PROFILE", "development")));
        assertFalse(LogoutEventFilter.allowSubParameter(), "this process sets neither");
        assertEquals(LogoutEventFilter.DEFAULT_MAX_AGE_SECONDS, LogoutEventFilter.maxAgeSeconds());
    }

    @Test
    void unsignedTokensAreRefusedRegardlessOfAlgorithmHeader() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        JsonWebSignature jws = new JsonWebSignature();
        JwtClaims c = new JwtClaims();
        c.setIssuer(PF_ISSUER);
        c.setSubject("victim");
        jws.setPayload(c.toJson());
        jws.setAlgorithmHeaderValue("none");
        jws.setAlgorithmConstraints(org.jose4j.jwa.AlgorithmConstraints.NO_CONSTRAINTS);
        assertEquals(LogoutEventFilter.HINT_INVALID, read(request(jws.getCompactSerialization(), null),
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER)).refusal());
    }

    /**
     * A verifier that does not know which issuer to expect must refuse every token rather than accept every one: with
     * no issuer there is nothing to enforce, and any JWT PF's keys ever signed would name the subject of a
     * {@code caep.session-revoked}.
     */
    @Test
    @Requirement("OIDC-CORE §3.1.3.7")
    void aVerifierWithNoExpectedIssuerRefusesEveryToken() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        PfIdTokenVerifier noIssuer = PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), null);

        assertEquals(LogoutEventFilter.HINT_INVALID,
                read(request(idToken(pfKey, "https://elsewhere.example", "victim", now()), null), noIssuer).refusal(),
                "without an expected issuer the issuer check is absent, not satisfied");
        assertEquals(LogoutEventFilter.HINT_INVALID, read(request(idToken(pfKey, PF_ISSUER, "alice", now()), null), noIssuer).refusal(),
                "fail closed: even a token from this PF is refused until the deployment says who this PF is");
    }

    /**
     * The production wiring: PF's signing keys plus the issuer PF reports for the request. Built through
     * the same factory the filter uses, with the two PF lookups injected, so what is asserted here is
     * the composition rather than a hand-built verifier.
     */
    @Test
    @Requirement("OIDC-CORE §3.1.3.7")
    void theDeploymentVerifierEnforcesTheIssuerPfReportsForTheRequest() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        HttpServletRequest foreign = request(idToken(pfKey, "https://elsewhere.example", "victim", now()), null);
        HttpServletRequest own = request(idToken(pfKey, PF_ISSUER, "alice", now()), null);

        assertEquals(LogoutEventFilter.HINT_INVALID,
                LogoutEventFilter.readHint(foreign, req -> PF_ISSUER, () -> new JsonWebKeySet(pfKey), DEFAULTS).refusal());
        LogoutEventFilter.Hint hint = LogoutEventFilter.readHint(own, req -> PF_ISSUER, () -> new JsonWebKeySet(pfKey), DEFAULTS);
        assertEquals(SubjectId.issSub(PF_ISSUER, "alice").toString(), hint.subject().toString());
        assertEquals(9, PfIdTokenVerifier.acceptedAlgorithms().size());
    }
}
