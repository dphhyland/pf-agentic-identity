package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.ssf.SubjectId;
import javax.servlet.http.HttpServletRequest;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Whose session the transmitter says ended.
 *
 * <p>The emitted SET is signed by this transmitter, so a receiver cannot tell that the transmitter was
 * merely told whom to name. That made the subject's provenance the entire security property: on an
 * unauthenticated endpoint, an unverified token or a bare {@code sub} parameter let any caller aim a
 * {@code caep.session-revoked} at any user.
 */
class LogoutSubjectVerificationTest {

    private static final String PF_ISSUER = "https://as.example.com";

    @AfterEach
    void clearFlag() {
        System.clearProperty("oidf.ssf.logout.allow.sub.param");
    }

    private static RsaJsonWebKey key(String kid) throws Exception {
        RsaJsonWebKey k = RsaJwkGenerator.generateJwk(2048);
        k.setKeyId(kid);
        return k;
    }

    private static String idToken(RsaJsonWebKey signer, String iss, String sub, boolean expired) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        c.setAudience("some-client");
        if (expired) {
            c.setIssuedAt(org.jose4j.jwt.NumericDate.fromSeconds(1000));
            c.setExpirationTime(org.jose4j.jwt.NumericDate.fromSeconds(2000));
        } else {
            c.setIssuedAtToNow();
            c.setExpirationTimeMinutesInTheFuture(10);
        }
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(signer.getRsaPrivateKey());
        jws.setKeyIdHeaderValue(signer.getKeyId());
        jws.setAlgorithmHeaderValue("RS256");
        return jws.getCompactSerialization();
    }

    private static HttpServletRequest request(String idTokenHint, String subParam) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("id_token_hint")).thenReturn(idTokenHint);
        when(req.getParameter("logout_token")).thenReturn(null);
        when(req.getParameter("sub")).thenReturn(subParam);
        return req;
    }

    @Test
    void aTokenSignedByThisPfYieldsTheSubject() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        LogoutEventFilter.IdTokenVerifier verifier =
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER);

        SubjectId subject = LogoutEventFilter.extractSubject(
                request(idToken(pfKey, PF_ISSUER, "alice", false), null), verifier);

        assertNotNull(subject);
    }

    @Test
    void anExpiredHintStillIdentifiesTheSubject() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        LogoutEventFilter.IdTokenVerifier verifier =
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER);

        assertNotNull(LogoutEventFilter.extractSubject(
                        request(idToken(pfKey, PF_ISSUER, "alice", true), null), verifier),
                "an id_token_hint is routinely expired at logout; its age says nothing about who it names");
    }

    @Test
    void aTokenSignedBySomeoneElseIsRefused() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        RsaJsonWebKey attackerKey = key("pf-1");   // same kid, different key
        LogoutEventFilter.IdTokenVerifier verifier =
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER);

        assertNull(LogoutEventFilter.extractSubject(
                        request(idToken(attackerKey, PF_ISSUER, "victim", false), null), verifier),
                "a token this PF did not sign must not name a subject");
    }

    @Test
    void aTokenFromAnotherIssuerIsRefused() throws Exception {
        RsaJsonWebKey pfKey = key("pf-1");
        LogoutEventFilter.IdTokenVerifier verifier =
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER);

        assertNull(LogoutEventFilter.extractSubject(
                request(idToken(pfKey, "https://elsewhere.example", "victim", false), null), verifier));
    }

    @Test
    void aBareSubParameterIsIgnoredByDefault() {
        LogoutEventFilter.IdTokenVerifier verifier = jwt -> null;

        assertNull(LogoutEventFilter.extractSubject(request(null, "victim"), verifier),
                "THE spoofing path: an unauthenticated caller naming any subject must be ignored");
    }

    @Test
    void aBareSubParameterIsHonouredOnlyWhenExplicitlyAllowed() {
        System.setProperty("oidf.ssf.logout.allow.sub.param", "true");
        LogoutEventFilter.IdTokenVerifier verifier = jwt -> null;

        assertNotNull(LogoutEventFilter.extractSubject(request(null, "alice"), verifier),
                "the dev-rig escape hatch still works when deliberately switched on");
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
        LogoutEventFilter.IdTokenVerifier verifier =
                PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER);

        assertNull(LogoutEventFilter.extractSubject(request(jws.getCompactSerialization(), null), verifier));
    }
}
