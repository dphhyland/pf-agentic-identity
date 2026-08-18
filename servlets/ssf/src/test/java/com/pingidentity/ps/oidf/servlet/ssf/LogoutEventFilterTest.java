/*
 * Logout filter: extracts the subject from id_token_hint/sub, always runs the chain, signals best-effort.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.ssf.SubjectId;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

class LogoutEventFilterTest {

    private static String idToken(String iss, String sub) throws Exception {
        RsaJsonWebKey k = RsaJwkGenerator.generateJwk(2048);
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(k.getPrivateKey());
        jws.setAlgorithmHeaderValue("RS256");
        return jws.getCompactSerialization();
    }

    @Test
    void signalsSessionRevokedAfterLogout() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("id_token_hint")).thenReturn(idToken("https://op.example.com", "user-1"));
        FilterChain chain = mock(FilterChain.class);
        ServletResponse resp = mock(ServletResponse.class);

        List<SubjectId> revoked = new ArrayList<>();
        // The subject now comes from a VERIFIED token, so this stubs the verifier rather than relying
        // on an unverified parse. What this test is about is the signal path, not provenance -
        // provenance is LogoutSubjectVerificationTest.
        LogoutEventFilter.IdTokenVerifier verifier = jwt -> SubjectId.issSub("https://op.example.com", "user-1");
        new LogoutEventFilter(req2 -> LogoutEventFilter.extractSubject(req2, verifier),
                (s, r) -> revoked.add(s)).doFilter(req, resp, chain);

        verify(chain, times(1)).doFilter(req, resp);
        assertEquals(1, revoked.size());
        assertEquals(SubjectId.issSub("https://op.example.com", "user-1"), revoked.get(0));
    }

    @Test
    void noSubjectMeansNoSignalButLogoutStillRuns() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class); // all params null
        FilterChain chain = mock(FilterChain.class);
        List<SubjectId> revoked = new ArrayList<>();

        new LogoutEventFilter(LogoutEventFilter::extractSubject, (s, r) -> revoked.add(s))
                .doFilter(req, mock(ServletResponse.class), chain);

        verify(chain).doFilter(any(), any());
        assertTrue(revoked.isEmpty());
    }

    @Test
    void extractorFailureIsFailOpen() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        FilterChain chain = mock(FilterChain.class);
        List<SubjectId> revoked = new ArrayList<>();

        new LogoutEventFilter(r -> {
            throw new RuntimeException("boom");
        }, (s, r) -> revoked.add(s)).doFilter(req, mock(ServletResponse.class), chain);

        verify(chain).doFilter(any(), any()); // logout still happened
        assertTrue(revoked.isEmpty());
    }

    @Test
    void sinkFailureDoesNotBreakLogout() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        FilterChain chain = mock(FilterChain.class);

        new LogoutEventFilter(r -> SubjectId.opaque("x"), (s, r) -> {
            throw new RuntimeException("sink down");
        }).doFilter(req, mock(ServletResponse.class), chain);

        verify(chain).doFilter(any(), any()); // no exception propagated
    }

    @Test
    void extractSubjectTakesTheTokenAndIgnoresABareSubParameter() throws Exception {
        // This used to assert "prefers token, THEN falls back to the sub parameter". That fallback was
        // the spoofing path - on an unauthenticated endpoint it let any caller name any subject - and
        // is now off unless explicitly enabled. Signature verification itself is covered in depth by
        // LogoutSubjectVerificationTest; here the verifier is stubbed to keep this test about routing.
        LogoutEventFilter.IdTokenVerifier accepts = jwt -> SubjectId.issSub("https://op.example.com", "u1");
        LogoutEventFilter.IdTokenVerifier rejects = jwt -> null;

        HttpServletRequest tokenReq = mock(HttpServletRequest.class);
        when(tokenReq.getParameter("id_token_hint")).thenReturn(idToken("https://op.example.com", "u1"));
        assertEquals(SubjectId.issSub("https://op.example.com", "u1"),
                LogoutEventFilter.extractSubject(tokenReq, accepts));

        HttpServletRequest subReq = mock(HttpServletRequest.class);
        when(subReq.getParameter("sub")).thenReturn("opaque-1");
        assertNull(LogoutEventFilter.extractSubject(subReq, rejects),
                "a bare sub parameter must not name a subject by default");

        HttpServletRequest garbage = mock(HttpServletRequest.class);
        when(garbage.getParameter("id_token_hint")).thenReturn("not-a-jwt");
        assertNull(LogoutEventFilter.extractSubject(garbage, rejects), "unverifiable token -> no subject");
    }
}
