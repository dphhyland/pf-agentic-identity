/*
 * Logout filter: signals only after a logout PingFederate did not fail, for an accepted hint, once; always runs the chain.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.ThreadContext;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LogoutEventFilterTest {

    private static final String PF_ISSUER = "https://as.example.com";
    private static final SubjectId ALICE = SubjectId.issSub(PF_ISSUER, "alice");

    private final List<Event> events = new CopyOnWriteArrayList<>();
    private final List<String> revoked = new ArrayList<>();

    @BeforeEach
    void capture() {
        Events.reset();
        Events.configure(this.events::add);
    }

    @AfterEach
    void release() {
        Events.reset();
        ThreadContext.clearAll();
    }

    private LogoutEventFilter filter(LogoutEventFilter.HintReader reader) {
        return new LogoutEventFilter(reader, (s, r, txn) -> this.revoked.add(s.canonicalKey() + "|" + r + "|" + txn),
                new LogoutEventFilter.Replay(LogoutEventFilter.Replay.CAPACITY));
    }

    private static HttpServletResponse response(int status, String location) {
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getStatus()).thenReturn(status);
        when(resp.getHeader("Location")).thenReturn(location);
        return resp;
    }

    private static LogoutEventFilter.Hint hint(long iat) {
        return LogoutEventFilter.Hint.of(ALICE, "sub:" + ALICE.canonicalKey() + "|" + iat, iat);
    }

    private List<String> refusals() {
        return this.events.stream().filter(e -> "ssf.logout.signal.refused".equals(e.code())).map(Event::reason).toList();
    }

    @Test
    void signalsSessionRevokedAfterALogoutPingFederateHandedOn() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        FilterChain chain = mock(FilterChain.class);
        HttpServletResponse resp = response(200, null); // 13.1.3's hand-off to /idp/startSLO.ping
        ThreadContext.put("transactionid", "tx-1");

        filter(r -> hint(LogoutEventFilter.nowSeconds())).doFilter(req, resp, chain);

        verify(chain, times(1)).doFilter(req, resp);
        assertEquals(List.of(ALICE.canonicalKey() + "|logout|tx-1"), this.revoked, "PingFederate's transactionid is the txn");
        assertTrue(refusals().isEmpty());
    }

    @Test
    void theEndToEndPathVerifiesTheHintBeforeSignalling() throws Exception {
        RsaJsonWebKey pfKey = LogoutSubjectVerificationTest.key("pf-1");
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("id_token_hint")).thenReturn(
                LogoutSubjectVerificationTest.idToken(pfKey, PF_ISSUER, "alice", LogoutEventFilter.nowSeconds()));
        LogoutEventFilter f = filter(r -> LogoutEventFilter.readVerifiedHint(r, PfIdTokenVerifier.withKeys(new JsonWebKeySet(pfKey), PF_ISSUER),
                LogoutSubjectVerificationTest.settings(Map.of())));

        f.doFilter(req, response(200, null), mock(FilterChain.class));
        assertEquals(1, this.revoked.size());
        assertTrue(this.revoked.get(0).startsWith(ALICE.canonicalKey() + "|logout|"));
        assertNull(LogoutEventFilter.transactionId(), "no transactionid on this thread: the emitter mints the txn");
    }

    @Test
    void aFailedLogoutRaisesNothing() throws Exception {
        long iat = LogoutEventFilter.nowSeconds();
        filter(r -> hint(iat)).doFilter(mock(HttpServletRequest.class), response(400, null), mock(FilterChain.class));
        filter(r -> hint(iat + 1)).doFilter(mock(HttpServletRequest.class),
                response(302, "https://rp.example/after?error=access_denied"), mock(FilterChain.class));
        FilterChain throwing = mock(FilterChain.class);
        doThrow(new IOException("PF failed")).when(throwing).doFilter(any(), any());
        assertThrows(IOException.class, () -> filter(r -> hint(iat + 2)).doFilter(mock(HttpServletRequest.class),
                response(200, null), throwing), "the chain's own failure still reaches the container");

        assertTrue(this.revoked.isEmpty());
        assertEquals(List.of("logout_failed", "logout_failed", "logout_failed"), refusals());
    }

    @Test
    void aRedirectWithoutAnErrorOrAPlainServletResponseIsNotAFailure() {
        assertFalse(LogoutEventFilter.failed(true, response(302, "https://rp.example/after?state=x")));
        assertFalse(LogoutEventFilter.failed(true, mock(ServletResponse.class)));
        assertTrue(LogoutEventFilter.failed(true, response(302, "https://rp.example/after#error=x")));
        assertTrue(LogoutEventFilter.failed(false, response(200, null)));
    }

    @Test
    void aRefusedHintIsCountedWithItsReason() throws Exception {
        for (String reason : List.of(LogoutEventFilter.HINT_INVALID, LogoutEventFilter.HINT_TOO_OLD,
                LogoutEventFilter.HINT_NOT_ID_TOKEN)) {
            filter(r -> LogoutEventFilter.Hint.refused(reason)).doFilter(mock(HttpServletRequest.class), response(200, null),
                    mock(FilterChain.class));
        }
        assertTrue(this.revoked.isEmpty());
        assertEquals(List.of("hint_invalid", "hint_too_old", "hint_not_id_token"), refusals());
    }

    /** At most once per (sid or sub, iat) within the bound: the same hint presented again raises nothing. */
    @Test
    void aReplayedHintRaisesNothing() throws Exception {
        long iat = LogoutEventFilter.nowSeconds();
        LogoutEventFilter f = filter(r -> hint(iat));
        f.doFilter(mock(HttpServletRequest.class), response(200, null), mock(FilterChain.class));
        f.doFilter(mock(HttpServletRequest.class), response(200, null), mock(FilterChain.class));
        filter(r -> hint(iat)); // another filter instance has its own memory; the one PF maps is the one that counts

        assertEquals(1, this.revoked.size());
        assertEquals(List.of("replayed"), refusals());
        f.doFilter(mock(HttpServletRequest.class), response(200, null), mock(FilterChain.class));
        assertEquals(1, this.revoked.size());
        LogoutEventFilter g = filter(r -> hint(iat + 1));
        g.doFilter(mock(HttpServletRequest.class), response(200, null), mock(FilterChain.class));
        assertEquals(2, this.revoked.size(), "a new login's hint (another iat) signals");
    }

    @Test
    void theReplayMemoryForgetsWhatIsPastItsTimeAndStaysBounded() {
        LogoutEventFilter.Replay replay = new LogoutEventFilter.Replay(2);
        assertTrue(replay.firstUse("a", 100, 10));
        assertFalse(replay.firstUse("a", 100, 50));
        assertTrue(replay.firstUse("a", 200, 100), "past its time, the key is new again");
        assertTrue(replay.firstUse("b", 300, 100));
        assertTrue(replay.firstUse("c", 300, 250), "full: the expired a is swept");
        assertEquals(2, replay.size());
        assertTrue(replay.firstUse("d", 400, 260), "full and nothing expired: the oldest is dropped");
        assertEquals(2, replay.size());
        assertTrue(replay.firstUse("b", 400, 260), "b was the oldest");
    }

    @Test
    void aHintWithNoReplayKeySignalsEachTime() throws Exception {
        LogoutEventFilter f = filter(r -> LogoutEventFilter.Hint.of(SubjectId.opaque("dev"), null, 0));
        f.doFilter(mock(HttpServletRequest.class), response(200, null), mock(FilterChain.class));
        f.doFilter(mock(HttpServletRequest.class), response(200, null), mock(FilterChain.class));
        assertEquals(2, this.revoked.size(), "the development-only sub parameter has no iat to bound it");
    }

    @Test
    void noHintMeansNoSignalButLogoutStillRuns() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        new LogoutEventFilter().doFilter(mock(HttpServletRequest.class), mock(ServletResponse.class), chain);
        verify(chain).doFilter(any(), any());
        assertTrue(this.revoked.isEmpty());
        assertTrue(refusals().isEmpty());
    }

    @Test
    void extractorFailureIsFailOpen() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        filter(r -> {
            throw new RuntimeException("boom");
        }).doFilter(mock(HttpServletRequest.class), mock(ServletResponse.class), chain);
        verify(chain).doFilter(any(), any()); // logout still happened
        assertTrue(this.revoked.isEmpty());
    }

    @Test
    void sinkFailureDoesNotBreakLogout() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        new LogoutEventFilter(r -> hint(LogoutEventFilter.nowSeconds()), (s, r, t) -> {
            throw new RuntimeException("sink down");
        }, new LogoutEventFilter.Replay(4)).doFilter(mock(HttpServletRequest.class), response(200, null), chain);
        verify(chain).doFilter(any(), any()); // no exception propagated
    }

    /** The production sink goes through the bridge as the logout filter; with SSF not started it raises nothing. */
    @Test
    void theProductionSinkIsTheBridge() {
        org.junit.jupiter.api.Assumptions.assumeFalse(com.pingidentity.ps.oidf.ssf.SsfSupport.isConfigured());
        LogoutEventFilter.revoke(SubjectId.issSub(PF_ISSUER, "sink-" + System.nanoTime()), "logout", "tx-9");
        assertEquals(List.of("not_started"), this.events.stream().filter(e -> "ssf.set.dropped".equals(e.code()))
                .map(Event::reason).toList());
        assertEquals("logout", this.events.get(0).fields().get("source"));
    }

    /** OpenID Connect RP-Initiated Logout 1.0 §2: {@code id_token_hint} is the only token this endpoint takes. */
    @Test
    @Requirement("OIDC-RPL §2")
    void aLogoutTokenParameterIsNotRead() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("logout_token")).thenReturn("a.logout.token");
        assertNull(LogoutEventFilter.readVerifiedHint(req, (jwt, now, max) -> {
            throw new AssertionError("nothing to verify");
        }, LogoutSubjectVerificationTest.settings(Map.of())));
    }

    @Test
    void initAndDestroyDoNothing() {
        LogoutEventFilter f = new LogoutEventFilter();
        f.init(null);
        f.destroy();
        assertNull(LogoutEventFilter.readHint(mock(HttpServletRequest.class)), "no hint and no sub: nothing to read");
    }
}
