/*
 * The decision endpoint: off by default, and exact about what it records.
 */
package com.pingidentity.ps.oidf.cibasim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.cibasim.DecisionStore.Decision;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

class CibaSimDecisionServletTest {

    private static final class Exchange {
        final int status;
        final String body;

        Exchange(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }

    private static Exchange post(DecisionStore store, boolean enabled, String authReqId, String action) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("auth_req_id")).thenReturn(authReqId);
        when(req.getParameter("action")).thenReturn(action);
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(sink));

        CibaSimDecisionServlet.handle(req, resp, store, enabled);

        ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
        verify(resp).setStatus(status.capture());
        return new Exchange(status.getValue(), sink.toString(StandardCharsets.UTF_8));
    }

    @Test
    void offUnlessEnabledAndNothingIsRecordedWhileOff(@TempDir Path dir) throws Exception {
        DecisionStore store = new DecisionStore(dir, Duration.ofMinutes(15), Clock.systemUTC());
        Exchange x = post(store, false, "urn:req:1", "allow");
        assertEquals(404, x.status);
        assertEquals(Optional.empty(), store.lookup(DecisionStore.txIdFor("urn:req:1")));
    }

    @Test
    void recordsAllowAndDenyAndAnswersTheTransaction(@TempDir Path dir) throws Exception {
        DecisionStore store = new DecisionStore(dir, Duration.ofMinutes(15), Clock.systemUTC());
        Exchange allow = post(store, true, "urn:req:1", "allow");
        assertEquals(200, allow.status);
        assertTrue(allow.body.contains("\"action\":\"allow\""));
        assertTrue(allow.body.contains("\"tx\":\"" + DecisionStore.txIdFor("urn:req:1") + "\""));
        assertEquals(Optional.of(Decision.ALLOW), store.lookup(DecisionStore.txIdFor("urn:req:1")));

        assertEquals(200, post(store, true, "urn:req:1", "DENY").status);
        assertEquals(Optional.of(Decision.DENY), store.lookup(DecisionStore.txIdFor("urn:req:1")));
    }

    @Test
    void aMissingIdOrAnUnknownActionIs400AndRecordsNothing(@TempDir Path dir) throws Exception {
        DecisionStore store = new DecisionStore(dir, Duration.ofMinutes(15), Clock.systemUTC());
        Exchange noId = post(store, true, " ", "allow");
        assertEquals(400, noId.status);
        assertTrue(noId.body.contains("auth_req_id"));
        assertEquals(400, post(store, true, null, "allow").status);

        Exchange badAction = post(store, true, "urn:req:2", "approve");
        assertEquals(400, badAction.status);
        assertTrue(badAction.body.contains("allow or deny"));
        assertEquals(400, post(store, true, "urn:req:2", null).status);
        assertEquals(Optional.empty(), store.lookup(DecisionStore.txIdFor("urn:req:2")));
    }

    @Test
    void theSwitchIsReadFromTheEnvironment() {
        assertTrue(new CibaSimDecisionServlet(null, k -> "true").isEnabledForTests());
        assertTrue(new CibaSimDecisionServlet(null, k -> "TRUE").isEnabledForTests());
        assertEquals(false, new CibaSimDecisionServlet(null, k -> "yes").isEnabledForTests());
        assertEquals(false, new CibaSimDecisionServlet(null, k -> null).isEnabledForTests());
    }
}
