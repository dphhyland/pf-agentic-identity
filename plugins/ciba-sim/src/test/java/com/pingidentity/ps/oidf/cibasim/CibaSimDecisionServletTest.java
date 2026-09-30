/*
 * The decision endpoint: a 404 wherever the simulator may not run, and exact about what it records.
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    /** A rig's environment over {@code dir}, which is made private the way the gate wants it. */
    private static Map<String, String> rig(Path dir) throws Exception {
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        Map<String, String> env = new HashMap<>();
        env.put(SimulatorGate.ENABLED_ENV, "true");
        env.put(SimulatorGate.PROFILE_ENV, "development");
        env.put(SimulatorGate.DIR_ENV, dir.toString());
        return env;
    }

    private static Exchange post(Map<String, String> env, String authReqId, String action) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("auth_req_id")).thenReturn(authReqId);
        when(req.getParameter("action")).thenReturn(action);
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(sink));

        new CibaSimDecisionServlet(env::get, DecisionStore::at).doPost(req, resp);

        ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
        verify(resp).setStatus(status.capture());
        return new Exchange(status.getValue(), sink.toString(StandardCharsets.UTF_8));
    }

    private static boolean empty(Path dir) throws Exception {
        try (Stream<Path> entries = Files.list(dir)) {
            return entries.findAny().isEmpty();
        }
    }

    @Test
    void offUnlessSwitchedOnAndNothingIsRecordedWhileOff(@TempDir Path dir) throws Exception {
        Map<String, String> env = rig(dir);
        env.remove(SimulatorGate.ENABLED_ENV);
        Exchange x = post(env, "urn:req:1", "allow");
        assertEquals(404, x.status);
        assertEquals("{\"error\":\"not_found\"}", x.body);
        assertTrue(empty(dir));
    }

    @Test
    void neverInProductionWhichIsTheDefault(@TempDir Path dir) throws Exception {
        Map<String, String> env = rig(dir);
        env.remove(SimulatorGate.PROFILE_ENV);
        assertEquals(404, post(env, "urn:req:1", "allow").status);
        env.put(SimulatorGate.PROFILE_ENV, "production");
        assertEquals(404, post(env, "urn:req:1", "allow").status);
        assertTrue(empty(dir));
    }

    @Test
    void aDirectoryTheGateRefusesIs404Too(@TempDir Path dir) throws Exception {
        Map<String, String> env = rig(dir);
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-x---"));
        assertEquals(404, post(env, "urn:req:1", "allow").status);
        env.put(SimulatorGate.DIR_ENV, dir.resolve("absent").toString());
        assertEquals(404, post(env, "urn:req:1", "allow").status);
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        assertTrue(empty(dir));
    }

    @Test
    void recordsAllowAndDenyAndAnswersTheTransaction(@TempDir Path dir) throws Exception {
        Map<String, String> env = rig(dir);
        DecisionStore store = DecisionStore.at(dir);
        Exchange allow = post(env, "urn:req:1", "allow");
        assertEquals(200, allow.status);
        assertTrue(allow.body.contains("\"action\":\"allow\""));
        assertTrue(allow.body.contains("\"tx\":\"" + DecisionStore.txIdFor("urn:req:1") + "\""));
        assertEquals(Optional.of(Decision.ALLOW), store.lookup(DecisionStore.txIdFor("urn:req:1")));

        assertEquals(200, post(env, "urn:req:1", "DENY").status);
        assertEquals(Optional.of(Decision.DENY), store.lookup(DecisionStore.txIdFor("urn:req:1")));
    }

    @Test
    void aMissingIdOrAnUnknownActionIs400AndRecordsNothing(@TempDir Path dir) throws Exception {
        Map<String, String> env = rig(dir);
        Exchange noId = post(env, " ", "allow");
        assertEquals(400, noId.status);
        assertTrue(noId.body.contains("auth_req_id"));
        assertEquals(400, post(env, null, "allow").status);

        Exchange badAction = post(env, "urn:req:2", "approve");
        assertEquals(400, badAction.status);
        assertTrue(badAction.body.contains("allow or deny"));
        assertEquals(400, post(env, "urn:req:2", null).status);
        assertTrue(empty(dir));
    }

    @Test
    void theContainerConstructorReadsTheProcessEnvironment() {
        // Nothing in this JVM's environment switches it on, so the servlet PingFederate would construct refuses.
        assertEquals(false, SimulatorGate.refusal(System::getenv) == null);
        new CibaSimDecisionServlet();
    }
}
