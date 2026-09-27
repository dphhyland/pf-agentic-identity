/*
 * What the authenticator tells PingFederate for each state of the decision, and when it refuses to say anything.
 */
package com.pingidentity.ps.oidf.cibasim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.cibasim.DecisionStore.Decision;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.sdk.oobauth.OOBAuthGeneralException;
import com.pingidentity.sdk.oobauth.OOBAuthRequestContext;
import com.pingidentity.sdk.oobauth.OOBAuthResultContext;
import com.pingidentity.sdk.oobauth.OOBAuthTransactionContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimOobAuthenticatorTest {

    private static Map<String, Object> params(String authReqId) {
        HashMap<String, Object> m = new HashMap<>();
        m.put(SimOobAuthenticator.AUTH_REQ_ID_PARAM, authReqId);
        return m;
    }

    private static OOBAuthRequestContext request() {
        OOBAuthRequestContext ctx = new OOBAuthRequestContext();
        ctx.setUserAuthBindingMessage("A1B2");
        ctx.setRequestedScope(Map.of("openid", "OpenID"));
        return ctx;
    }

    /** A rig's environment over {@code dir}, made private the way the gate wants it. */
    private static Map<String, String> rig(Path dir) throws Exception {
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        Map<String, String> env = new HashMap<>();
        env.put(SimulatorGate.ENABLED_ENV, "true");
        env.put(SimulatorGate.PROFILE_ENV, "development");
        env.put(SimulatorGate.DIR_ENV, dir.toString());
        return env;
    }

    private static SimOobAuthenticator plugin(Map<String, String> env) {
        return new SimOobAuthenticator(env::get, DecisionStore::at);
    }

    @Test
    @Requirement("CIBA §7.1")
    void initiateDerivesTheTransactionFromTheAuthReqIdAndRefusesToStartWithout(@TempDir Path dir) throws Exception {
        SimOobAuthenticator plugin = plugin(rig(dir));

        OOBAuthTransactionContext tx = plugin.initiate(request(), params("urn:req:1"));
        assertEquals(DecisionStore.txIdFor("urn:req:1"), tx.getTransactionIdentifier());
        assertFalse(tx.isStatusChangeCallbackCapable());
        assertEquals(tx.getTransactionIdentifier(), plugin.initiate(null, params("urn:req:1")).getTransactionIdentifier(),
                "no request context needed to derive it");

        assertThrows(OOBAuthGeneralException.class, () -> plugin.initiate(request(), params(" ")));
        assertThrows(OOBAuthGeneralException.class, () -> plugin.initiate(request(), params(null)));
        assertThrows(OOBAuthGeneralException.class, () -> plugin.initiate(request(), null));
        Map<String, Object> notAString = new HashMap<>();
        notAString.put(SimOobAuthenticator.AUTH_REQ_ID_PARAM, 42);
        assertThrows(OOBAuthGeneralException.class, () -> plugin.initiate(request(), notAString));
    }

    /**
     * The suite polls the token endpoint expecting authorization_pending before it decides, and two of
     * its modules never decide at all: no decision is in progress, never approval.
     */
    @Test
    @Requirement({"CIBA §10.1", "CIBA §11"})
    void checkIsInProgressUntilADecisionThenSuccessOrFailure(@TempDir Path dir) throws Exception {
        DecisionStore store = new DecisionStore(dir, Duration.ofMinutes(15), Clock.systemUTC());
        SimOobAuthenticator plugin = plugin(rig(dir));
        String tx = plugin.initiate(request(), params("urn:req:2")).getTransactionIdentifier();

        assertEquals(OOBAuthResultContext.Status.IN_PROGRESS, plugin.check(tx, Map.of()).getStatus());
        assertEquals(OOBAuthResultContext.Status.IN_PROGRESS, plugin.check(tx, null).getStatus(), "ping mode passes nothing");

        store.record("urn:req:2", Decision.ALLOW);
        OOBAuthResultContext allowed = plugin.check(tx, Map.of());
        assertEquals(OOBAuthResultContext.Status.SUCCESS, allowed.getStatus());
        assertNull(allowed.getApprovedScope(), "null = as requested");

        store.record("urn:req:2", Decision.DENY);
        OOBAuthResultContext denied = plugin.check(tx, Map.of());
        assertEquals(OOBAuthResultContext.Status.FAILURE, denied.getStatus());
        assertEquals("the user denied the request", denied.getStatusMessage());

        plugin.finished(tx);
        assertEquals(Optional.empty(), store.lookup(tx), "finished forgets the decision");
        assertEquals(OOBAuthResultContext.Status.IN_PROGRESS, plugin.check(tx, Map.of()).getStatus());
    }

    /** Off, in production, or over a directory the gate refuses: every entry point is a failure PingFederate hears about. */
    @Test
    void whereTheSimulatorMayNotRunEveryCallRefusesAndTouchesNothing(@TempDir Path dir) throws Exception {
        String tx = DecisionStore.txIdFor("urn:req:3");
        DecisionStore.at(dir).record("urn:req:3", Decision.ALLOW);

        Map<String, String> off = rig(dir);
        off.remove(SimulatorGate.ENABLED_ENV);
        Map<String, String> production = rig(dir);
        production.remove(SimulatorGate.PROFILE_ENV);
        Map<String, String> shared = rig(dir);
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-x---"));
        for (Map<String, String> env : List.of(off, production, shared)) {
            SimOobAuthenticator plugin = plugin(env);
            OOBAuthGeneralException initiate = assertThrows(OOBAuthGeneralException.class, () -> plugin.initiate(request(), params("urn:req:3")));
            assertTrue(initiate.getMessage().startsWith("the CIBA simulator may not run here: "), initiate.getMessage());
            assertThrows(OOBAuthGeneralException.class, () -> plugin.check(tx, Map.of()), "a recorded allow is never read");
            assertThrows(OOBAuthGeneralException.class, () -> plugin.finished(tx));
        }
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        assertEquals(Optional.of(Decision.ALLOW), DecisionStore.at(dir).lookup(tx), "and never forgotten either");
    }

    @Test
    void aStoreThatCannotBeReadIsAnOobFailureNotASilentPending(@TempDir Path dir) throws Exception {
        Map<String, String> env = rig(dir);
        String tx = DecisionStore.txIdFor("urn:req:4");
        // a decision file that cannot be read is an error PingFederate hears about
        DecisionStore unreadable = new DecisionStore(dir, Duration.ofMinutes(15), Clock.systemUTC()) {
            @Override
            public Optional<Decision> lookup(String txId) throws java.io.IOException {
                throw new java.io.IOException("disk gone");
            }

            @Override
            public void forget(String txId) throws java.io.IOException {
                throw new java.io.IOException("disk gone");
            }
        };
        SimOobAuthenticator broken = new SimOobAuthenticator(env::get, d -> unreadable);
        assertThrows(OOBAuthGeneralException.class, () -> broken.check(tx, Map.of()));
        assertThrows(OOBAuthGeneralException.class, () -> broken.finished(tx));
        try (Stream<Path> entries = Files.list(dir)) {
            assertTrue(entries.findAny().isEmpty());
        }
    }

    @Test
    void theContainerConstructorReadsTheProcessEnvironment() {
        // Nothing in this JVM's environment switches it on, so the plugin PingFederate would construct refuses.
        SimOobAuthenticator plugin = new SimOobAuthenticator();
        assertThrows(OOBAuthGeneralException.class, () -> plugin.check(DecisionStore.txIdFor("urn:req:5"), Map.of()));
        plugin.configure(null);
        assertEquals("Conformance CIBA simulator", plugin.getPluginDescriptor().getType());
    }
}
