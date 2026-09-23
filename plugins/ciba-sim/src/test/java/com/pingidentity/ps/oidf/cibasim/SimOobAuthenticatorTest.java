/*
 * What the authenticator tells PingFederate for each state of the decision.
 */
package com.pingidentity.ps.oidf.cibasim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.cibasim.DecisionStore.Decision;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.sdk.oobauth.OOBAuthGeneralException;
import com.pingidentity.sdk.oobauth.OOBAuthRequestContext;
import com.pingidentity.sdk.oobauth.OOBAuthResultContext;
import com.pingidentity.sdk.oobauth.OOBAuthTransactionContext;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
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

    @Test
    @Requirement("CIBA §7.1")
    void initiateDerivesTheTransactionFromTheAuthReqIdAndRefusesToStartWithout(@TempDir Path dir) throws Exception {
        SimOobAuthenticator plugin = new SimOobAuthenticator(new DecisionStore(dir, Duration.ofMinutes(15), Clock.systemUTC()));

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
        SimOobAuthenticator plugin = new SimOobAuthenticator(store);
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

    @Test
    void aStoreThatCannotBeReadIsAnOobFailureNotASilentPending(@TempDir Path dir) throws Exception {
        // a regular file where the directory should be: every read and every delete throws
        Path notADir = dir.resolve("decisions");
        java.nio.file.Files.writeString(notADir, "x");
        SimOobAuthenticator plugin = new SimOobAuthenticator(new DecisionStore(notADir, Duration.ofMinutes(15), Clock.systemUTC()));
        String tx = DecisionStore.txIdFor("urn:req:3");

        // lookup of a non-directory parent: Files.isRegularFile(dir/tx) is false, so this is "absent" - fine
        assertEquals(OOBAuthResultContext.Status.IN_PROGRESS, plugin.check(tx, Map.of()).getStatus());
        // but a decision file that cannot be read is an error PingFederate hears about
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
        SimOobAuthenticator broken = new SimOobAuthenticator(unreadable);
        assertThrows(OOBAuthGeneralException.class, () -> broken.check(tx, Map.of()));
        assertThrows(OOBAuthGeneralException.class, () -> broken.finished(tx));
    }
}
