/*
 * The event bridge is best-effort: it never throws and returns 0 when SSF isn't configured.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfEventBridgeTest {

    @BeforeEach
    @AfterEach
    void reset() {
        SsfSupport.resetForTests();
        SsfEventBridge.resetRecentForTests();
    }

    @Test
    void bridgeSwallowsUnconfiguredStateAndReturnsZero() {
        // SSF not configured -> SsfSupport.eventEmitter() throws -> bridge must catch and return 0, not break PF
        assertEquals(0, SsfEventBridge.onSessionRevoked(SubjectId.email("a@b.com"), "logout"));
        assertEquals(0, SsfEventBridge.onAccountDisabledEmail("a@b.com", "hijacking"));
        assertEquals(0, SsfEventBridge.onSessionRevoked("https://op.example.com", "user-1", null));
    }

    @Test
    void nullSubjectIsANoOp() {
        assertEquals(0, SsfEventBridge.onSessionRevoked(null, "logout"));
    }

    @Test
    void duplicateSameTypeAndSubjectWithinWindowIsSuppressed() {
        // a logout seen by both LogoutEventFilter and the audit SLO event must emit only once
        SubjectId bob = SubjectId.issSub("https://op.example.com", "bob");
        SsfEventBridge.recordEmission("session-revoked", bob);
        assertEquals(true, SsfEventBridge.suppressed("session-revoked", bob));
        // a different event type or subject is NOT suppressed
        assertEquals(false, SsfEventBridge.suppressed("account-disabled", bob));
        assertEquals(false, SsfEventBridge.suppressed("session-revoked",
                SubjectId.issSub("https://op.example.com", "carol")));
        // and the window clears with reset (stands in for time passing)
        SsfEventBridge.resetRecentForTests();
        assertEquals(false, SsfEventBridge.suppressed("session-revoked", bob));
    }
}
