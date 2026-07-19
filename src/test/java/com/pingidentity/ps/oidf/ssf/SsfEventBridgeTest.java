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
}
