/*
 * The boot path never throws: a store that cannot be opened is logged, retried, and the loops start when it can be.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * "Found while designing" 11: {@code SsfConfigurationServlet} loads at start-up and let a boot-time DB error
 * escape its {@code init}, which fails the whole {@code pf-runtime.war} (U-0076). {@link SsfSupport#start} is
 * the path every servlet's init takes now, and these are its promises; the same path was run in PingFederate
 * 13.1.3 with a store whose database came up after boot (the README's Boot section).
 */
class SsfSupportBootTest {

    private static final SsfConfiguration JDBC = new SsfConfiguration.Builder()
            .issuer("https://op.example.com").dataStoreId("pf-ds").build();

    private final AtomicInteger wired = new AtomicInteger();

    @BeforeEach
    void fresh() {
        SsfSupport.resetForTests();
    }

    @AfterEach
    void cleanUp() {
        SsfSupport.resetForTests();
    }

    /** A factory whose first {@code failures} calls throw, as a data store that is down at boot does. */
    private static SsfSupport.StoreFactory failingFirst(int failures) {
        AtomicInteger calls = new AtomicInteger();
        return config -> {
            if (calls.incrementAndGet() <= failures) {
                throw new IllegalStateException("failed to apply SSF schema: connection refused");
            }
            return new InMemorySsfStore();
        };
    }

    private static void awaitConfigured() throws InterruptedException {
        for (int i = 0; i < 200; i++) {
            try {
                SsfSupport.configuration();
                return;
            } catch (IllegalStateException notYet) {
                Thread.sleep(50);
            }
        }
        throw new AssertionError("the retry did not bring the transmitter up within 10 s");
    }

    /**
     * The half-configured state the old code left: {@code configuration} assigned before the store was
     * opened, so a failed open left a transmitter that reported itself configured, had no store, and
     * returned from every later configure at the first check.
     */
    @Test
    void aStoreThatCannotBeOpenedLeavesNothingConfigured() {
        SsfSupport.installStoreFactory(failingFirst(1));

        assertThrows(IllegalStateException.class, () -> SsfSupport.configure(JDBC));

        IllegalStateException notConfigured =
                assertThrows(IllegalStateException.class, SsfSupport::configuration, "not configured, not half-configured");
        assertThrows(IllegalStateException.class, SsfSupport::store);
        assertThrows(IllegalStateException.class, SsfSupport::pushDeliveryService);
        assertEquals(SsfSupport.NOT_CONFIGURED, notConfigured.getMessage(),
                "what a request's error says while the store is down: both causes, not \"no servlet init ran\"");
    }

    @Test
    void startDoesNotThrowWhenTheStoreIsDownAndSchedulesOneRetry() {
        SsfSupport.bootRetrySeconds = 3600;
        SsfSupport.installStoreFactory(failingFirst(Integer.MAX_VALUE));

        assertFalse(SsfSupport.start(JDBC, wired::incrementAndGet), "not up, and no exception out of init");
        assertTrue(SsfSupport.bootRetryPending(), "a retry is scheduled");
        assertFalse(SsfSupport.start(JDBC, wired::incrementAndGet), "a second servlet's init: still not up");
        assertTrue(SsfSupport.bootRetryPending(), "and it joined the pending retry rather than adding one");

        assertEquals(0, wired.get(), "the wiring waits for a store");
        assertThrows(IllegalStateException.class, SsfSupport::pushDeliveryService, "and so does the push loop");
    }

    /** The store comes back on the second retry, and the transmitter comes up on it - wiring and push loop included. */
    @Test
    void theRetryBringsTheTransmitterUpOnceTheStoreOpens() throws Exception {
        SsfSupport.bootRetrySeconds = 0;
        SsfSupport.installStoreFactory(failingFirst(2));

        assertFalse(SsfSupport.start(JDBC, wired::incrementAndGet));
        awaitConfigured();

        assertTrue(SsfSupport.pushDeliveryService().isRunning(), "the loop started on the retry that succeeded");
        assertEquals(1, wired.get(), "the wiring ran once, on that retry");
        assertFalse(SsfSupport.bootRetryPending());
        assertTrue(SsfSupport.start(JDBC, wired::incrementAndGet), "and start now answers up");
    }

    /** The servlet layer's wiring failing (a PF accessor outside PF, say) is logged; the loop still starts. */
    @Test
    void aWiringFailureIsLoggedAndThePushLoopStillStarts() {
        SsfConfiguration inMemory = new SsfConfiguration.Builder().issuer("https://op.example.com").build();

        assertTrue(SsfSupport.start(inMemory, () -> {
            throw new IllegalStateException("no PF here");
        }));

        assertTrue(SsfSupport.pushDeliveryService().isRunning());
        assertTrue(SsfSupport.start(inMemory, wired::incrementAndGet), "idempotent: a later servlet's init is a no-op that answers up");
        assertEquals(1, wired.get());
    }
}
