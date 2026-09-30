/*
 * The boot path never throws: a store that cannot be opened is logged, retried, and the loops start when it can be.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import java.util.Optional;
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

    /**
     * Until the retry has started the push loop, which it does last - after configure, which assigns the
     * configuration, and after the wiring. Waiting on the configuration alone raced the retry's thread.
     */
    private static void awaitPushLoop() throws InterruptedException {
        for (int i = 0; i < 200; i++) {
            try {
                if (SsfSupport.pushDeliveryService().isRunning()) {
                    return;
                }
            } catch (IllegalStateException notYet) {
                // not configured yet
            }
            Thread.sleep(50);
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
        assertEquals("oidf-ssf-boot-retry",
                ManagedExecutors.live(SsfSupport.BOOT_RETRY).orElseThrow().threadNamePrefix(), "on a managed executor");
    }

    @Test
    void noRetryIsScheduledHereWhileAnotherCopyRunsTheBootRetry() {
        SsfSupport.bootRetrySeconds = 3600;
        SsfSupport.installStoreFactory(failingFirst(Integer.MAX_VALUE));
        String claim = "oidf.exec.owner." + SsfSupport.BOOT_RETRY;
        System.setProperty(claim, "another-copy");
        try {
            assertFalse(SsfSupport.start(JDBC, wired::incrementAndGet), "still no exception out of init");
            assertFalse(SsfSupport.bootRetryPending(), "the retry belongs to the copy that runs it");
            assertEquals(Optional.empty(), ManagedExecutors.live(SsfSupport.BOOT_RETRY));
        } finally {
            System.clearProperty(claim);
        }
    }

    /** The store comes back on the second retry, and the transmitter comes up on it - wiring and push loop included. */
    @Test
    void theRetryBringsTheTransmitterUpOnceTheStoreOpens() throws Exception {
        SsfSupport.bootRetrySeconds = 0;
        SsfSupport.installStoreFactory(failingFirst(2));

        assertFalse(SsfSupport.start(JDBC, wired::incrementAndGet));
        awaitPushLoop();

        assertTrue(SsfSupport.pushDeliveryService().isRunning(), "the loop started on the retry that succeeded");
        assertEquals(1, wired.get(), "the wiring ran once, on that retry");
        assertFalse(SsfSupport.bootRetryPending());
        assertTrue(SsfSupport.start(JDBC, wired::incrementAndGet), "and start now answers up");
    }

    /**
     * A JDBC URL can carry a password, and the driver's message repeats it: the ERROR names the cause chain
     * with the URL replaced.
     */
    @Test
    void theBootErrorNamesTheCauseChainWithoutTheJdbcUrl() {
        String url = "jdbc:postgresql://db.example.com/idm?user=ssf&password=hunter2";
        RuntimeException e = new IllegalStateException("failed to apply SSF schema",
                new java.sql.SQLException("No suitable driver found for " + url));

        assertEquals("java.lang.IllegalStateException: failed to apply SSF schema; caused by "
                + "java.sql.SQLException: No suitable driver found for <jdbcUrl>", SsfSupport.describe(e, url));
        assertEquals("java.lang.RuntimeException", SsfSupport.describe(new RuntimeException(), null),
                "no message, no URL to replace");
        assertEquals("java.lang.IllegalStateException: x", SsfSupport.describe(new IllegalStateException("x"), ""));
    }

    /** A cause chain that loops back on itself is cut at eight, not followed for ever. */
    @Test
    void aCauseChainThatLoopsIsCut() {
        RuntimeException a = new RuntimeException("a");
        RuntimeException b = new RuntimeException("b", a);
        a.initCause(b);

        String line = SsfSupport.describe(a, null);

        assertEquals(7, line.split("; caused by ", -1).length - 1, line);
    }

    /**
     * The stack trace goes with the first failure only, so a store that is down for an hour is 120 lines, not
     * 120 stack traces; and never with a jdbcUrl store's, because a logged exception prints its messages as
     * they are.
     */
    @Test
    void theStackTraceIsLoggedOnceAndNeverForAJdbcUrlStore() {
        RuntimeException e = new IllegalStateException("connection refused");
        assertEquals(e, SsfSupport.logBootFailure(JDBC, e), "the first failure, with its stack");
        assertNull(SsfSupport.logBootFailure(JDBC, e), "a retry's: one line");

        SsfSupport.resetForTests();
        SsfConfiguration byUrl = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .jdbcUrl("jdbc:postgresql://db.example.com/idm?password=hunter2").build();
        assertNull(SsfSupport.logBootFailure(byUrl, e), "a jdbcUrl store's first failure: one line");
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
