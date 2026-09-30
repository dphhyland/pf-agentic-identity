/*
 * The transmitter's state is published whole or not at all, and a failed start leaves nothing behind to be read.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Finding F-0040 and plan item S-9: {@code SsfConfigurationServlet} loads at start-up and a database error in its init
 * escaped, and the shared state was published one member at a time. {@link SsfSupport#configure} now builds every
 * member first and publishes them in one write; {@link SsfSupport#start} throws what configuring threw, for the
 * {@code SSF} part to record ({@code SsfComponentsTest} holds the part's side).
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
        assertThrows(IllegalStateException.class, SsfSupport::receiverAuthenticator);
        assertNull(SsfSupport.receiverService());
        assertFalse(SsfSupport.isConfigured());
        assertEquals(SsfSupport.NOT_CONFIGURED, notConfigured.getMessage());

        assertTrue(SsfSupport.configure(JDBC), "and a later configure publishes it");
        assertFalse(SsfSupport.configure(JDBC), "once");
    }

    @Test
    void startThrowsWhatConfiguringThrewAndStartsNothing() {
        SsfSupport.installStoreFactory(failingFirst(1));

        assertThrows(IllegalStateException.class, () -> SsfSupport.start(JDBC, true, wired::incrementAndGet));

        assertEquals(0, wired.get(), "the wiring waits for a store");
        assertThrows(IllegalStateException.class, SsfSupport::pushDeliveryService, "and so does the push loop");

        SsfSupport.start(JDBC, true, wired::incrementAndGet);
        assertTrue(SsfSupport.pushDeliveryService().isRunning(), "the loop started on the start that succeeded");
        SsfSupport.start(JDBC, true, wired::incrementAndGet);
        assertEquals(1, wired.get(), "idempotent: the wiring ran once");
    }

    /**
     * No reader ever sees part of the state: while a configure is building a slow store, readers on other threads see
     * the transmitter not configured, and once any member is visible every member is, from the same configuration.
     */
    @Test
    void aConcurrentReaderSeesAllOfTheStateOrNone() throws Exception {
        CountDownLatch building = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        InMemorySsfStore slow = new InMemorySsfStore();
        SsfSupport.installStoreFactory(config -> {
            building.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return slow;
        });
        AtomicBoolean stop = new AtomicBoolean();
        AtomicReference<String> torn = new AtomicReference<>();
        AtomicInteger sawNothing = new AtomicInteger();
        AtomicInteger sawAll = new AtomicInteger();
        List<Thread> readers = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            Thread reader = new Thread(() -> {
                while (!stop.get()) {
                    SsfConfiguration cfg;
                    try {
                        cfg = SsfSupport.configuration();
                    } catch (IllegalStateException notYet) {
                        sawNothing.incrementAndGet();
                        if (SsfSupport.receiverService() != null) {
                            torn.set("a receiver without a configuration");
                        }
                        continue;
                    }
                    try {
                        if (SsfSupport.store() != slow || SsfSupport.streamService() == null || SsfSupport.pushDeliveryService() == null
                                || SsfSupport.eventEmitter() == null || SsfSupport.minter() == null || SsfSupport.emitService() == null
                                || SsfSupport.scimSubjectService() == null || SsfSupport.receiverAuthenticator() == null
                                || cfg != SsfSupport.configuration()) {
                            torn.set("a member missing or from another state");
                        }
                        sawAll.incrementAndGet();
                    } catch (IllegalStateException e) {
                        torn.set("a configuration without its other members: " + e.getMessage());
                    }
                }
            });
            reader.start();
            readers.add(reader);
        }
        Thread configuring = new Thread(() -> SsfSupport.configure(JDBC));
        configuring.start();
        assertTrue(building.await(10, TimeUnit.SECONDS));
        Thread.sleep(50);
        assertFalse(SsfSupport.isConfigured(), "nothing is published while the store is being built");
        release.countDown();
        configuring.join(10_000);
        Thread.sleep(50);
        stop.set(true);
        for (Thread reader : readers) {
            reader.join(10_000);
        }
        assertNull(torn.get(), torn.get());
        assertTrue(sawNothing.get() > 0 && sawAll.get() > 0, "readers ran before and after the publication");
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
     * The stack trace goes with the first failure only, so a store that is down for an hour is a line per retry, not a
     * stack trace per retry; and never with a jdbcUrl store's, because a logged exception prints its messages as they
     * are.
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

        SsfSupport.start(inMemory, true, () -> {
            throw new IllegalStateException("no PF here");
        });

        assertTrue(SsfSupport.pushDeliveryService().isRunning());
    }

    /** The receiver is built only when its component may run, whatever its settings say. */
    @Test
    void theReceiverIsBuiltOnlyWhenItsComponentMayRun() {
        SsfConfiguration receiver = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .receiverExpectedIssuer("https://transmitter.example.com").receiverAudience("https://op.example.com")
                .receiverEndpointAuthToken("t0ken").build();

        SsfSupport.configure(receiver, false);
        assertNull(SsfSupport.receiverService(), "SSF_RECEIVER switched off or refused");

        SsfSupport.resetForTests();
        SsfSupport.configure(receiver, true);
        assertTrue(SsfSupport.receiverService() != null);
    }

    /** A test's authenticator wins over the one configure built, and goes with a reset. */
    @Test
    void anInstalledAuthenticatorWinsOverTheBuiltOne() {
        SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com").build());
        ReceiverAuthenticator built = SsfSupport.receiverAuthenticator();
        ReceiverAuthenticator fake = token -> AuthContext.inactive();

        SsfSupport.installReceiverAuthenticator(fake);
        assertSame(fake, SsfSupport.receiverAuthenticator());
        SsfSupport.installReceiverAuthenticator(null);
        assertSame(built, SsfSupport.receiverAuthenticator());
    }
}
