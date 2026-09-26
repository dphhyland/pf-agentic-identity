package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The bound on registration work any unauthenticated request can start (OpenID Federation 1.0 §18.1): one registration
 * of a client at a time, so many at once across every client, and a 503 - held against nobody - for the rest.
 */
class RegistrationCoordinatorTest {

    private final ExecutorService pool = Executors.newFixedThreadPool(2);

    @AfterEach
    void stop() {
        this.pool.shutdownNow();
    }

    /** Starts {@code clientId}'s registration on another thread and holds it until {@code release} opens. */
    private Future<?> hold(RegistrationCoordinator coordinator, String clientId, CountDownLatch started, CountDownLatch release) {
        return this.pool.submit(() -> {
            coordinator.register(clientId, () -> {
                started.countDown();
                release.await(5, TimeUnit.SECONDS);
            });
            return null;
        });
    }

    @Test
    void theWorkRuns() throws Exception {
        AtomicInteger runs = new AtomicInteger();
        new RegistrationCoordinator(1, 0L).register("https://rp.example", runs::incrementAndGet);
        assertEquals(1, runs.get());
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aSecondRegistrationOfTheSameClientWaitsThenIsTurnedAway() throws Exception {
        RegistrationCoordinator coordinator = new RegistrationCoordinator(8, 50L);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<?> first = this.hold(coordinator, "https://rp.example", started, release);
        assertTrue(started.await(5, TimeUnit.SECONDS));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> coordinator.register("https://rp.example", () -> { }));

        assertEquals(503, e.status());
        assertEquals("temporarily_unavailable", e.error());
        assertEquals(RegistrationRejectedException.Kind.BUSY, e.kind());
        release.countDown();
        first.get(5, TimeUnit.SECONDS);
        AtomicInteger after = new AtomicInteger();
        coordinator.register("https://rp.example", after::incrementAndGet);
        assertEquals(1, after.get(), "free again once the first is done");
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void onlySoManyRegistrationsAreResolvedAtOnce() throws Exception {
        RegistrationCoordinator coordinator = new RegistrationCoordinator(1, 0L);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<?> first = this.hold(coordinator, "https://one.example", started, release);
        assertTrue(started.await(5, TimeUnit.SECONDS));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> coordinator.register("https://two.example", () -> { }));

        assertEquals(RegistrationRejectedException.Kind.BUSY, e.kind());
        assertTrue(e.getMessage().contains("too many"), e.getMessage());
        release.countDown();
        first.get(5, TimeUnit.SECONDS);
    }

    @Test
    void aFailureIsPassedOnAndFreesTheSlot() throws Exception {
        RegistrationCoordinator coordinator = new RegistrationCoordinator(1, 0L);
        IllegalStateException failure = new IllegalStateException("boom");

        assertSame(failure, assertThrows(IllegalStateException.class, () -> coordinator.register("https://rp.example", () -> {
            throw failure;
        })));
        AtomicInteger runs = new AtomicInteger();
        coordinator.register("https://rp.example", runs::incrementAndGet);
        assertEquals(1, runs.get());
    }
}
