package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.ResolutionBudget;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
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
            coordinator.register(clientId, budget -> {
                started.countDown();
                release.await(5, TimeUnit.SECONDS);
            });
            return null;
        });
    }

    @Test
    void theWorkRuns() throws Exception {
        AtomicInteger runs = new AtomicInteger();
        new RegistrationCoordinator(1, 0L).register("https://rp.example", budget -> runs.incrementAndGet());
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
                () -> coordinator.register("https://rp.example", budget -> { }));

        assertEquals(503, e.status());
        assertEquals("temporarily_unavailable", e.error());
        assertEquals(RegistrationRejectedException.Kind.BUSY, e.kind());
        release.countDown();
        first.get(5, TimeUnit.SECONDS);
        AtomicInteger after = new AtomicInteger();
        coordinator.register("https://rp.example", budget -> after.incrementAndGet());
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
                () -> coordinator.register("https://two.example", budget -> { }));

        assertEquals(RegistrationRejectedException.Kind.BUSY, e.kind());
        assertTrue(e.getMessage().contains("too many"), e.getMessage());
        release.countDown();
        first.get(5, TimeUnit.SECONDS);
    }

    @Test
    void aFailureIsPassedOnAndFreesTheSlot() throws Exception {
        RegistrationCoordinator coordinator = new RegistrationCoordinator(1, 0L);
        IllegalStateException failure = new IllegalStateException("boom");

        assertSame(failure, assertThrows(IllegalStateException.class, () -> coordinator.register("https://rp.example", budget -> {
            throw failure;
        })));
        AtomicInteger runs = new AtomicInteger();
        coordinator.register("https://rp.example", budget -> runs.incrementAndGet());
        assertEquals(1, runs.get());
    }

    /** Resolution settings of 24 requests and a 45 s wall clock, the catalogue's defaults. */
    private static ValidatorOptions resolution() {
        return ValidatorOptions.defaults().withMaxFetches(24).withResolutionWallClock(Duration.ofSeconds(45));
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void theWorkIsGivenABudgetOfTheResolutionSettingsCutToTheDeadline() throws Exception {
        AtomicReference<ResolutionBudget> given = new AtomicReference<>();
        new RegistrationCoordinator(8, 2_000L, resolution(), Duration.ofSeconds(25), System::nanoTime)
                .register("https://rp.example", given::set);

        assertEquals(24, given.get().requests(), "the resolution settings' requests");
        assertTrue(given.get().wallClock().compareTo(Duration.ofSeconds(25)) <= 0, "the deadline, not the 45 s wall clock: " + given.get());
        assertTrue(given.get().wallClock().compareTo(Duration.ofSeconds(24)) > 0, given.get().toString());
    }

    @Test
    void aWallClockShorterThanTheDeadlineIsKept() throws Exception {
        AtomicReference<ResolutionBudget> given = new AtomicReference<>();
        new RegistrationCoordinator(8, 0L, resolution().withResolutionWallClock(Duration.ofSeconds(5)), Duration.ofSeconds(25), System::nanoTime)
                .register("https://rp.example", given::set);

        assertEquals(Duration.ofSeconds(5), given.get().wallClock());
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void theTimeSpentWaitingForTheLockComesOffTheBudget() throws Exception {
        AtomicLong now = new AtomicLong();
        RegistrationCoordinator coordinator = new RegistrationCoordinator(8, 2_000L, resolution(), Duration.ofSeconds(25), now::get);
        long asked = now.get();
        now.addAndGet(Duration.ofMillis(1_500).toNanos());

        assertEquals(Duration.ofMillis(23_500), coordinator.budget(asked).wallClock());
    }

    @Test
    void aRegistrationThatWaitedPastItsDeadlineIsTurnedAwayBusy() {
        AtomicLong now = new AtomicLong();
        RegistrationCoordinator coordinator = new RegistrationCoordinator(8, 2_000L, resolution(), Duration.ofSeconds(25), now::get);
        now.addAndGet(Duration.ofSeconds(25).toNanos());

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> coordinator.budget(0L));

        assertEquals(RegistrationRejectedException.Kind.BUSY, e.kind());
        assertEquals(503, e.status());
    }

    @Test
    void aLockWaitAsLongAsTheDeadlineIsRefused() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new RegistrationCoordinator(8, 25_000L, resolution(), Duration.ofSeconds(25), System::nanoTime));

        assertTrue(e.getMessage().contains("OIDF_AUTO_REGISTRATION_LOCK_WAIT_MS"), e.getMessage());
        assertTrue(e.getMessage().contains(RegistrationCoordinator.DEADLINE_SETTING), e.getMessage());
    }

    @Test
    void theDeadlineIsReadFromTheRegistrationCatalogue() {
        assertEquals(RegistrationCoordinator.DEFAULT_DEADLINE, RegistrationCoordinator.configuredDeadline());
    }
}
