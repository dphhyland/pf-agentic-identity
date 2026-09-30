/*
 * Bounds the registration work unauthenticated requests can start.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.federation.ResolutionBudget;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/**
 * Every automatic registration starts from a request nobody has authenticated yet, and so does an explicit one
 * (OpenID Federation 1.0 §12.2: the posted Entity Configuration is self-signed), and resolving either means
 * fetching statements from the federation. §18.1 warns what that invites. This keeps it bounded: one registration
 * of a client at a time (a second request for it waits briefly, then finds the work done or does its own), at most
 * so many resolved at once across every client, and each one given a {@link ResolutionBudget} that ends by the
 * registration's deadline. A request that cannot get the lock or a place is answered 503 - retry shortly - and
 * held against nobody.
 *
 * <p>The deadline ({@value #DEADLINE_SETTING}) runs from when the request asks to register, so the time it waited
 * for the lock is taken off its budget: the lock wait and the resolution together never outlast it. The budget's
 * requests and wall clock are the {@code federation-resolution} settings' (plan item S5b), the wall clock cut to
 * what is left of the deadline.
 *
 * <p>There is deliberately no per-client rate limit: whoever names a client could spend it, and the real client
 * would find it gone. What stops one stranger repeating the same work is elsewhere - failures remembered per
 * chain, successes kept briefly, and a presented chain validated only on its own.
 */
final class RegistrationCoordinator {
    /** How long one registration may take, from asking to register to the end of its resolution. */
    static final String DEADLINE_SETTING = "OIDF_REGISTRATION_DEADLINE_SECONDS";
    /** The catalogue's default: under PingFederate's 30 s {@code pf.runtime.http.idleTimeout}, with room to answer. */
    static final Duration DEFAULT_DEADLINE = Duration.ofSeconds(25);
    private static final int STRIPES = 64;

    private final ReentrantLock[] stripes = new ReentrantLock[STRIPES];
    private final Semaphore resolutions;
    private final long lockWaitMillis;
    private final ValidatorOptions resolution;
    private final Duration deadline;
    private final LongSupplier nanoTime;

    /** One unit of registration work, spending from the budget it is given. */
    @FunctionalInterface
    interface Work {
        void run(ResolutionBudget budget) throws Exception;
    }

    /** With this process's {@code federation-resolution} settings and the default deadline. */
    RegistrationCoordinator(int maxConcurrentResolutions, long lockWaitMillis) {
        this(maxConcurrentResolutions, lockWaitMillis, ValidatorOptions.defaults(), DEFAULT_DEADLINE, System::nanoTime);
    }

    /**
     * @param resolution the requests and wall clock one resolution may spend
     * @param deadline   how long one registration may take, its wait for the lock included
     * @throws IllegalStateException when the lock wait is not shorter than the deadline: a request that waited it
     *     out would have nothing left to resolve with
     */
    RegistrationCoordinator(int maxConcurrentResolutions, long lockWaitMillis, ValidatorOptions resolution, Duration deadline,
                            LongSupplier nanoTime) {
        this.resolution = Objects.requireNonNull(resolution, "resolution");
        this.deadline = Objects.requireNonNull(deadline, "deadline");
        this.nanoTime = Objects.requireNonNull(nanoTime, "nanoTime");
        if (lockWaitMillis >= deadline.toMillis()) {
            throw new IllegalStateException(FederationRuntimeConfig.AUTO_REGISTRATION_LOCK_WAIT_MS_ENV + " (" + lockWaitMillis
                    + " ms) must be shorter than " + DEADLINE_SETTING + " (" + deadline.toMillis() + " ms): a registration that"
                    + " waited out the lock would have no time left to resolve its chain");
        }
        for (int i = 0; i < STRIPES; i++) {
            this.stripes[i] = new ReentrantLock();
        }
        this.resolutions = new Semaphore(maxConcurrentResolutions);
        this.lockWaitMillis = lockWaitMillis;
    }

    /** This process's registration deadline ({@value #DEADLINE_SETTING}, in the {@code registration} catalogue). */
    static Duration configuredDeadline() {
        return Settings.of("registration").duration(DEADLINE_SETTING);
    }

    /**
     * Runs {@code work} for {@code clientId}: alone among registrations of that client, within the limit on
     * registrations resolved at once, and with a budget that ends by the registration's deadline.
     *
     * @throws RegistrationRejectedException {@link RegistrationRejectedException.Kind#BUSY} when it could not start
     */
    void register(String clientId, Work work) throws Exception {
        long asked = this.nanoTime.getAsLong();
        ReentrantLock lock = this.stripes[Math.floorMod(clientId.hashCode(), STRIPES)];
        if (!acquire(lock)) {
            throw RegistrationRejectedException.busy("another registration of this client is still in progress; try again shortly");
        }
        try {
            if (!this.resolutions.tryAcquire()) {
                throw RegistrationRejectedException.busy("too many federation registrations are being resolved; try again shortly");
            }
            try {
                work.run(this.budget(asked));
            } finally {
                this.resolutions.release();
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * The budget for a registration asked for at {@code asked}: the resolution settings' requests, and their wall
     * clock or what is left of the deadline, whichever is shorter.
     *
     * @throws RegistrationRejectedException {@link RegistrationRejectedException.Kind#BUSY} when the deadline passed
     *     while it waited
     */
    ResolutionBudget budget(long asked) throws RegistrationRejectedException {
        Duration left = this.deadline.minusNanos(this.nanoTime.getAsLong() - asked);
        if (left.isNegative() || left.isZero()) {
            throw RegistrationRejectedException.busy("the registration waited past its deadline; try again shortly");
        }
        Duration wallClock = left.compareTo(this.resolution.resolutionWallClock()) < 0 ? left : this.resolution.resolutionWallClock();
        return ResolutionBudget.of(wallClock, this.resolution.maxFetches());
    }

    private boolean acquire(ReentrantLock lock) throws InterruptedException {
        return lock.tryLock(this.lockWaitMillis, TimeUnit.MILLISECONDS);
    }
}
