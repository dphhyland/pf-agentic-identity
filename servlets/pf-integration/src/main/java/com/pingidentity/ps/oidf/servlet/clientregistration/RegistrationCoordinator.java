/*
 * Bounds the registration work unauthenticated requests can start.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Every automatic registration starts from a request nobody has authenticated yet, and resolving one means
 * fetching statements from the federation. OpenID Federation 1.0 §18.1 warns what that invites. This keeps it
 * bounded: one registration of a client at a time (a second request for it waits briefly, then finds the work
 * done), and at most so many resolved at once across every client. A request that cannot get either is answered
 * 503 - retry shortly - and held against nobody.
 *
 * <p>There is deliberately no per-client rate limit: whoever names a client could spend it, and the real client
 * would find it gone. What stops one stranger repeating the same work is elsewhere - failures remembered per
 * chain, successes kept briefly, and a presented chain validated only on its own.
 */
final class RegistrationCoordinator {
    private static final int STRIPES = 64;

    private final ReentrantLock[] stripes = new ReentrantLock[STRIPES];
    private final Semaphore resolutions;
    private final long lockWaitMillis;

    /** One unit of registration work. */
    @FunctionalInterface
    interface Work {
        void run() throws Exception;
    }

    RegistrationCoordinator(int maxConcurrentResolutions, long lockWaitMillis) {
        for (int i = 0; i < STRIPES; i++) {
            this.stripes[i] = new ReentrantLock();
        }
        this.resolutions = new Semaphore(maxConcurrentResolutions);
        this.lockWaitMillis = lockWaitMillis;
    }

    /**
     * Runs {@code work} for {@code clientId}: alone among registrations of that client, and within the limit on
     * registrations resolved at once.
     *
     * @throws RegistrationRejectedException {@link RegistrationRejectedException.Kind#BUSY} when it could not start
     */
    void register(String clientId, Work work) throws Exception {
        ReentrantLock lock = this.stripes[Math.floorMod(clientId.hashCode(), STRIPES)];
        if (!acquire(lock)) {
            throw RegistrationRejectedException.busy("another registration of this client is still in progress; try again shortly");
        }
        try {
            if (!this.resolutions.tryAcquire()) {
                throw RegistrationRejectedException.busy("too many federation registrations are being resolved; try again shortly");
            }
            try {
                work.run();
            } finally {
                this.resolutions.release();
            }
        } finally {
            lock.unlock();
        }
    }

    private boolean acquire(ReentrantLock lock) throws InterruptedException {
        return lock.tryLock(this.lockWaitMillis, TimeUnit.MILLISECONDS);
    }
}
