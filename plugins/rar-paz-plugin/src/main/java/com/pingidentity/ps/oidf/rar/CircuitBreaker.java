/*
 * Stops asking a PDP that has stopped answering, and tries it again after a while.
 */
package com.pingidentity.ps.oidf.rar;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * A circuit breaker over one processor instance's PDP transport. After {@code threshold} transport failures in a
 * row it opens for {@code openFor}: every call is answered "unreachable" at once, without touching the network. When
 * the time is up it half-opens and lets one call through as a trial; that call's outcome closes it again or opens it
 * for another {@code openFor}, and every other call during the trial is answered "unreachable" as if it were open.
 *
 * <p>Only a transport failure counts: the {@link PdpUnavailableException} the transport throws, which is
 * {@link PdpTransport#classify}'s set - connect, reset, deadline, a full bulkhead. A PDP that answers, with a 4xx,
 * a body that does not parse or anything else, is a PDP that is there: its answer is refused or believed as before,
 * never counted, and it ends a run of failures (plan S-2, S2a's rule: those fail closed; the breaker is for an
 * outage, and an outage is the one case fail-open may cover). The HTTP statuses that read as unavailable (429 and
 * 502-504) are decided after the transport returns and do not count either: a PDP that answers them quickly holds no
 * thread.
 *
 * <p>An answer while open is a {@link PdpUnavailableException}, so fail-open applies to it exactly where the
 * {@code pdp-fail-open} risk is accepted, and closed everywhere else.
 */
final class CircuitBreaker {

    enum State { CLOSED, OPEN, HALF_OPEN }

    static final int DEFAULT_THRESHOLD = 5;
    static final int DEFAULT_OPEN_SECONDS = 30;

    private final int threshold;
    private final long openNanos;
    private final LongSupplier clock;
    private State state = State.CLOSED;
    private int failures;
    private long openUntil;
    private boolean trialInFlight;

    CircuitBreaker(int threshold, int openSeconds, LongSupplier nanoClock) {
        this.threshold = threshold > 0 ? threshold : DEFAULT_THRESHOLD;
        this.openNanos = TimeUnit.SECONDS.toNanos(openSeconds > 0 ? openSeconds : DEFAULT_OPEN_SECONDS);
        this.clock = nanoClock;
    }

    CircuitBreaker(int threshold, int openSeconds) {
        this(threshold, openSeconds, System::nanoTime);
    }

    int threshold() {
        return threshold;
    }

    long openNanos() {
        return openNanos;
    }

    /** The state now: an open breaker whose time is up reads as half-open until a trial settles it. */
    synchronized State state() {
        if (state == State.OPEN && clock.getAsLong() - openUntil >= 0) {
            return State.HALF_OPEN;
        }
        return state;
    }

    /**
     * Whether this call may go to the PDP. Closed: yes. Open: no, until the time is up; then the first call to ask
     * is the trial and gets a yes, and every other call gets a no until the trial settles.
     */
    synchronized boolean allow() {
        if (state == State.CLOSED) {
            return true;
        }
        if (state == State.OPEN && clock.getAsLong() - openUntil >= 0) {
            state = State.HALF_OPEN;
            trialInFlight = false;
        }
        if (state == State.HALF_OPEN && !trialInFlight) {
            trialInFlight = true;
            return true;
        }
        return false;
    }

    /** The PDP was reached (whatever it said): the run of failures ends, and a trial closes the breaker. */
    synchronized void onReached() {
        failures = 0;
        state = State.CLOSED;
        trialInFlight = false;
    }

    /** A transport failure: one more in the run, and the breaker opens at the threshold or when a trial fails. */
    synchronized void onUnreachable() {
        failures++;
        if (state == State.HALF_OPEN || failures >= threshold) {
            state = State.OPEN;
            openUntil = clock.getAsLong() + openNanos;
            trialInFlight = false;
        }
    }

    /**
     * A transport that asks this breaker before each call and tells it how the call went. The breaker is shared by
     * the single evaluation and the batch, which go to the same PDP.
     */
    static final class Guarded implements HttpTransport {
        private final HttpTransport delegate;
        private final CircuitBreaker breaker;

        Guarded(HttpTransport delegate, CircuitBreaker breaker) {
            this.delegate = delegate;
            this.breaker = breaker;
        }

        HttpTransport delegate() {
            return delegate;
        }

        CircuitBreaker breaker() {
            return breaker;
        }

        @Override
        public Response post(String url, String body, Map<String, String> headers) throws IOException {
            if (!breaker.allow()) {
                PdpMetrics.call(PdpMetrics.OUTCOME_BREAKER_OPEN);
                throw new PdpUnavailableException("PDP circuit breaker is open after " + breaker.threshold()
                        + " transport failures in a row; not calling the PDP");
            }
            Response response;
            try {
                response = delegate.post(url, body, headers);
            } catch (PdpUnavailableException e) {
                breaker.onUnreachable();
                PdpMetrics.call(PdpMetrics.OUTCOME_UNREACHABLE);
                throw e;
            } catch (IOException | RuntimeException | Error e) {
                // Something answered, or nothing was sent: either way not an outage, and a trial must settle.
                breaker.onReached();
                PdpMetrics.call(PdpMetrics.OUTCOME_FAILED);
                throw e;
            }
            breaker.onReached();
            PdpMetrics.call(PdpMetrics.OUTCOME_ANSWERED);
            return response;
        }
    }
}
