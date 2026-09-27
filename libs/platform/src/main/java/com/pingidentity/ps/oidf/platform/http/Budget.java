/*
 * A wall-clock deadline and a number of requests, shared by everything one piece of work fetches.
 */
package com.pingidentity.ps.oidf.platform.http;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * What one piece of work may spend on outbound requests: a {@link Deadline} and a count. Resolving a trust chain
 * is the case it is for (plan item S5b threads one through the validator): each fetch spends one request, and the
 * whole resolution stops when either the time or the requests run out, however the chain branches.
 *
 * <p>A {@link #child} is a narrower budget inside this one: its deadline is the sooner of its own and this one's,
 * and each request it spends is spent here too, so a child can never spend more than its parent has left. Spending
 * is thread-safe; a request refused by a parent is given back to the child that asked.
 */
public final class Budget {
    private final Budget parent;
    private final Deadline deadline;
    private final AtomicInteger requests;

    private Budget(Budget parent, Deadline deadline, int requests) {
        this.parent = parent;
        this.deadline = deadline;
        this.requests = new AtomicInteger(requests);
    }

    /** A budget of {@code requests} requests and {@code wallClock} from now. */
    public static Budget of(Duration wallClock, int requests) {
        return of(Deadline.after(wallClock), requests);
    }

    /** A budget of {@code requests} requests ending at {@code deadline}. */
    public static Budget of(Deadline deadline, int requests) {
        Objects.requireNonNull(deadline, "deadline");
        return new Budget(null, deadline, Math.max(0, requests));
    }

    /** A budget inside this one: at most {@code requests} of this one's requests, ending no later than it does. */
    public Budget child(Duration wallClock, int requests) {
        return new Budget(this, this.deadline.sooner(wallClock), Math.max(0, requests));
    }

    /** When this budget's time runs out. */
    public Deadline deadline() {
        return this.deadline;
    }

    /** Requests this budget has left, not counting what its parents have left. */
    public int remainingRequests() {
        return this.requests.get();
    }

    /**
     * Spends one request and returns the deadline to make it by.
     *
     * @param what the request, for the message when it is refused
     * @throws OutboundHttpException with {@link OutboundHttpException.Reason#BUDGET_EXHAUSTED} when this budget or a
     *     parent has no time or no request left
     */
    public Deadline spend(String what) throws OutboundHttpException {
        if (this.deadline.expired()) {
            throw new OutboundHttpException(OutboundHttpException.Reason.BUDGET_EXHAUSTED,
                    "not fetching " + what + ": the budget's time is spent");
        }
        if (!take()) {
            throw new OutboundHttpException(OutboundHttpException.Reason.BUDGET_EXHAUSTED,
                    "not fetching " + what + ": the budget's requests are spent");
        }
        if (this.parent != null) {
            try {
                this.parent.spend(what);
            } catch (OutboundHttpException e) {
                this.requests.incrementAndGet();
                throw e;
            }
        }
        return this.deadline;
    }

    /** Takes one request if one is left. */
    private boolean take() {
        while (true) {
            int left = this.requests.get();
            if (left <= 0) {
                return false;
            }
            if (this.requests.compareAndSet(left, left - 1)) {
                return true;
            }
        }
    }

    @Override
    public String toString() {
        return "Budget[requests=" + this.requests.get() + ", " + this.deadline + "]";
    }
}
