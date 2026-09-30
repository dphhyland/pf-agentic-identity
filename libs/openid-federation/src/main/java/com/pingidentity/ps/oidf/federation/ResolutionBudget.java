/*
 * What one trust chain resolution may spend on the network: a wall clock and a number of requests.
 */
package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind;
import com.pingidentity.ps.oidf.platform.http.Budget;
import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import java.time.Duration;
import java.util.Objects;

/**
 * The network work one resolution may cause (plan item S5b): a wall clock, from the moment the budget is made, and
 * a number of requests, over platform's {@link Budget}. One budget covers everything a resolution fetches however
 * the chain is shaped: every statement the validator asks its gateway for (answered from the cache or not), every
 * further request the gateway makes to answer it (an authority's Entity Configuration to find its fetch endpoint,
 * the OpenID Federation 1.0 §11.3 second retrieval of an anchor's), a peer chain, and a Trust Mark validation's
 * issuers and status calls, which spend from a {@link #child} of it. Every request is made by the budget's
 * {@link #deadline()}, so a slow peer's body spends the resolution's time, not a fresh timeout of its own.
 *
 * <p>Spending is thread-safe. A budget that has run out answers with a {@link TrustChainValidationException} of kind
 * {@link Kind#BUDGET} saying which ran out, requests or time, and how much the budget had; it never names what was
 * being fetched, which a peer chose.
 */
public final class ResolutionBudget {

    /** What ran out. */
    public enum Exhausted {
        /** Every request the budget allowed has been spent. */
        REQUESTS,
        /** The budget's wall clock has passed. */
        TIME
    }

    private final ResolutionBudget parent;
    private final Budget budget;
    private final int requests;
    private final Duration wallClock;

    private ResolutionBudget(ResolutionBudget parent, Budget budget, int requests, Duration wallClock) {
        this.parent = parent;
        this.budget = budget;
        this.requests = requests;
        this.wallClock = wallClock;
    }

    /**
     * A budget of {@code requests} requests and {@code wallClock} from now.
     *
     * @throws IllegalArgumentException for a negative number of requests, or a wall clock that is not positive
     */
    public static ResolutionBudget of(Duration wallClock, int requests) {
        Objects.requireNonNull(wallClock, "wallClock");
        if (requests < 0) {
            throw new IllegalArgumentException("a resolution budget's requests must not be negative");
        }
        if (wallClock.isNegative() || wallClock.isZero()) {
            throw new IllegalArgumentException("a resolution budget's wall clock must be positive");
        }
        return new ResolutionBudget(null, Budget.of(wallClock, requests), requests, wallClock);
    }

    /** A budget of {@link ValidatorOptions#maxFetches()} requests and {@link ValidatorOptions#resolutionWallClock()} from now. */
    public static ResolutionBudget of(ValidatorOptions options) {
        return of(options.resolutionWallClock(), options.maxFetches());
    }

    /**
     * A budget inside this one, for part of the same resolution: at most {@code requests} of this one's requests,
     * each spent here too, and this one's deadline.
     */
    public ResolutionBudget child(int requests) {
        int own = Math.max(0, requests);
        return new ResolutionBudget(this, this.budget.child(this.budget.deadline().remaining(), own), own, this.wallClock);
    }

    /** {@link #child(int)} with as many requests as this budget was made with: bounded by what this one has left. */
    public ResolutionBudget child() {
        return child(this.requests);
    }

    /** When the budget's time runs out: every request is made by it. */
    public Deadline deadline() {
        return this.budget.deadline();
    }

    /** Whether the budget's time has run out. */
    public boolean expired() {
        return this.budget.deadline().expired();
    }

    /** The requests this budget was made with. */
    public int requests() {
        return this.requests;
    }

    /** The wall clock the budget (or the budget it is inside) was made with. */
    public Duration wallClock() {
        return this.wallClock;
    }

    /** Requests spent through this budget and its children. */
    public int used() {
        return this.requests - this.budget.remainingRequests();
    }

    /**
     * Spends one request and returns the deadline to make it by.
     *
     * @param what the request, for a debug log line only: a refusal never repeats it, since a peer chose it
     * @throws TrustChainValidationException of kind {@link Kind#BUDGET} when this budget, or one it is inside, has no
     *     time or no request left
     */
    public Deadline spend(String what) {
        try {
            return this.budget.spend(what);
        } catch (OutboundHttpException e) {
            throw this.exhausted();
        }
    }

    /** Spends one request if one is left and there is time; for work that is never worth failing a resolution over. */
    public boolean trySpend(String what) {
        try {
            this.budget.spend(what);
            return true;
        } catch (OutboundHttpException e) {
            return false;
        }
    }

    /** What has run out: time when the deadline has passed, otherwise requests. */
    public Exhausted exhaustion() {
        return this.expired() ? Exhausted.TIME : Exhausted.REQUESTS;
    }

    /**
     * The refusal for a resolution that ran out, saying what ran out and what the budget allowed: the wall clock, or
     * the requests of whichever budget - this one or one it is inside - has none left.
     */
    public TrustChainValidationException exhausted() {
        if (this.exhaustion() == Exhausted.TIME) {
            return new TrustChainValidationException(Kind.BUDGET, null, null, "trust chain resolution ran out of time: its"
                    + " wall-clock budget of " + this.wallClock.toMillis() + " ms is spent; refusing to keep resolving");
        }
        ResolutionBudget spent = this;
        while (spent.budget.remainingRequests() > 0 && spent.parent != null) {
            spent = spent.parent;
        }
        return new TrustChainValidationException(Kind.BUDGET, null, null, "trust chain resolution ran out of requests: its"
                + " budget of " + spent.requests + " requests is spent; refusing to keep resolving");
    }

    @Override
    public String toString() {
        return "ResolutionBudget[requests=" + this.requests + ", used=" + this.used() + ", " + this.budget.deadline() + "]";
    }
}
