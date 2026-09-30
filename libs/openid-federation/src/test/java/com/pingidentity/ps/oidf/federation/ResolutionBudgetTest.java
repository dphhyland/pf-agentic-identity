package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** One resolution's budget: requests and a wall clock, shared by its children, spent safely from many threads. */
class ResolutionBudgetTest {

    @Test
    void spendingCountsRequestsUntilTheyRunOut() {
        ResolutionBudget budget = ResolutionBudget.of(Duration.ofSeconds(30), 2);

        assertEquals(2, budget.requests());
        assertEquals(Duration.ofSeconds(30), budget.wallClock());
        assertFalse(budget.deadline().expired());
        budget.spend("one");
        assertTrue(budget.trySpend("two"));
        assertEquals(2, budget.used());
        assertFalse(budget.trySpend("three"));

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class, () -> budget.spend("https://peer.example/x"));
        assertEquals(Kind.BUDGET, e.kind());
        assertEquals(FederationError.INVALID_TRUST_CHAIN, e.error());
        assertEquals(ResolutionBudget.Exhausted.REQUESTS, budget.exhaustion());
        assertTrue(e.getMessage().contains("ran out of requests") && e.getMessage().contains("budget of 2 requests"), e.getMessage());
        assertFalse(e.getMessage().contains("peer.example"), "a refusal never repeats what a peer chose: " + e.getMessage());
        assertTrue(budget.toString().contains("requests=2") && budget.toString().contains("used=2"), budget.toString());
    }

    @Test
    void aBudgetWhoseTimeHasPassedRefusesSayingSo() throws Exception {
        ResolutionBudget budget = ResolutionBudget.of(Duration.ofMillis(30), 10);
        Thread.sleep(60);

        assertTrue(budget.expired());
        assertEquals(ResolutionBudget.Exhausted.TIME, budget.exhaustion());
        assertFalse(budget.trySpend("late"));
        TrustChainValidationException e = assertThrows(TrustChainValidationException.class, () -> budget.spend("late"));
        assertEquals(Kind.BUDGET, e.kind());
        assertTrue(e.getMessage().contains("ran out of time") && e.getMessage().contains("30 ms"), e.getMessage());
        assertEquals(0, budget.used(), "nothing was spent");
    }

    @Test
    void aChildSpendsItsParentAndNeverMoreThanTheParentHasLeft() {
        ResolutionBudget parent = ResolutionBudget.of(Duration.ofSeconds(30), 3);
        ResolutionBudget child = parent.child(5);
        ResolutionBudget sibling = parent.child();

        assertEquals(5, child.requests());
        assertEquals(3, sibling.requests(), "a child with no count has as many as its parent was made with");
        assertSame(parent.wallClock(), child.wallClock());
        long parentLeft = parent.deadline().remainingNanos();
        assertTrue(child.deadline().remainingNanos() <= parentLeft, "a child ends no later than its parent");
        child.spend("a");
        child.spend("b");
        sibling.spend("c");
        assertEquals(3, parent.used(), "the parent counts what its children spent");

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class, () -> child.spend("d"));
        assertTrue(e.getMessage().contains("budget of 3 requests"), "names the budget that ran out, the parent's: " + e.getMessage());
        assertEquals(2, child.used(), "a request its parent refused is given back to the child");
    }

    @Test
    void aChildWithNoRequestsRefusesAtOnceAndNamesItsOwnLimit() {
        ResolutionBudget child = ResolutionBudget.of(Duration.ofSeconds(30), 24).child(-4);

        assertEquals(0, child.requests());
        TrustChainValidationException e = assertThrows(TrustChainValidationException.class, () -> child.spend("x"));
        assertTrue(e.getMessage().contains("budget of 0 requests"), e.getMessage());
    }

    @Test
    void aBudgetIsMadeWithPositiveTimeAndNoNegativeRequests() {
        assertThrows(IllegalArgumentException.class, () -> ResolutionBudget.of(Duration.ZERO, 1));
        assertThrows(IllegalArgumentException.class, () -> ResolutionBudget.of(Duration.ofSeconds(-1), 1));
        assertThrows(IllegalArgumentException.class, () -> ResolutionBudget.of(Duration.ofSeconds(1), -1));
        assertThrows(NullPointerException.class, () -> ResolutionBudget.of(null, 1));
        ResolutionBudget fromOptions = ResolutionBudget.of(ValidatorOptions.defaults().withMaxFetches(7)
                .withResolutionWallClock(Duration.ofSeconds(4)));
        assertEquals(7, fromOptions.requests());
        assertEquals(Duration.ofSeconds(4), fromOptions.wallClock());
    }

    /** Many threads spending one budget - a resolution's children on a caller's pool - spend exactly what it holds. */
    @Test
    void concurrentSpendsNeverSpendMoreThanTheBudgetHolds() throws Exception {
        int requests = 500;
        int threads = 16;
        int attemptsEach = 100;
        ResolutionBudget parent = ResolutionBudget.of(Duration.ofSeconds(60), requests);
        AtomicInteger granted = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<?>> done = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                // Half the threads spend through a child of their own, half through the parent.
                ResolutionBudget spender = t % 2 == 0 ? parent.child(attemptsEach) : parent;
                done.add(pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < attemptsEach; i++) {
                        try {
                            spender.spend("r");
                            granted.incrementAndGet();
                        } catch (TrustChainValidationException refused) {
                            // spent
                        }
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> f : done) {
                f.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(requests, granted.get(), "16 x 100 attempts on a budget of 500 are granted 500 times");
        assertEquals(requests, parent.used());
    }
}
