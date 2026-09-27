package com.pingidentity.ps.oidf.platform.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException.Reason;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/** Deadline arithmetic on a clock the test moves, and Budget spending, children included. */
class DeadlineAndBudgetTest {

    private final AtomicLong now = new AtomicLong(Long.MAX_VALUE - 5_000_000_000L);

    private Deadline after(long nanos) {
        return Deadline.after(Duration.ofNanos(nanos), this.now::get);
    }

    @Test
    void aDeadlineCountsDownAndExpiresEvenAcrossTheClocksWrap() {
        Deadline deadline = after(10_000_000_000L);
        assertEquals(Duration.ofSeconds(10), deadline.remaining());
        assertFalse(deadline.expired());
        this.now.addAndGet(9_999_999_999L);
        assertEquals(1L, deadline.remainingNanos());
        assertEquals(1, deadline.timeoutMillis());
        this.now.addAndGet(1L);
        assertTrue(deadline.expired());
        assertEquals(Duration.ZERO, deadline.remaining());
        assertEquals(0, deadline.timeoutMillis());
        this.now.addAndGet(1_000_000L);
        assertEquals(0L, deadline.remainingNanos());
        assertTrue(deadline.toString().contains("PT0S"));
    }

    @Test
    void zeroNegativeAndHugeDurationsAreHeldToTheRange() {
        assertTrue(after(0).expired());
        assertTrue(Deadline.after(Duration.ofSeconds(-5), this.now::get).expired());
        assertEquals(Deadline.MAX_NANOS, Deadline.after(Duration.ofDays(365L * 1000L), this.now::get).remainingNanos());
        assertEquals(Deadline.MAX_NANOS, Deadline.nanos(Duration.ofNanos(Deadline.MAX_NANOS)));
        assertEquals(Integer.MAX_VALUE, Deadline.after(Duration.ofDays(365), this.now::get).timeoutMillis());
        assertEquals(1000, after(999_999_001L).timeoutMillis());
        assertEquals(1000, after(1_000_000_000L).timeoutMillis());
        assertThrows(NullPointerException.class, () -> Deadline.after(null));
        assertThrows(NullPointerException.class, () -> Deadline.after(Duration.ZERO, null));
        assertTrue(Deadline.after(Duration.ofMinutes(1)).remainingNanos() > 0);
    }

    @Test
    void theSoonerOfTwoDeadlinesWins() {
        Deadline ten = after(10_000);
        Deadline five = after(5_000);
        assertSame(five, ten.min(five));
        assertSame(five, five.min(ten));
        assertSame(ten, ten.min(after(10_000)));
        assertSame(ten, ten.sooner(Duration.ofNanos(20_000)));
        assertEquals(3_000, ten.sooner(Duration.ofNanos(3_000)).remainingNanos());
        assertThrows(NullPointerException.class, () -> ten.min(null));
    }

    @Test
    void aBudgetSpendsItsRequestsThenRefuses() throws Exception {
        Budget budget = Budget.of(after(1_000_000), 2);
        assertEquals(2, budget.remainingRequests());
        assertSame(budget.deadline(), budget.spend("a"));
        budget.spend("b");
        OutboundHttpException e = assertThrows(OutboundHttpException.class, () -> budget.spend("c"));
        assertEquals(Reason.BUDGET_EXHAUSTED, e.reason());
        assertTrue(e.getMessage().contains("requests"));
        assertTrue(budget.toString().contains("requests=0"));
    }

    @Test
    void aBudgetWhoseTimeIsSpentRefusesWithRequestsLeft() {
        Budget budget = Budget.of(after(1_000), 5);
        this.now.addAndGet(1_000);
        OutboundHttpException e = assertThrows(OutboundHttpException.class, () -> budget.spend("late"));
        assertTrue(e.getMessage().contains("time"));
        assertEquals(5, budget.remainingRequests());
    }

    @Test
    void aNegativeCountIsNoRequests() {
        assertEquals(0, Budget.of(Duration.ofSeconds(1), -3).remainingRequests());
        assertEquals(0, Budget.of(Duration.ofSeconds(1), 3).child(Duration.ofSeconds(1), -1).remainingRequests());
        assertThrows(NullPointerException.class, () -> Budget.of((Deadline) null, 1));
    }

    @Test
    void aChildSpendsItsParentAndEndsNoLaterThanIt() throws Exception {
        Budget parent = Budget.of(after(1_000_000), 3);
        Budget child = parent.child(Duration.ofSeconds(60), 10);
        assertEquals(1_000_000, child.deadline().remainingNanos());
        Budget shortChild = parent.child(Duration.ofNanos(500), 10);
        assertEquals(500, shortChild.deadline().remainingNanos());
        child.spend("1");
        child.spend("2");
        shortChild.spend("3");
        assertEquals(0, parent.remainingRequests());
        OutboundHttpException e = assertThrows(OutboundHttpException.class, () -> child.spend("4"));
        assertEquals(Reason.BUDGET_EXHAUSTED, e.reason());
        // The request the parent refused is given back to the child.
        assertEquals(8, child.remainingRequests());
    }

    @Test
    void concurrentSpendingNeverSpendsMoreThanTheBudget() throws Exception {
        Budget budget = Budget.of(Duration.ofSeconds(30), 1000);
        AtomicInteger spent = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        List<Thread> threads = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
            Thread thread = new Thread(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 200; i++) {
                        try {
                            budget.spend("x");
                            spent.incrementAndGet();
                        } catch (OutboundHttpException e) {
                            // spent out
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            threads.add(thread);
            thread.start();
        }
        start.countDown();
        for (Thread thread : threads) {
            thread.join();
        }
        assertEquals(1000, spent.get());
        assertEquals(0, budget.remainingRequests());
    }
}
