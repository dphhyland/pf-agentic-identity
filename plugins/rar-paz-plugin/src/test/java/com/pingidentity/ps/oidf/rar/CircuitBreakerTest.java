package com.pingidentity.ps.oidf.rar;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The breaker with a clock the test moves: it opens after N transport failures in a row, answers "unreachable" without
 * calling while open, lets one trial through when the time is up, and closes or opens again on the trial's outcome.
 * Only a transport failure counts; a PDP that answered, however badly, ends a run.
 */
class CircuitBreakerTest {

    private final AtomicLong now = new AtomicLong(1_000_000_000L);

    private CircuitBreaker breaker(int threshold, int openSeconds) {
        return new CircuitBreaker(threshold, openSeconds, now::get);
    }

    private void advance(long seconds) {
        now.addAndGet(TimeUnit.SECONDS.toNanos(seconds));
    }

    /** A transport that plays back a script of outcomes and counts the calls that reached it. */
    private static final class Script implements HttpTransport {
        final Deque<Object> outcomes = new ArrayDeque<>();
        final AtomicInteger calls = new AtomicInteger();

        Script then(Object outcome) {
            outcomes.add(outcome);
            return this;
        }

        @Override
        public Response post(String url, String body, Map<String, String> headers) throws IOException {
            calls.incrementAndGet();
            Object next = outcomes.isEmpty() ? new Response(200, "{}") : outcomes.poll();
            if (next instanceof IOException e) {
                throw e;
            }
            if (next instanceof RuntimeException e) {
                throw e;
            }
            if (next instanceof Error e) {
                throw e;
            }
            return (Response) next;
        }
    }

    private static PdpUnavailableException down() {
        return new PdpUnavailableException("connection refused");
    }

    @Test
    void theDefaultsAreFiveFailuresAndThirtySeconds() {
        CircuitBreaker defaults = new CircuitBreaker(0, 0);
        assertEquals(5, defaults.threshold());
        assertEquals(TimeUnit.SECONDS.toNanos(30), defaults.openNanos());
        assertEquals(CircuitBreaker.State.CLOSED, defaults.state());
    }

    @Test
    void itOpensAfterTheThresholdAndAnswersUnreachableWithoutCalling() throws Exception {
        CircuitBreaker breaker = breaker(3, 30);
        Script pdp = new Script().then(down()).then(down()).then(down());
        CircuitBreaker.Guarded guarded = new CircuitBreaker.Guarded(pdp, breaker);
        for (int i = 0; i < 3; i++) {
            assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        }
        assertEquals(CircuitBreaker.State.OPEN, breaker.state());
        PdpUnavailableException open = assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        assertTrue(open.getMessage().contains("circuit breaker is open"), open.getMessage());
        assertEquals(3, pdp.calls.get(), "an open breaker does not call the PDP");
        advance(29);
        assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        assertEquals(3, pdp.calls.get());
        assertSame(pdp, guarded.delegate());
        assertSame(breaker, guarded.breaker());
    }

    @Test
    void whenTheTimeIsUpOneTrialGoesThroughAndItsSuccessClosesTheBreaker() throws Exception {
        CircuitBreaker breaker = breaker(1, 30);
        breaker.onUnreachable();
        assertEquals(CircuitBreaker.State.OPEN, breaker.state());
        advance(30);
        assertEquals(CircuitBreaker.State.HALF_OPEN, breaker.state());
        assertTrue(breaker.allow(), "the first caller is the trial");
        assertFalse(breaker.allow(), "every other caller is refused while the trial is out");
        assertEquals(CircuitBreaker.State.HALF_OPEN, breaker.state());
        breaker.onReached();
        assertEquals(CircuitBreaker.State.CLOSED, breaker.state());
        assertTrue(breaker.allow());
        assertTrue(breaker.allow());
    }

    @Test
    void aFailedTrialOpensItForAnotherPeriod() throws Exception {
        CircuitBreaker breaker = breaker(2, 10);
        Script pdp = new Script().then(down()).then(down()).then(down()).then(new HttpTransport.Response(200, "{}"));
        CircuitBreaker.Guarded guarded = new CircuitBreaker.Guarded(pdp, breaker);
        assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        assertEquals(CircuitBreaker.State.OPEN, breaker.state());
        advance(10);
        assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()), "the trial fails");
        assertEquals(3, pdp.calls.get());
        assertEquals(CircuitBreaker.State.OPEN, breaker.state(), "one failed trial opens it again, below the threshold");
        advance(9);
        assertEquals(CircuitBreaker.State.OPEN, breaker.state());
        advance(1);
        assertEquals(200, guarded.post("u", "{}", Map.of()).status(), "the next trial succeeds");
        assertEquals(CircuitBreaker.State.CLOSED, breaker.state());
    }

    /** S2a's rule: a 4xx, a malformed body or a TLS failure fails closed and is never an outage. */
    @Test
    void onlyATransportFailureCountsAndAnAnswerEndsTheRun() throws Exception {
        CircuitBreaker breaker = breaker(2, 30);
        Script pdp = new Script()
                .then(down())
                .then(new IOException("the TLS handshake with https://pdp:443 failed"))
                .then(down())
                .then(new HttpTransport.Response(401, "{}"))
                .then(down())
                .then(new IllegalStateException("a bug"))
                .then(down())
                .then(new HttpTransport.Response(503, "{}"));
        CircuitBreaker.Guarded guarded = new CircuitBreaker.Guarded(pdp, breaker);
        assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        IOException tls = assertThrows(IOException.class, () -> guarded.post("u", "{}", Map.of()));
        assertFalse(tls instanceof PdpUnavailableException);
        assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        assertEquals(401, guarded.post("u", "{}", Map.of()).status());
        assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        assertThrows(IllegalStateException.class, () -> guarded.post("u", "{}", Map.of()));
        assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        assertEquals(503, guarded.post("u", "{}", Map.of()).status(), "a 503 is decided after the transport, uncounted");
        assertEquals(CircuitBreaker.State.CLOSED, breaker.state(), "never two transport failures in a row");
        assertEquals(8, pdp.calls.get());
    }

    @Test
    void anErrorDuringTheTrialStillSettlesIt() {
        CircuitBreaker breaker = breaker(1, 5);
        breaker.onUnreachable();
        advance(5);
        CircuitBreaker.Guarded guarded = new CircuitBreaker.Guarded(new Script().then(new StackOverflowError()), breaker);
        assertThrows(StackOverflowError.class, () -> guarded.post("u", "{}", Map.of()));
        assertEquals(CircuitBreaker.State.CLOSED, breaker.state(), "the trial reached something");
    }

    @Test
    void theGaugeCountsInstancesByState() {
        CircuitBreaker open = breaker(1, 30);
        CircuitBreaker closed = breaker(1, 30);
        double openBefore = PdpMetrics.breakers(CircuitBreaker.State.OPEN);
        double closedBefore = PdpMetrics.breakers(CircuitBreaker.State.CLOSED);
        PdpMetrics.track(open);
        PdpMetrics.track(closed);
        open.onUnreachable();
        assertEquals(openBefore + 1, PdpMetrics.breakers(CircuitBreaker.State.OPEN));
        assertEquals(closedBefore + 1, PdpMetrics.breakers(CircuitBreaker.State.CLOSED));
        double halfBefore = PdpMetrics.breakers(CircuitBreaker.State.HALF_OPEN);
        advance(30);
        assertEquals(halfBefore + 1, PdpMetrics.breakers(CircuitBreaker.State.HALF_OPEN), "an open breaker whose time is up reads half-open");
        assertEquals(openBefore, PdpMetrics.breakers(CircuitBreaker.State.OPEN));
        assertEquals("half_open", PdpMetrics.labelOf(CircuitBreaker.State.HALF_OPEN));
    }

    @Test
    void theCallCounterSaysWhatEachCallCameTo() throws Exception {
        long answered = PdpMetrics.calls(PdpMetrics.MODE_EVALUATION, PdpMetrics.OUTCOME_ANSWERED);
        long unreachable = PdpMetrics.calls(PdpMetrics.MODE_EVALUATION, PdpMetrics.OUTCOME_UNREACHABLE);
        long failed = PdpMetrics.calls(PdpMetrics.MODE_EVALUATION, PdpMetrics.OUTCOME_FAILED);
        long refused = PdpMetrics.calls(PdpMetrics.MODE_EVALUATION, PdpMetrics.OUTCOME_BREAKER_OPEN);
        long batched = PdpMetrics.calls(PdpMetrics.MODE_EVALUATIONS, PdpMetrics.OUTCOME_ANSWERED);
        CircuitBreaker breaker = breaker(1, 30);
        CircuitBreaker.Guarded guarded = new CircuitBreaker.Guarded(
                new Script().then(new HttpTransport.Response(200, "{}")).then(new IOException("tls")).then(down())
                        .then(new HttpTransport.Response(200, "{}")), breaker);
        guarded.post("u", "{}", Map.of());
        assertThrows(IOException.class, () -> guarded.post("u", "{}", Map.of()));
        assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        assertThrows(PdpUnavailableException.class, () -> guarded.post("u", "{}", Map.of()));
        assertEquals(answered + 1, PdpMetrics.calls(PdpMetrics.MODE_EVALUATION, PdpMetrics.OUTCOME_ANSWERED));
        assertEquals(failed + 1, PdpMetrics.calls(PdpMetrics.MODE_EVALUATION, PdpMetrics.OUTCOME_FAILED));
        assertEquals(unreachable + 1, PdpMetrics.calls(PdpMetrics.MODE_EVALUATION, PdpMetrics.OUTCOME_UNREACHABLE));
        assertEquals(refused + 1, PdpMetrics.calls(PdpMetrics.MODE_EVALUATION, PdpMetrics.OUTCOME_BREAKER_OPEN));
        advance(30);
        PdpMetrics.inBatch(() -> guarded.post("u", "{}", Map.of()));
        assertEquals(batched + 1, PdpMetrics.calls(PdpMetrics.MODE_EVALUATIONS, PdpMetrics.OUTCOME_ANSWERED));
        assertEquals(answered + 1, PdpMetrics.calls(PdpMetrics.MODE_EVALUATION, PdpMetrics.OUTCOME_ANSWERED),
                "the mode goes back to single after the batch");
    }
}
