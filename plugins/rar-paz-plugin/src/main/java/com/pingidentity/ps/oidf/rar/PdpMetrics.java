/*
 * The PDP call's counters and the breaker gauge, in this plugin's relocated copy of platform.metrics.
 */
package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.platform.metrics.Counter;
import com.pingidentity.ps.oidf.platform.metrics.Gauge;
import com.pingidentity.ps.oidf.platform.metrics.Label;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;

import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

/**
 * Three metrics, registered once per loaded copy of this plugin:
 *
 * <ul>
 *   <li>{@code oidf_rar_pdp_calls_total{mode, outcome}}: each call this plugin made, or would have made, to the PDP.
 *       {@code mode} is {@code evaluation} (one detail) or {@code evaluations} (an AuthZEN batch); {@code outcome} is
 *       {@code answered} (an HTTP response came back, whatever its status), {@code unreachable} (a transport failure),
 *       {@code failed} (a TLS failure, a response too large or malformed, a request that could not be built) or
 *       {@code breaker_open} (not sent: the circuit breaker is open).</li>
 *   <li>{@code oidf_rar_pdp_answers_total{source}}: where each {@code enrich}'s decision came from - {@code pdp} (a
 *       call made for it), {@code memo} (an earlier call in the same HTTP request, a batch included) or {@code cache}
 *       (the per-type decision cache).</li>
 *   <li>{@code oidf_rar_pdp_breakers{state}}: how many processor instances in this copy have a breaker in each
 *       state, {@code closed}, {@code open} or {@code half_open}.</li>
 * </ul>
 *
 * <p>The plugin shades platform under {@code com.pingidentity.ps.oidf.rar.shaded.platform}, so these live in the
 * plugin's own registry and MXBean, not the webapp's: in a JMX console, the MBean
 * {@code com.pingidentity.ps.oidf:type=Metrics,copy="com.pingidentity.ps.oidf.rar.shaded.platform.metrics from ..."},
 * its {@code Samples} attribute. No label carries a principal, a client or a detail value.
 */
final class PdpMetrics {

    static final String MODE_EVALUATION = "evaluation";
    static final String MODE_EVALUATIONS = "evaluations";
    static final String OUTCOME_ANSWERED = "answered";
    static final String OUTCOME_UNREACHABLE = "unreachable";
    static final String OUTCOME_FAILED = "failed";
    static final String OUTCOME_BREAKER_OPEN = "breaker_open";
    static final String SOURCE_PDP = "pdp";
    static final String SOURCE_MEMO = "memo";
    static final String SOURCE_CACHE = "cache";

    private static final Counter CALLS = Metrics.counter("oidf_rar_pdp_calls_total",
            "Calls the RAR plugin made, or would have made, to its PDP",
            Label.oneOf("mode", MODE_EVALUATION, MODE_EVALUATIONS),
            Label.oneOf("outcome", OUTCOME_ANSWERED, OUTCOME_UNREACHABLE, OUTCOME_FAILED, OUTCOME_BREAKER_OPEN));
    private static final Counter ANSWERS = Metrics.counter("oidf_rar_pdp_answers_total",
            "Where each RAR plugin decision came from: a PDP call, the per-request memo or the decision cache",
            Label.oneOf("source", SOURCE_PDP, SOURCE_MEMO, SOURCE_CACHE));
    private static final Set<CircuitBreaker> BREAKERS = Collections.synchronizedSet(
            Collections.newSetFromMap(new WeakHashMap<>()));
    private static final Gauge BREAKER_STATES = Metrics.gauge("oidf_rar_pdp_breakers",
            "RAR plugin instances whose PDP circuit breaker is in each state", Label.oneOf("state", "closed", "open", "half_open"));

    /** The mode of the call on this thread: the batch sets it around its one call. */
    private static final ThreadLocal<String> MODE = ThreadLocal.withInitial(() -> MODE_EVALUATION);

    static {
        for (CircuitBreaker.State state : CircuitBreaker.State.values()) {
            BREAKER_STATES.set(() -> count(state), labelOf(state));
        }
    }

    private PdpMetrics() { }

    static void call(String outcome) {
        CALLS.inc(MODE.get(), outcome);
    }

    static void answer(String source) {
        ANSWERS.inc(source);
    }

    /** Counts the calls {@code body} makes as batch calls. */
    static <T, E extends Exception> T inBatch(Callable<T, E> body) throws E {
        MODE.set(MODE_EVALUATIONS);
        try {
            return body.call();
        } finally {
            MODE.remove();
        }
    }

    static void track(CircuitBreaker breaker) {
        BREAKERS.add(breaker);
    }

    /** Stops counting a breaker a reconfigure replaced, rather than until the collector takes it. Null is nothing. */
    static void untrack(CircuitBreaker breaker) {
        if (breaker != null) {
            BREAKERS.remove(breaker);
        }
    }

    static long calls(String mode, String outcome) {
        return CALLS.get(mode, outcome);
    }

    static long answers(String source) {
        return ANSWERS.get(source);
    }

    static double breakers(CircuitBreaker.State state) {
        return BREAKER_STATES.read(labelOf(state));
    }

    static String labelOf(CircuitBreaker.State state) {
        return state.name().toLowerCase(java.util.Locale.ROOT);
    }

    private static double count(CircuitBreaker.State state) {
        CircuitBreaker[] all;
        synchronized (BREAKERS) {
            all = BREAKERS.toArray(new CircuitBreaker[0]);
        }
        int n = 0;
        for (CircuitBreaker breaker : all) {
            if (breaker.state() == state) {
                n++;
            }
        }
        return n;
    }

    /** A {@link java.util.concurrent.Callable} with a checked exception of the caller's choosing. */
    @FunctionalInterface
    interface Callable<T, E extends Exception> {
        T call() throws E;
    }
}
