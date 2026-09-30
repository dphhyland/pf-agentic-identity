/*
 * A count that only rises, one per combination of label values.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import java.util.concurrent.atomic.LongAdder;

/**
 * A counter. Label values are passed in the order the labels were declared; each is kept within its label's
 * bound or counted as {@link Label#OTHER}. The increment is a {@link LongAdder}: no lock once the values are
 * known (see {@link Family}).
 */
public final class Counter {

    private final Family<LongAdder> family;

    Counter(Family<LongAdder> family) {
        this.family = family;
    }

    /** Adds one. */
    public void inc(String... labelValues) {
        this.family.cell(labelValues).increment();
    }

    /** Adds {@code delta}; nothing happens when it is not positive, because a counter only rises. */
    public void add(long delta, String... labelValues) {
        if (delta > 0) {
            this.family.cell(labelValues).add(delta);
        }
    }

    /** The count for these exact values, 0 when nothing has been counted under them; creates nothing. */
    public long get(String... labelValues) {
        LongAdder c = this.family.peek(labelValues);
        return c == null ? 0 : c.sum();
    }

    public String name() {
        return this.family.name;
    }
}
