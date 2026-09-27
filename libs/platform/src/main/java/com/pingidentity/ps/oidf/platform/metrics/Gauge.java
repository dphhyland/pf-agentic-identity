/*
 * A value read from a supplier when the metrics are read.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import java.util.Objects;
import java.util.function.DoubleSupplier;

/**
 * A gauge: one supplier per combination of label values, read when the metrics are read (a snapshot, the MXBean,
 * O-5's endpoint), never on the hot path. A supplier must be cheap and must not block: it runs on the reader's
 * thread. One that throws reads as {@code NaN}, so a broken supplier cannot break the reader.
 */
public final class Gauge {

    /** The supplier bound to one series. */
    static final class Cell {
        volatile DoubleSupplier supplier = () -> Double.NaN;

        double read() {
            try {
                return this.supplier.getAsDouble();
            } catch (RuntimeException | LinkageError e) {
                return Double.NaN;
            }
        }
    }

    private final Family<Cell> family;

    Gauge(Family<Cell> family) {
        this.family = family;
    }

    /**
     * Binds the supplier for these label values, replacing any bound before - so a servlet initialised again
     * binds its new instance's supplier in place of the old one's.
     */
    public void set(DoubleSupplier supplier, String... labelValues) {
        Objects.requireNonNull(supplier, "supplier");
        this.family.cell(labelValues).supplier = supplier;
    }

    /** The value now for these exact values, {@code NaN} when nothing is bound to them. */
    public double read(String... labelValues) {
        Cell c = this.family.peek(labelValues);
        return c == null ? Double.NaN : c.read();
    }

    public String name() {
        return this.family.name;
    }
}
