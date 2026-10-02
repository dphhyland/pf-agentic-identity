/*
 * One registered metric: its name, its labels, and a bounded map of series.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Supplier;

/**
 * A metric's name, help, kind and labels, and one cell per combination of kept label values. The number of cells
 * is bounded by {@link #maxSeries}, the product of each label's {@link Label#maxValues()}, because every value is
 * admitted through the label's bound first.
 *
 * <p>The hot path takes no lock once a value is known: {@link #cell} is a lookup in a {@link ConcurrentHashMap}
 * for each label and one for the series. A lock is taken only to admit a new value under a cap (at most the cap's
 * number of times per label) and, inside {@link ConcurrentHashMap#computeIfAbsent}, to create a series (at most
 * {@link #maxSeries} times).
 */
final class Family<C> {

    /** Holds the values one label has kept, and admits new ones within its bound. */
    static final class Slot {
        private final Label label;
        final Set<String> seen = ConcurrentHashMap.newKeySet();
        private volatile boolean full;

        Slot(Label label) {
            this.label = label;
        }

        /** The value kept, or {@code null} when it is counted as {@link Label#OTHER}. */
        String admit(String value) {
            if (!Label.keepable(value)) {
                return null;
            }
            if (Label.OTHER.equals(value)) {
                return value;
            }
            if (this.label.isDeclared()) {
                return this.label.declared().contains(value) ? value : null;
            }
            if (this.seen.contains(value)) {
                return value;
            }
            if (this.full) {
                return null;
            }
            synchronized (this) {
                if (this.seen.contains(value)) {
                    return value;
                }
                if (this.seen.size() >= this.label.cap()) {
                    this.full = true;
                    return null;
                }
                this.seen.add(value);
                return value;
            }
        }
    }

    final String name;
    final String help;
    final Kind kind;
    final List<Label> labels;
    final int maxSeries;
    /** The public handle - a {@link Counter}, {@link Timer} or {@link Gauge} - set by the registry before the family is shared. */
    Object handle;

    private final Slot[] slots;
    private final Supplier<C> factory;
    private final Map<List<String>, C> series = new ConcurrentHashMap<>();
    private final LongAdder folds = new LongAdder();

    Family(Kind kind, String name, String help, List<Label> labels, Supplier<C> factory) {
        this.kind = kind;
        this.name = name;
        this.help = help;
        this.labels = List.copyOf(labels);
        this.factory = factory;
        this.maxSeries = maxSeries(name, this.labels);
        this.slots = new Slot[this.labels.size()];
        for (int i = 0; i < this.slots.length; i++) {
            this.slots[i] = new Slot(this.labels.get(i));
        }
    }

    /**
     * The most series these labels allow: the product of each one's {@link Label#maxValues()}.
     *
     * @throws IllegalArgumentException when it is over {@link MetricRegistry#MAX_SERIES_PER_METRIC}
     */
    static int maxSeries(String name, List<Label> labels) {
        long product = 1;
        for (Label l : labels) {
            product *= l.maxValues();
            if (product > MetricRegistry.MAX_SERIES_PER_METRIC) {
                throw new IllegalArgumentException(name + ": its labels allow more than " + MetricRegistry.MAX_SERIES_PER_METRIC
                        + " series; declare fewer values or lower a cap");
            }
        }
        return (int) product;
    }

    /**
     * The cell for these label values, created on first use. Each value is admitted through its label's bound, so
     * no sequence of values can create more than {@link #maxSeries} cells.
     *
     * @throws IllegalArgumentException when the number of values is not the number of labels - the same at every
     *                                  call from one call site, so a bug for the caller's tests to find
     */
    C cell(String... values) {
        List<String> key = key(values);
        C c = this.series.get(key);
        return c != null ? c : this.series.computeIfAbsent(key, k -> this.factory.get());
    }

    /** The cell for these label values if it exists, without creating it or counting a fold. */
    C peek(String... values) {
        int n = values == null ? 0 : values.length;
        if (n != this.slots.length) {
            return null;
        }
        String[] kept = new String[n];
        for (int i = 0; i < n; i++) {
            kept[i] = Label.keepable(values[i]) ? values[i] : Label.OTHER;
        }
        return this.series.get(List.of(kept));
    }

    List<String> key(String[] values) {
        int n = values == null ? 0 : values.length;
        if (n != this.slots.length) {
            throw new IllegalArgumentException(this.name + " takes " + this.slots.length + " label value(s), not " + n);
        }
        if (n == 0) {
            return List.of();
        }
        String[] kept = new String[n];
        for (int i = 0; i < n; i++) {
            String v = this.slots[i].admit(values[i]);
            if (v == null) {
                this.folds.increment();
                v = Label.OTHER;
            }
            kept[i] = v;
        }
        return List.of(kept);
    }

    /** How many label values have been counted as {@link Label#OTHER}. */
    long folds() {
        return this.folds.sum();
    }

    int seriesCount() {
        return this.series.size();
    }

    /** Whether a second registration under this name asks for the same metric. */
    boolean sameShape(Family<?> other) {
        return this.kind == other.kind && this.labels.equals(other.labels);
    }

    /** Every series, ordered by its label values. */
    List<Map.Entry<List<String>, C>> entries() {
        List<Map.Entry<List<String>, C>> out = new ArrayList<>(this.series.entrySet());
        out.sort(Comparator.comparing(e -> String.join("\u0000", e.getKey())));
        return out;
    }

    List<String> labelNames() {
        List<String> out = new ArrayList<>(this.labels.size());
        for (Label l : this.labels) {
            out.add(l.name());
        }
        return out;
    }
}
