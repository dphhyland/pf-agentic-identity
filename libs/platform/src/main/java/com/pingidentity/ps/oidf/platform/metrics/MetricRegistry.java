/*
 * The metrics one loaded copy of platform holds, bounded in number and in series.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.DoubleSupplier;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * A registry of counters, timers and gauges. {@link Metrics} holds this loader's; tests make their own.
 *
 * <p>Nothing a caller does can grow it without bound. A metric is registered once, by name, with fixed label
 * names; each label's values are bounded ({@link Label}), so a metric has at most
 * {@link #MAX_SERIES_PER_METRIC} series, and the registry at most {@link #MAX_METRICS} metrics whose series
 * together number at most {@link #MAX_SERIES}. A registration past either limit is refused: it gets a working
 * metric that no snapshot shows, {@value #REFUSED} rises, and the log says so the 1st, 2nd, 4th, 8th... time. How many label values were counted as
 * {@link Label#OTHER} is {@value #FOLDS}, per metric.
 *
 * <p>Registering a name again with the same kind and labels returns the metric registered first (a servlet
 * initialised twice gets the same counter); the first registration's help stands. With another kind or other
 * labels it is refused with {@link IllegalArgumentException}, as are bad names and labels: those are constants in
 * the caller's code, so the caller's tests find them.
 */
public final class MetricRegistry {

    /** The most metrics a registry shows. */
    public static final int MAX_METRICS = 256;

    /** The most series one metric's labels may allow. */
    public static final int MAX_SERIES_PER_METRIC = 2048;

    /** The most series the metrics of one registry may allow between them. */
    public static final int MAX_SERIES = 16384;

    /** The counter of label values counted as {@link Label#OTHER}, with a {@code metric} label. */
    public static final String FOLDS = "oidf_metrics_label_folds_total";

    /** The counter of registrations refused at {@link #MAX_METRICS} or {@link #MAX_SERIES}. */
    public static final String REFUSED = "oidf_metrics_refused_total";

    private static final PlatformLog LOG = PlatformLog.get(MetricRegistry.class);
    private static final Pattern NAME = Pattern.compile("oidf_[a-z0-9_]{1,123}");
    private static final int MAX_HELP = 256;
    private static final int MAX_LABELS = 8;

    private final Map<String, Family<?>> families = new TreeMap<>();
    private final LongAdder refused = new LongAdder();
    private final Runnable onFirstRegistration;
    private int reserved;
    private boolean announced;

    /** A registry of its own, for a test or a component that renders its metrics itself. */
    public MetricRegistry() {
        this(() -> { });
    }

    /** @param onFirstRegistration run once, after the first metric is registered: {@link Metrics} registers its MXBean */
    MetricRegistry(Runnable onFirstRegistration) {
        this.onFirstRegistration = Objects.requireNonNull(onFirstRegistration, "onFirstRegistration");
    }

    /** Registers a counter; its name starts {@code oidf_} and ends {@code _total}. */
    public Counter counter(String name, String help, Label... labels) {
        return (Counter) register(Kind.COUNTER, name, help, labels, LongAdder::new, Counter::new).handle;
    }

    /** Registers a timer; its name starts {@code oidf_} and ends {@code _seconds}. */
    public Timer timer(String name, String help, Label... labels) {
        return (Timer) register(Kind.TIMER, name, help, labels, Timer.Cell::new, Timer::new).handle;
    }

    /**
     * Registers a gauge with labels, each series bound to a supplier by {@link Gauge#set}. Its name starts
     * {@code oidf_} and ends in none of {@code _total}, {@code _count}, {@code _sum}, {@code _bucket} and
     * {@code _max}, which are counters' and timers'.
     */
    public Gauge gauge(String name, String help, Label... labels) {
        return (Gauge) register(Kind.GAUGE, name, help, labels, Gauge.Cell::new, Gauge::new).handle;
    }

    /** Registers a gauge without labels and binds its supplier, replacing the one bound before. */
    public Gauge gauge(String name, String help, DoubleSupplier supplier) {
        Gauge g = gauge(name, help);
        g.set(supplier);
        return g;
    }

    @SuppressWarnings("unchecked")
    <C> Family<C> register(Kind kind, String name, String help, Label[] labels, Supplier<C> factory, Function<Family<C>, ?> handle) {
        checkName(kind, name);
        checkHelp(name, help);
        List<Label> list = checkLabels(name, labels);
        Family<C> candidate = new Family<>(kind, name, help, list, factory);
        candidate.handle = handle.apply(candidate);
        boolean first;
        synchronized (this) {
            Family<?> existing = this.families.get(name);
            if (existing != null) {
                if (!existing.sameShape(candidate)) {
                    throw new IllegalArgumentException(name + " is already registered as a " + existing.kind + " with labels "
                            + existing.labels + "; this registration asks for a " + kind + " with " + list);
                }
                return (Family<C>) existing;
            }
            if (this.families.size() >= MAX_METRICS || this.reserved + candidate.maxSeries > MAX_SERIES) {
                this.refused.increment();
                long n = this.refused.sum();
                if ((n & (n - 1)) == 0) {
                    LOG.warn("Metrics: " + name + " is not shown: the registry is full (" + this.families.size() + " metrics, "
                            + this.reserved + " series reserved); " + n + " registration(s) refused so far");
                }
                return candidate;
            }
            this.families.put(name, candidate);
            this.reserved += candidate.maxSeries;
            first = !this.announced;
            this.announced = true;
        }
        if (first) {
            this.onFirstRegistration.run();
        }
        return candidate;
    }

    static void checkName(Kind kind, String name) {
        if (name == null || !NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("a metric name is oidf_ and then 1-123 of a-z, 0-9 and '_': " + name);
        }
        if (FOLDS.equals(name) || REFUSED.equals(name)) {
            throw new IllegalArgumentException(name + " is the registry's own");
        }
        boolean ok = switch (kind) {
            case COUNTER -> name.endsWith("_total");
            case TIMER -> name.endsWith("_seconds");
            case GAUGE -> !(name.endsWith("_total") || name.endsWith("_count") || name.endsWith("_sum")
                    || name.endsWith("_bucket") || name.endsWith("_max"));
        };
        if (!ok) {
            throw new IllegalArgumentException(name + ": a counter's name ends _total, a timer's _seconds, and a gauge's in "
                    + "none of _total, _count, _sum, _bucket or _max");
        }
    }

    static void checkHelp(String name, String help) {
        if (help == null || help.isBlank() || help.length() > MAX_HELP || help.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(name + ": help is one line of 1-" + MAX_HELP + " characters");
        }
    }

    static List<Label> checkLabels(String name, Label[] labels) {
        List<Label> list = labels == null ? List.of() : Arrays.asList(labels);
        if (list.size() > MAX_LABELS) {
            throw new IllegalArgumentException(name + ": at most " + MAX_LABELS + " labels");
        }
        Set<String> names = new HashSet<>();
        for (Label l : list) {
            Objects.requireNonNull(l, "label");
            if (!names.add(l.name())) {
                throw new IllegalArgumentException(name + ": label " + l.name() + " is declared twice");
            }
        }
        return list;
    }

    /** How many metrics a snapshot shows, the registry's own two not counted. */
    public synchronized int size() {
        return this.families.size();
    }

    /** How many series exist now, across every metric. */
    public int seriesCount() {
        int n = 0;
        for (Family<?> f : families()) {
            n += f.seriesCount();
        }
        return n;
    }

    /** How many label values have been counted as {@link Label#OTHER}, across every metric shown. */
    public long labelFolds() {
        long n = 0;
        for (Family<?> f : families()) {
            n += f.folds();
        }
        return n;
    }

    /** How many registrations have been refused because the registry was full. */
    public long refusedRegistrations() {
        return this.refused.sum();
    }

    private synchronized List<Family<?>> families() {
        return new ArrayList<>(this.families.values());
    }

    /**
     * Every metric and series now, ordered by name, with the registry's own two - {@value #FOLDS} (a series for
     * each metric that has folded a value) and {@value #REFUSED} - among them. Gauges' suppliers are read here.
     */
    public List<MetricSnapshot> snapshot() {
        List<MetricSnapshot> out = new ArrayList<>();
        List<SeriesSnapshot> folds = new ArrayList<>();
        for (Family<?> f : families()) {
            out.add(snapshot(f));
            long n = f.folds();
            if (n > 0) {
                folds.add(counterSeries(List.of(f.name), n));
            }
        }
        out.add(new MetricSnapshot(FOLDS, "Label values counted as other, because they were outside the label's declared set or past its cap",
                Kind.COUNTER, List.of("metric"), folds));
        out.add(new MetricSnapshot(REFUSED, "Metric registrations refused because the registry was full", Kind.COUNTER, List.of(),
                List.of(counterSeries(List.of(), this.refused.sum()))));
        out.sort((a, b) -> a.getName().compareTo(b.getName()));
        return List.copyOf(out);
    }

    private static MetricSnapshot snapshot(Family<?> f) {
        List<SeriesSnapshot> series = new ArrayList<>();
        for (Map.Entry<List<String>, ?> e : f.entries()) {
            Object cell = e.getValue();
            series.add(switch (f.kind) {
                case COUNTER -> counterSeries(e.getKey(), ((LongAdder) cell).sum());
                case GAUGE -> new SeriesSnapshot(e.getKey(), 0, ((Gauge.Cell) cell).read(), 0, 0, new long[0]);
                case TIMER -> timerSeries(e.getKey(), (Timer.Cell) cell);
            });
        }
        return new MetricSnapshot(f.name, f.help, f.kind, f.labelNames(), series);
    }

    private static SeriesSnapshot counterSeries(List<String> values, long count) {
        return new SeriesSnapshot(values, count, count, 0, 0, new long[0]);
    }

    private static SeriesSnapshot timerSeries(List<String> values, Timer.Cell cell) {
        long[] buckets = cell.cumulative();
        return new SeriesSnapshot(values, buckets[buckets.length - 1], 0, cell.sumNanos.sum() / 1e9, cell.maxNanos.get() / 1e9, buckets);
    }
}
