/*
 * Every event counts itself: platform.events' bridge to platform.metrics (plan item O-4).
 */
package com.pingidentity.ps.oidf.platform.events;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.metrics.Counter;
import com.pingidentity.ps.oidf.platform.metrics.Label;
import com.pingidentity.ps.oidf.platform.metrics.MetricRegistry;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

/**
 * Counts each event {@link Events#emit} admits, before any sink sees it, in {@value #EVENTS}: one series per
 * catalogued code and outcome. Both labels are declared sets taken from the catalogues this loader reads, so the
 * series are bounded by the catalogues: a code or outcome no catalogue declares counts as {@code other}, and
 * {@code oidf_metrics_label_folds_total{metric="oidf_events_total"}} rises with it - which is how an emitter that
 * has drifted from its catalogue shows up. Two gauges read the catalogues' own counts: {@value #DROPPED_FIELDS},
 * the fields admission dropped, and {@value #UNCATALOGUED}, the events whose code no catalogue declares.
 *
 * <p>The counter is registered once per loader, the first time an event is counted, in that loader's
 * {@link Metrics} registry - so an event the engine's copy emits from an OGNL criterion is counted in the engine's
 * registry. Counting never fails an event: a registration the registry refuses (a catalogue that outgrows the
 * 2048-series bound, which is when the counter splits by component instead) is logged once and the events go
 * uncounted.
 */
final class EventMetrics {

    static final String EVENTS = "oidf_events_total";
    static final String DROPPED_FIELDS = "oidf_events_dropped_fields";
    static final String UNCATALOGUED = "oidf_events_uncatalogued";

    private static final PlatformLog LOG = PlatformLog.get(EventMetrics.class);
    private static final Object LOCK = new Object();
    private static volatile Supplier<MetricRegistry> registries = Metrics::registry;
    private static volatile Bound bound;

    /** The counter for one set of catalogues in one registry; {@code counter} is null when it could not be registered. */
    private record Bound(EventCatalogues catalogues, MetricRegistry registry, Counter counter) {
    }

    private EventMetrics() {
    }

    /** Counts {@code admitted}, an event {@code catalogues} has admitted. Never throws. */
    static void count(EventCatalogues catalogues, Event admitted) {
        try {
            Counter counter = counterFor(catalogues);
            if (counter != null) {
                counter.inc(admitted.code(), admitted.outcome().name().toLowerCase(Locale.ROOT));
            }
        } catch (RuntimeException e) {
            // Counting never fails the event it counts.
        }
    }

    /** The counter for {@code catalogues} in the current registry, registered on first use. */
    static Counter counterFor(EventCatalogues catalogues) {
        MetricRegistry registry = registries.get();
        Bound local = bound;
        if (local != null && local.catalogues() == catalogues && local.registry() == registry) {
            return local.counter();
        }
        synchronized (LOCK) {
            // Two threads can both get here; the second registration returns the first's counter.
            local = new Bound(catalogues, registry, register(registry, catalogues));
            bound = local;
            return local.counter();
        }
    }

    /**
     * Registers {@value #EVENTS} over every code and outcome {@code catalogues} declares, and the two gauges over
     * its counts. Null when there is no catalogue to take the labels from, or the registry refuses the counter.
     */
    static Counter register(MetricRegistry registry, EventCatalogues catalogues) {
        registry.gauge(DROPPED_FIELDS, "Event fields dropped because the event's code does not declare them",
                catalogues::droppedFields);
        registry.gauge(UNCATALOGUED, "Events whose code no event catalogue declares", catalogues::uncataloguedEvents);
        Set<String> codes = new TreeSet<>();
        Set<String> outcomes = new TreeSet<>();
        for (EventCatalogue catalogue : catalogues.components().values()) {
            for (EventCatalogue.Code code : catalogue.codes().values()) {
                codes.add(code.code());
                for (Event.Outcome outcome : code.outcomes()) {
                    outcomes.add(outcome.name().toLowerCase(Locale.ROOT));
                }
            }
        }
        if (codes.isEmpty()) {
            return null;
        }
        try {
            return registry.counter(EVENTS, "Events emitted, by catalogued code and outcome",
                    Label.oneOf("code", codes), Label.oneOf("outcome", outcomes));
        } catch (IllegalArgumentException e) {
            LOG.warn("Events are not counted in " + EVENTS + ": " + LogSafe.value(e.getMessage()));
            return null;
        }
    }

    /** Tests only: count into the registry {@code source} gives, not this loader's {@link Metrics} registry. */
    static void useRegistry(Supplier<MetricRegistry> source) {
        synchronized (LOCK) {
            registries = source == null ? Metrics::registry : source;
            bound = null;
        }
    }
}
