/*
 * Every event counts itself, by catalogued code and outcome, before any sink runs.
 */
package com.pingidentity.ps.oidf.platform.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.metrics.Counter;
import com.pingidentity.ps.oidf.platform.metrics.MetricRegistry;
import com.pingidentity.ps.oidf.platform.metrics.MetricSnapshot;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class EventMetricsTest {

    private final MetricRegistry registry = new MetricRegistry();

    @AfterEach
    void reset() {
        EventMetrics.useRegistry(null);
        Events.reset();
    }

    private double gauge(String name) {
        for (MetricSnapshot m : this.registry.snapshot()) {
            if (m.getName().equals(name)) {
                return m.getSeries().get(0).getValue();
            }
        }
        throw new AssertionError(name + " is not registered");
    }

    @Test
    void anEventIsCountedByItsCodeAndOutcomeEvenWhenTheSinkFails() {
        EventMetrics.useRegistry(() -> this.registry);
        EventCatalogues catalogues = TestCatalogues.shopAndBank();
        EventCatalogues.install(catalogues);
        Events.configure(event -> {
            throw new IllegalStateException("the sink is down");
        });

        Events.event(null, "shop.order.placed").field("item", "tea").emit();
        Events.event(null, "shop.order.placed").emit();
        Events.event(null, "shop.order.refused").failure("out_of_stock").emit();
        Events.event(null, "nobody.declares.this").emit();

        Counter events = EventMetrics.counterFor(catalogues);
        assertEquals(2, events.get("shop.order.placed", "success"));
        assertEquals(1, events.get("shop.order.refused", "failure"));
        assertEquals(1, events.get("other", "success"), "an uncatalogued code folds into other");
        assertEquals(1, gauge(EventMetrics.UNCATALOGUED));
        assertEquals(0, gauge(EventMetrics.DROPPED_FIELDS));
        Events.event(null, "shop.order.placed").field("card_number", "4111").emit();
        assertEquals(1, gauge(EventMetrics.DROPPED_FIELDS));
    }

    @Test
    void theCounterIsRegisteredOncePerCataloguesAndRegistry() {
        EventMetrics.useRegistry(() -> this.registry);
        EventCatalogues catalogues = TestCatalogues.shopAndBank();
        Counter first = EventMetrics.counterFor(catalogues);
        assertSame(first, EventMetrics.counterFor(catalogues));
        assertEquals(List.of("code", "outcome"), labelsOf(EventMetrics.EVENTS));

        java.util.concurrent.atomic.AtomicReference<MetricRegistry> current = new java.util.concurrent.atomic.AtomicReference<>(this.registry);
        EventMetrics.useRegistry(current::get);
        assertSame(first, EventMetrics.counterFor(catalogues));
        current.set(new MetricRegistry());
        Counter second = EventMetrics.counterFor(catalogues);
        assertEquals(false, first == second, "another registry, another counter");
        current.set(this.registry);
        assertSame(first, EventMetrics.counterFor(catalogues), "the same catalogues in the first registry again: its counter");
    }

    @Test
    void noCatalogueMeansNothingToCountAndARefusedRegistrationIsNotAnError() {
        EventMetrics.useRegistry(() -> this.registry);
        EventCatalogues none = EventCatalogues.of(List.of());
        assertNull(EventMetrics.counterFor(none));
        EventMetrics.count(none, Event.builder("shop", "shop.order.placed").build());

        // Another shape under the same name - a second set of catalogues in one registry - is refused by the
        // registry; the events go uncounted and nothing throws.
        EventCatalogues shop = EventCatalogues.of(List.of(TestCatalogues.shop()));
        EventCatalogues bank = EventCatalogues.of(List.of(TestCatalogues.bank()));
        EventMetrics.counterFor(shop);
        assertNull(EventMetrics.counterFor(bank));
        EventMetrics.count(bank, Event.builder("bank", "bank.transfer.made").build());
    }

    @Test
    void aCounterThatThrowsNeverFailsTheEvent() {
        EventMetrics.useRegistry(() -> {
            throw new IllegalStateException("no registry");
        });
        EventMetrics.count(TestCatalogues.shopAndBank(), Event.builder("shop", "shop.order.placed").build());
    }

    @Test
    void byDefaultEventsCountInThisLoadersRegistry() {
        EventMetrics.useRegistry(null);
        EventCatalogues catalogues = TestCatalogues.shopAndBank();
        Counter counter = EventMetrics.counterFor(catalogues);
        if (counter != null) {
            // Another test in this JVM may have registered oidf_events_total over other catalogues first; the
            // registry then refuses this shape, which is the documented behaviour.
            assertTrue(Metrics.registry().snapshot().stream().anyMatch(m -> m.getName().equals(EventMetrics.EVENTS)));
        }
    }

    private List<String> labelsOf(String name) {
        List<String> out = new ArrayList<>();
        for (MetricSnapshot m : this.registry.snapshot()) {
            if (m.getName().equals(name)) {
                out.addAll(m.getLabelNames());
            }
        }
        return out;
    }
}
