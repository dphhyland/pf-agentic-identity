/*
 * The per-loader sink registry.
 */
package com.pingidentity.ps.oidf.platform.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class EventsTest {

    @AfterEach
    void reset() {
        Events.reset();
    }

    @Test
    void theFirstConfiguredSinkWinsAndEmitNeverThrows() {
        List<Event> seen = new ArrayList<>();
        EventSink capture = seen::add;
        Events.configure(capture);
        Events.configure(capture);
        Events.configure(e -> {
            throw new IllegalStateException("should never be installed");
        });
        assertSame(capture, Events.sink());
        assertTrue(Events.isConfigured());

        Events.event("shop", "shop.order.placed").subject("c").emit();
        Events.emit(null);
        assertEquals(1, seen.size());
        assertEquals("c", seen.get(0).subject());

        Events.reset();
        Events.configure(e -> {
            throw new IllegalStateException("a sink that throws");
        });
        Events.event("shop", "x.y.z").emit();
    }

    @Test
    void withNothingConfiguredEventsGoToTheLoggingSink() {
        assertFalse(Events.isConfigured());
        assertInstanceOf(LoggingSink.class, Events.sink());
        assertSame(Events.sink(), Events.sink());
        Events.event("shop", "shop.order.placed").emit();
    }

    @Test
    void aFieldTheCodeDoesNotDeclareNeverReachesTheSink() {
        EventCatalogues catalogues = TestCatalogues.shopAndBank();
        EventCatalogues.install(catalogues);
        List<Event> seen = new ArrayList<>();
        Events.configure(seen::add);

        Events.event(null, "shop.order.placed").field("item", "tea").field("card_number", "4111").emit();

        assertEquals(Map.of("item", "tea"), seen.get(0).fields());
        assertEquals("shop", seen.get(0).component());
        assertEquals(1, catalogues.droppedFields());
    }

    @Test
    void resetForgetsTheLoadedCatalogues() {
        EventCatalogues installed = TestCatalogues.shopAndBank();
        EventCatalogues.install(installed);
        assertSame(installed, EventCatalogues.current());
        Events.reset();
        assertTrue(EventCatalogues.current().components().isEmpty(), "platform's own test classpath has no catalogue");
    }
}
