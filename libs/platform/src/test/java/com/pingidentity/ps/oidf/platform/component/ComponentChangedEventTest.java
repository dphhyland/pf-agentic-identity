/*
 * Every state change of a registered component is one platform.component.changed event, and a failing sink never
 * fails the move.
 */
package com.pingidentity.ps.oidf.platform.component;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ComponentChangedEventTest {

    private final List<Event> emitted = new ArrayList<>();

    @BeforeEach
    void capture() {
        Events.reset();
        Events.configure(this.emitted::add);
    }

    @AfterEach
    void forget() {
        Events.reset();
    }

    @Test
    void aStateChangeIsOneCountedEventAndTheSameStateAgainIsNone() {
        ComponentRegistry registry = new ComponentRegistry();
        ComponentRegistry.Component fapi = registry.register("FAPI", true);
        fapi.ready();
        fapi.ready();
        fapi.refused("a forbidden switch");
        assertEquals(2, this.emitted.size(), this.emitted.toString());
        Event first = this.emitted.get(0);
        assertEquals("platform.component.changed", first.code());
        assertEquals("platform", first.component());
        assertEquals(Map.of("component", "FAPI", "from", "STARTING", "to", "READY"), first.fields());
        assertEquals(Map.of("component", "FAPI", "from", "READY", "to", "REFUSED"), this.emitted.get(1).fields());
        assertTrue(!first.audit(), "counted, not audited");
    }

    @Test
    void anEventThatCannotBeBuiltNeverFailsTheMove() {
        Events.reset();
        Events.configure(e -> {
            throw new IllegalStateException("sink down");
        });
        ComponentRegistry registry = new ComponentRegistry();
        assertTrue(registry.register("SSF", true).ready());
        ComponentRegistry.changed("SSF", null, ComponentState.DEGRADED);
    }
}
