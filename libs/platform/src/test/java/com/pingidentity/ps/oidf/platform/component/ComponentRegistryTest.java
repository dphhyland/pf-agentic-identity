/*
 * A component is registered once, reports its state through its handle, and health reads a snapshot.
 */
package com.pingidentity.ps.oidf.platform.component;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.component.ComponentRegistry.Component;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ComponentRegistryTest {

    /** A clock the test moves by hand. */
    private static final class Hand extends Clock {
        Instant now = Instant.parse("2026-09-28T00:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return this.now;
        }
    }

    private final Hand clock = new Hand();
    private final ComponentRegistry registry = new ComponentRegistry(this.clock);

    @Test
    void anEnabledComponentStartsAndADisabledOneStaysDisabled() {
        Component federation = this.registry.register("FEDERATION", true);
        Component ssf = this.registry.register("SSF", false);
        assertEquals(new ComponentStatus("FEDERATION", true, ComponentState.STARTING, "", this.clock.now), federation.status());
        assertEquals(ComponentState.DISABLED, ssf.status().state());
        assertFalse(ssf.ready(), "a disabled component's handle does nothing");
        assertFalse(ssf.failedConfig("x"));
        assertFalse(ssf.starting());
        assertEquals(ComponentState.DISABLED, ssf.status().state());
        assertEquals("SSF", ssf.name());
    }

    @Test
    void theHandleMovesAnEnabledComponentThroughEveryState() {
        Component c = this.registry.register("SSF_RECEIVER", true);
        assertTrue(c.ready());
        assertEquals(new ComponentStatus("SSF_RECEIVER", true, ComponentState.READY, "", this.clock.now), c.status());
        assertTrue(c.degraded("Redis slow"));
        assertEquals("Redis slow", c.status().reason());
        assertTrue(c.failedDependency("database unreachable"));
        assertEquals(ComponentState.FAILED_DEPENDENCY, c.status().state());
        assertTrue(c.starting());
        assertEquals(new ComponentStatus("SSF_RECEIVER", true, ComponentState.STARTING, "", this.clock.now), c.status());
        assertTrue(c.failedConfig("OIDF_SSF_ISSUER is not an https URL"));
        assertEquals(ComponentState.FAILED_CONFIG, c.status().state());
        assertTrue(c.refused("insecure TLS is forbidden in production"));
        assertEquals(ComponentState.REFUSED, c.status().state());
        assertTrue(c.ready());
        assertEquals("", c.status().reason(), "a state that needs no reason keeps none");
    }

    /** Reporting the same state and reason again keeps the time it was entered; a new reason is a new entry. */
    @Test
    void theSameStateKeepsItsTime() {
        Component c = this.registry.register("HOSTING", true);
        Instant first = this.clock.now;
        c.degraded("slow");
        this.clock.now = first.plus(Duration.ofMinutes(5));
        assertTrue(c.degraded("slow"));
        assertEquals(first, c.status().since());
        assertTrue(c.degraded("slower"));
        assertEquals(this.clock.now, c.status().since());
    }

    /** A servlet initialised again registers again; the earlier instance's handle can no longer move it. */
    @Test
    void registeringAgainStartsAfreshAndRetiresTheOldHandle() {
        Component old = this.registry.register("FEDERATION", true);
        old.ready();
        Component fresh = this.registry.register("FEDERATION", false);
        assertEquals(ComponentState.DISABLED, fresh.status().state());
        assertFalse(old.failedConfig("late report from a destroyed instance"));
        assertEquals(ComponentState.DISABLED, this.registry.status("FEDERATION").orElseThrow().state());
        Component again = this.registry.register("FEDERATION", true);
        assertFalse(old.ready());
        assertTrue(again.ready());
        assertEquals(1, this.registry.snapshot().size());
    }

    @Test
    void theSnapshotIsOrderedByNameAndCannotBeChanged() {
        this.registry.register("SSF", true);
        this.registry.register("FAPI", false);
        this.registry.register("ATTESTATION_AUTH", true);
        List<ComponentStatus> snapshot = this.registry.snapshot();
        assertEquals(List.of("ATTESTATION_AUTH", "FAPI", "SSF"), snapshot.stream().map(ComponentStatus::name).toList());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.remove(0));
        assertEquals(Optional.empty(), this.registry.status("OPERATOR_API"));
    }

    @Test
    void namesAreSNinesSpellingShortAndLogSafe() {
        for (String ok : List.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH", "ATTESTATION_ISSUER", "HOSTING", "SSF",
                "SSF_RECEIVER", "OPERATOR_API", "FAPI", "A", "X".repeat(64), "V2_API")) {
            ComponentRegistry.checkName(ok);
        }
        for (String bad : Arrays.asList(null, "", "federation", "Federation", "ssf-receiver", "ATTESTATION.ISSUER", "_LEAD",
                "9LIVES", "X".repeat(65), "A B", "A\nB", "\u00c9")) {
            assertThrows(IllegalArgumentException.class, () -> this.registry.register(bad, true), String.valueOf(bad));
        }
    }

    @Test
    void theStatesThatNeedAReasonAreTheOnesNotServingNormally() {
        for (ComponentState s : ComponentState.values()) {
            boolean expected = s == ComponentState.DEGRADED || s == ComponentState.FAILED_CONFIG
                    || s == ComponentState.FAILED_DEPENDENCY || s == ComponentState.REFUSED;
            assertEquals(expected, s.needsReason(), s.name());
        }
        assertEquals(List.of("DISABLED", "STARTING", "READY", "DEGRADED", "FAILED_CONFIG", "FAILED_DEPENDENCY", "REFUSED"),
                Arrays.stream(ComponentState.values()).map(Enum::name).toList(), "S-9's names, in S-9's order");
    }

    /** A reason is one short line: nothing in it can start a log line of its own or hide from the operator. */
    @Test
    void aReasonIsCleanedToOneShortLine() {
        assertEquals("no reason given", ComponentRegistry.clean(null));
        assertEquals("no reason given", ComponentRegistry.clean(" \t "));
        assertEquals("bad value", ComponentRegistry.clean("  bad value \n"));
        assertEquals("a?b?c?d?e?f?g", ComponentRegistry.clean("a\nb\rc\u2028d\u202ee\u0085f\u2029g"));
        assertEquals("x".repeat(ComponentRegistry.MAX_REASON), ComponentRegistry.clean("x".repeat(1000)));
        String pairAtTheCut = "x".repeat(ComponentRegistry.MAX_REASON - 1) + "\ud83d\ude00";
        assertEquals("x".repeat(ComponentRegistry.MAX_REASON - 1), ComponentRegistry.clean(pairAtTheCut), "never half a pair");
        String pairInside = "x".repeat(ComponentRegistry.MAX_REASON - 2) + "\ud83d\ude00";
        assertEquals(pairInside, ComponentRegistry.clean(pairInside));
        Component c = this.registry.register("FAPI", true);
        c.failedDependency(null);
        assertEquals("no reason given", c.status().reason());
    }

    /** The static entry point is this loader's one registry. */
    @Test
    void componentsIsTheLoadersRegistry() {
        Component c = Components.register("PLATFORM_TEST_COMPONENT", true);
        c.ready();
        assertEquals(ComponentState.READY, Components.status("PLATFORM_TEST_COMPONENT").orElseThrow().state());
        assertTrue(Components.snapshot().stream().anyMatch(s -> s.name().equals("PLATFORM_TEST_COMPONENT")));
        assertSame(Components.registry(), Components.registry());
        assertTrue(new ComponentRegistry().snapshot().isEmpty());
    }
}
