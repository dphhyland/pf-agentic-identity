/*
 * A component's parts register at init, and the registry shows the worst of the enabled ones.
 */
package com.pingidentity.ps.oidf.platform.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.component.ComponentRegistry;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class ComponentPartsTest {

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

    /** Every state a part can be moved to, the worst first. */
    private static final List<ComponentState> WORST_FIRST = List.of(ComponentState.FAILED_CONFIG, ComponentState.REFUSED,
            ComponentState.FAILED_DEPENDENCY, ComponentState.STARTING, ComponentState.DEGRADED, ComponentState.READY);

    private final Hand clock = new Hand();
    private final ComponentRegistry registry = new ComponentRegistry();
    private final ComponentParts parts = new ComponentParts(this.registry, this.clock);

    private ComponentStatus component(String name) {
        return this.registry.status(name).orElseThrow();
    }

    private static void moveTo(ComponentParts.Part part, ComponentState state) {
        switch (state) {
            case READY -> part.ready();
            case DEGRADED -> part.degraded("d");
            case FAILED_CONFIG -> part.failedConfig("c");
            case FAILED_DEPENDENCY -> part.failedDependency("f");
            case REFUSED -> part.refused("r");
            default -> { }
        }
    }

    @Test
    void aPartStartsAndFinishesReady() {
        ComponentParts.Part part = this.parts.begin("FEDERATION", "OpenIdFederationServlet");
        assertEquals(ComponentState.STARTING, part.status().state());
        assertEquals(ComponentState.STARTING, component("FEDERATION").state());
        assertTrue(component("FEDERATION").enabled());
        assertEquals("FEDERATION", part.component());
        assertEquals("OpenIdFederationServlet", part.part());

        assertTrue(part.finish());
        assertEquals(ComponentState.READY, part.status().state());
        assertEquals(ComponentState.READY, component("FEDERATION").state());
        assertFalse(part.finish(), "finish moves only a part that is still starting");
    }

    @Test
    void theComponentShowsTheWorstOfItsEnabledParts() {
        ComponentParts.Part token = this.parts.begin("AUTO_REGISTRATION", "TokenEndpointAutoRegistrationFilter");
        ComponentParts.Part front = this.parts.begin("AUTO_REGISTRATION", "FrontChannelAutoRegistrationFilter");
        token.finish();
        assertEquals(ComponentState.STARTING, component("AUTO_REGISTRATION").state(), "one part is still starting");
        front.degraded("slow");
        assertEquals(ComponentState.DEGRADED, component("AUTO_REGISTRATION").state());
        assertEquals("FrontChannelAutoRegistrationFilter: slow", component("AUTO_REGISTRATION").reason());
        token.failedDependency("store down");
        assertEquals(ComponentState.FAILED_DEPENDENCY, component("AUTO_REGISTRATION").state());
        front.failedConfig("no anchor keys");
        assertEquals(ComponentState.FAILED_CONFIG, component("AUTO_REGISTRATION").state());
        assertEquals("FrontChannelAutoRegistrationFilter: no anchor keys", component("AUTO_REGISTRATION").reason());
        token.failedConfig("bad setting");
        assertEquals("TokenEndpointAutoRegistrationFilter: bad setting; FrontChannelAutoRegistrationFilter: no anchor keys",
                component("AUTO_REGISTRATION").reason(), "every part in the worst state is named, in registration order");
    }

    @Test
    void worstOrdersEveryPairOfStates() {
        for (ComponentState a : WORST_FIRST) {
            for (ComponentState b : WORST_FIRST) {
                ComponentRegistry fresh = new ComponentRegistry();
                ComponentParts two = new ComponentParts(fresh, this.clock);
                moveTo(two.begin("SSF", "A"), a);
                moveTo(two.begin("SSF", "B"), b);
                two.begin("SSF", "C").disabled();
                ComponentState expected = WORST_FIRST.get(Math.min(WORST_FIRST.indexOf(a), WORST_FIRST.indexOf(b)));
                assertEquals(expected, fresh.status("SSF").orElseThrow().state(), a + " and " + b + ", beside a disabled part");
            }
        }
    }

    @Test
    void aComponentWithNoEnabledPartIsDisabledAndAnEnabledOneRegistersItAgain() {
        ComponentParts.Part front = this.parts.begin("AUTO_REGISTRATION", "FrontChannelAutoRegistrationFilter");
        assertTrue(front.disabled());
        assertEquals(ComponentState.DISABLED, component("AUTO_REGISTRATION").state());
        assertFalse(component("AUTO_REGISTRATION").enabled());
        assertFalse(front.ready(), "a disabled part stays disabled");
        assertFalse(front.failed(new IllegalStateException("x")));
        assertFalse(front.finish());
        assertFalse(front.disabled());
        assertEquals(ComponentState.DISABLED, front.status().state());

        ComponentParts.Part token = this.parts.begin("AUTO_REGISTRATION", "TokenEndpointAutoRegistrationFilter");
        assertTrue(component("AUTO_REGISTRATION").enabled());
        assertEquals(ComponentState.STARTING, component("AUTO_REGISTRATION").state());
        token.finish();
        assertEquals(ComponentState.READY, component("AUTO_REGISTRATION").state());
        token.disabled();
        assertFalse(component("AUTO_REGISTRATION").enabled(), "the last enabled part switching off disables the component");
    }

    @Test
    void registeringAPartAgainRetiresTheEarlierHandle() {
        ComponentParts.Part first = this.parts.begin("HOSTING", "HostedEntityServlet");
        first.failedConfig("no authority");
        ComponentParts.Part second = this.parts.begin("HOSTING", "HostedEntityServlet");
        assertEquals(ComponentState.STARTING, second.status().state(), "a second init starts the part afresh");
        assertFalse(first.ready(), "the earlier handle does nothing");
        assertFalse(first.finish());
        assertEquals(ComponentState.STARTING, component("HOSTING").state());
        assertEquals(1, this.parts.parts().size());
    }

    @Test
    void badNamesAreRefusedAndLeaveNothingBehind() {
        assertThrows(IllegalArgumentException.class, () -> this.parts.begin("FEDERATION", null));
        assertThrows(IllegalArgumentException.class, () -> this.parts.begin("FEDERATION", "1Servlet"));
        assertThrows(IllegalArgumentException.class, () -> this.parts.begin("FEDERATION", "a b"));
        assertThrows(IllegalArgumentException.class, () -> this.parts.begin("FEDERATION", "x".repeat(65)));
        this.parts.begin("FEDERATION", "A-b_c.D1");
        assertThrows(IllegalArgumentException.class, () -> this.parts.begin("federation", "OpenIdFederationServlet"));
        assertEquals(1, this.parts.parts().size(), "the refused component left no part behind");
        assertTrue(this.registry.status("federation").isEmpty());
    }

    @Test
    void aRefusedComponentNameLeavesTheOthersAlone() {
        this.parts.begin("SSF", "SsfConfigurationServlet").finish();
        assertThrows(IllegalArgumentException.class, () -> this.parts.begin("ssf", "SsfConfigurationServlet"));
        assertEquals(List.of("SSF"), this.parts.parts().stream().map(PartStatus::component).toList());
        assertEquals(ComponentState.READY, this.parts.parts().get(0).state());
    }

    @Test
    void anInitExceptionIsAConfigurationOrADependencyFailure() {
        assertEquals(ComponentState.FAILED_CONFIG, ComponentParts.stateFor(new IllegalStateException("OIDF_X is not a number")));
        assertEquals(ComponentState.FAILED_CONFIG, ComponentParts.stateFor(new RuntimeException("wrapped", new IllegalArgumentException())));
        assertEquals(ComponentState.FAILED_DEPENDENCY, ComponentParts.stateFor(new IOException("disk")));
        assertEquals(ComponentState.FAILED_DEPENDENCY, ComponentParts.stateFor(new RuntimeException(new ConnectException("refused"))));
        assertEquals(ComponentState.FAILED_DEPENDENCY, ComponentParts.stateFor(new UncheckedIOException(new IOException("x"))));
        assertEquals(ComponentState.FAILED_DEPENDENCY, ComponentParts.stateFor(new IllegalStateException(new SQLException("db"))));
        assertEquals(ComponentState.FAILED_DEPENDENCY, ComponentParts.stateFor(new RuntimeException(new TimeoutException())));
        assertEquals(ComponentState.FAILED_DEPENDENCY, ComponentParts.stateFor(new NoClassDefFoundError("org/x/Y")));
        assertEquals(ComponentState.FAILED_CONFIG, ComponentParts.stateFor(new AssertionError("an Error that is not a linkage one")));
    }

    @Test
    void aCauseChainIsFollowedAFixedDistanceAndNeverRoundACycle() {
        Cyclic a = new Cyclic("a");
        Cyclic b = new Cyclic("b");
        a.next = b;
        b.next = a;
        assertEquals(ComponentState.FAILED_CONFIG, ComponentParts.stateFor(a));
        assertEquals("a (Cyclic: b)", ComponentParts.reasonOf(a));

        Throwable deep = new IOException("far down");
        for (int i = 0; i < ComponentParts.MAX_CAUSES; i++) {
            deep = new RuntimeException("level " + i, deep);
        }
        assertEquals(ComponentState.FAILED_CONFIG, ComponentParts.stateFor(deep), "past the limit the I/O cause is not seen");
        assertEquals("level " + (ComponentParts.MAX_CAUSES - 1) + " (RuntimeException: level 0)", ComponentParts.reasonOf(deep),
                "the reason's root is the last cause within the limit");
    }

    /** An exception whose cause can be made to point back at it. */
    private static final class Cyclic extends RuntimeException {
        Throwable next;

        Cyclic(String message) {
            super(message);
        }

        @Override
        public synchronized Throwable getCause() {
            return this.next;
        }
    }

    @Test
    void aReasonIsTheMessageAndTheRootCauseWhenItSaysMore() {
        assertEquals("bad", ComponentParts.reasonOf(new IllegalStateException("bad")));
        assertEquals("IllegalStateException", ComponentParts.reasonOf(new IllegalStateException()));
        assertEquals("IllegalStateException", ComponentParts.reasonOf(new IllegalStateException(" ")));
        assertEquals("Failed to initialize (SQLException: connection refused)",
                ComponentParts.reasonOf(new RuntimeException("Failed to initialize", new IllegalStateException("middle",
                        new SQLException("connection refused")))));
        assertEquals("OpenID Federation automatic registration: no anchor",
                ComponentParts.reasonOf(new RuntimeException("OpenID Federation automatic registration: no anchor",
                        new IllegalStateException("no anchor"))), "a cause the message already carries is not repeated");
        assertEquals("Failed (TimeoutException)", ComponentParts.reasonOf(new RuntimeException("Failed", new TimeoutException())));
        assertEquals("Failed (TimeoutException)", ComponentParts.reasonOf(new RuntimeException("Failed", new TimeoutException(" "))));
    }

    @Test
    void failedRecordsWhatTheExceptionSays() {
        ComponentParts.Part part = this.parts.begin("ATTESTATION_ISSUER", "AttestationIssuanceServlet");
        assertTrue(part.failed(new RuntimeException("attestation issuance: the RAR containment models could not be loaded")));
        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertEquals("attestation issuance: the RAR containment models could not be loaded", part.status().reason());
        assertEquals("AttestationIssuanceServlet: attestation issuance: the RAR containment models could not be loaded",
                component("ATTESTATION_ISSUER").reason());
        assertFalse(part.finish(), "finish keeps a failure");
        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
    }

    @Test
    void aProbeMakesAPartReadyOnceItsDependencyIsBack() {
        AtomicBoolean back = new AtomicBoolean();
        ComponentParts.Part ssf = this.parts.begin("SSF", "SsfConfigurationServlet");
        ssf.failedDependency("store down", () -> {
            if (!back.get()) {
                throw new IllegalStateException("not configured");
            }
        });
        ComponentParts.Part other = this.parts.begin("SSF_RECEIVER", "SsfReceiverServlet");
        other.failedDependency("store down", () -> {
            throw new NoClassDefFoundError("x");
        });
        this.parts.refresh();
        assertEquals(ComponentState.FAILED_DEPENDENCY, ssf.status().state());
        assertEquals(ComponentState.FAILED_DEPENDENCY, other.status().state(), "a probe that fails to link counts as not back");
        back.set(true);
        this.parts.refresh();
        assertEquals(ComponentState.READY, ssf.status().state());
        assertEquals(ComponentState.READY, component("SSF").state());
        ssf.failedConfig("later");
        back.set(false);
        this.parts.refresh();
        assertEquals(ComponentState.FAILED_CONFIG, ssf.status().state(), "leaving FAILED_DEPENDENCY drops the probe");
    }

    @Test
    void aProbeOfARetiredPartDoesNothing() {
        ComponentParts.Part old = this.parts.begin("SSF", "SsfConfigurationServlet");
        AtomicBoolean ran = new AtomicBoolean();
        ComponentParts[] self = {this.parts};
        old.failedDependency("down", () -> {
            ran.set(true);
            self[0].begin("SSF", "SsfConfigurationServlet");
        });
        this.parts.refresh();
        assertTrue(ran.get());
        assertEquals(ComponentState.STARTING, this.parts.parts().get(0).state(), "the probe's part was replaced while it ran");
    }

    @Test
    void theTimeAPartEnteredItsStateMovesOnlyWhenTheStateOrReasonChanges() {
        ComponentParts.Part part = this.parts.begin("FAPI", "Fapi2ProfileFilter");
        Instant start = this.clock.now;
        this.clock.now = start.plus(Duration.ofSeconds(5));
        part.degraded("slow");
        assertEquals(start.plusSeconds(5), part.status().since());
        this.clock.now = start.plus(Duration.ofSeconds(9));
        part.degraded("slow");
        assertEquals(start.plusSeconds(5), part.status().since(), "the same state and reason keep their time");
        part.degraded("slower");
        assertEquals(start.plusSeconds(9), part.status().since());
    }

    @Test
    void aReasonIsKeptToOneShortLine() {
        assertEquals("no reason given", ComponentParts.clean(null));
        assertEquals("no reason given", ComponentParts.clean("  "));
        assertEquals("a?b?c?d?e", ComponentParts.clean(" a\nb\u200Bc\u2028d\u2029e "));
        assertEquals(256, ComponentParts.clean("x".repeat(300)).length());
        String split = "x".repeat(255) + "\uD83D\uDE00" + "y";
        assertEquals("x".repeat(255), ComponentParts.clean(split), "a surrogate pair is not cut in half");
        ComponentParts.Part part = this.parts.begin("OPERATOR_API", "FederationAdminServlet");
        part.failedConfig(null);
        assertEquals("no reason given", part.status().reason());
        part.ready();
        assertEquals("", part.status().reason(), "a state that needs no reason has none");
    }

    @Test
    void partsAreListedByComponentThenPart() {
        this.parts.begin("SSF", "B");
        this.parts.begin("FEDERATION", "Z");
        this.parts.begin("SSF", "A");
        assertEquals(List.of("FEDERATION/Z", "SSF/A", "SSF/B"),
                this.parts.parts().stream().map(p -> p.component() + "/" + p.part()).toList());
    }

    @Test
    void startupIsThisLoadersPartsOverThisLoadersRegistry() {
        ComponentParts.Part part = Startup.begin(Startup.OPERATOR_API, "StartupTestPart");
        part.finish();
        assertTrue(Startup.parts().parts().stream().anyMatch(p -> p.part().equals("StartupTestPart")));
        assertEquals(List.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH", "ATTESTATION_ISSUER", "HOSTING", "SSF",
                "SSF_RECEIVER", "OPERATOR_API", "FAPI"), List.of(Startup.FEDERATION, Startup.AUTO_REGISTRATION, Startup.ATTESTATION_AUTH,
                Startup.ATTESTATION_ISSUER, Startup.HOSTING, Startup.SSF, Startup.SSF_RECEIVER, Startup.OPERATOR_API, Startup.FAPI),
                "S-9's nine names");
        assertEquals(ComponentState.READY, com.pingidentity.ps.oidf.platform.component.Components.status(Startup.OPERATOR_API)
                .orElseThrow().state());
    }
    @Test
    void theGraceIsTheSupervisorsFirstTwoCeilings() {
        assertEquals(java.time.Duration.ofSeconds(15), ComponentParts.GRACE);
    }

    @Test
    void aServingComponentThatFailsOnADependencyIsGracedWhileItIsRetriedAndOnlyForTheGrace() {
        ComponentParts.Part part = this.parts.begin("SSF", "SsfConfigurationServlet");
        part.ready();
        assertFalse(this.parts.graced("SSF"));
        part.failedDependency("the database dropped");
        assertTrue(this.parts.graced("SSF"), "a blip: it was serving");
        // The supervisor's retries go through STARTING and back; the blip holds from when it began.
        this.clock.now = this.clock.now.plusSeconds(6);
        this.parts.move("SSF", "SsfConfigurationServlet", generation(part), ComponentState.STARTING, null, null);
        assertTrue(this.parts.graced("SSF"));
        part.failedDependency("still down");
        this.clock.now = this.clock.now.plusSeconds(8);
        assertTrue(this.parts.graced("SSF"), "14 s in");
        this.clock.now = this.clock.now.plusSeconds(1);
        assertFalse(this.parts.graced("SSF"), "15 s in: the grace is over and ready counts it");
        // Back: the blip ends, and a later blip starts its own grace.
        part.ready();
        assertFalse(this.parts.graced("SSF"));
        part.degraded("slow");
        part.failedDependency("dropped again");
        assertTrue(this.parts.graced("SSF"), "DEGRADED was serving too");
    }

    @Test
    void noGraceForAComponentThatNeverServedOrFailedOnAnythingButADependency() {
        ComponentParts.Part boot = this.parts.begin("SSF", "SsfConfigurationServlet");
        boot.failedDependency("the database is not there at boot");
        assertFalse(this.parts.graced("SSF"), "it never served");

        ComponentParts.Part config = this.parts.begin("FEDERATION", "OpenIdFederationServlet");
        config.ready();
        config.failedConfig("a bad setting");
        assertFalse(this.parts.graced("FEDERATION"));

        ComponentParts.Part dep = this.parts.begin("HOSTING", "HostedEntityServlet");
        dep.ready();
        dep.failedDependency("dropped");
        assertTrue(this.parts.graced("HOSTING"));
        dep.failedConfig("and then refused its configuration");
        assertFalse(this.parts.graced("HOSTING"), "a blip ends with anything but a retry");
        assertFalse(this.parts.graced("NOT_REGISTERED"));
    }

    @Test
    void theGateViewIsPublishedOnEveryChangeWithTheComponentsRefusal() {
        ComponentParts.Part a = this.parts.begin("FEDERATION", "A");
        assertEquals(new ComponentParts.GateView(ComponentState.STARTING, false), a.gateView());
        a.ready();
        assertEquals(new ComponentParts.GateView(ComponentState.READY, false), a.gateView());
        ComponentParts.Part b = this.parts.begin("FEDERATION", "B");
        b.refused("a forbidden setting");
        assertEquals(new ComponentParts.GateView(ComponentState.READY, true), a.gateView());
        assertEquals(new ComponentParts.GateView(ComponentState.REFUSED, true), b.gateView());
        b.disabled();
        assertEquals(new ComponentParts.GateView(ComponentState.DISABLED, false), b.gateView());
        assertEquals(new ComponentParts.GateView(ComponentState.READY, false), a.gateView());
    }

    private static long generation(ComponentParts.Part part) {
        try {
            java.lang.reflect.Field f = ComponentParts.Part.class.getDeclaredField("generation");
            f.setAccessible(true);
            return f.getLong(part);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }
}
