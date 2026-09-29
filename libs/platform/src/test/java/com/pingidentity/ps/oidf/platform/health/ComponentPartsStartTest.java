/*
 * A part's start never throws: it applies the switch, runs the start function, records the outcome and hands a
 * dependency failure to the supervisor, which runs the same function again until the part is ready.
 */
package com.pingidentity.ps.oidf.platform.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.component.ComponentRegistry;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.component.Supervisor;
import java.io.IOException;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ComponentPartsStartTest {

    private final ComponentRegistry registry = new ComponentRegistry();
    private final Map<String, ComponentSwitches.Kind> kinds = new HashMap<>();
    private final Deque<Runnable> due = new ArrayDeque<>();
    private boolean mayRetry = true;
    private final Supervisor supervisor = new Supervisor((delay, task) -> {
        if (!this.mayRetry) {
            return false;
        }
        this.due.add(task);
        return true;
    }, () -> 0.0, component -> { });
    private final ComponentParts parts = new ComponentParts(this.registry, Clock.systemUTC(), this::verdict, this.supervisor);

    private ComponentSwitches.Verdict verdict(String component) {
        ComponentSwitches.Kind kind = this.kinds.getOrDefault(component, ComponentSwitches.Kind.INFERRED);
        String name = "OIDF_" + component + "_ENABLED";
        return new ComponentSwitches.Verdict(component, name, kind, switch (kind) {
            case ENABLED -> name + "=true";
            case DISABLED -> name + "=false";
            case INFERRED -> name + " unset: inferred (development profile)";
            case FAILED_CONFIG -> name + " is unset and OIDF_X is set: in production set " + name + " to true or false";
        });
    }

    @Test
    void aStartThatSucceedsIsReadyWithTheSwitchNoteBesideIt() {
        ComponentParts.Part part = this.parts.begin("FEDERATION", "OpenIdFederationServlet");
        assertEquals(ComponentState.READY, part.start(() -> { }));
        assertEquals(ComponentState.READY, part.componentState());
        assertEquals("OIDF_FEDERATION_ENABLED unset: inferred (development profile)", this.registry.status("FEDERATION").orElseThrow().reason());
        assertEquals(Optional.of(ComponentState.READY), this.parts.component("FEDERATION").map(s -> s.state()));
        assertTrue(this.due.isEmpty());
    }

    @Test
    void aComponentSwitchedOffNeverRunsItsStart() {
        this.kinds.put("FAPI", ComponentSwitches.Kind.DISABLED);
        AtomicInteger runs = new AtomicInteger();
        ComponentParts.Part part = this.parts.begin("FAPI", "Fapi2ProfileFilter");
        assertEquals(ComponentState.DISABLED, part.start(runs::incrementAndGet));
        assertEquals(0, runs.get());
        assertEquals(ComponentState.DISABLED, part.componentState());
    }

    @Test
    void aComponentItsSwitchRefusesIsAFailedConfigurationNamingTheSwitch() {
        this.kinds.put("AUTO_REGISTRATION", ComponentSwitches.Kind.FAILED_CONFIG);
        AtomicInteger runs = new AtomicInteger();
        ComponentParts.Part part = this.parts.begin("AUTO_REGISTRATION", "TokenEndpointAutoRegistrationFilter");
        assertEquals(ComponentState.FAILED_CONFIG, part.start(runs::incrementAndGet));
        assertEquals(0, runs.get());
        assertTrue(part.status().reason().contains("OIDF_AUTO_REGISTRATION_ENABLED"), part.status().reason());
        assertTrue(this.due.isEmpty(), "never retried");
    }

    @Test
    void aStartMissingItsSettingsIsDisabledWhenInferredAndAFailedConfigurationWhenSwitchedOn() {
        ComponentParts.Part inferred = this.parts.begin("OPERATOR_API", "FederationAdminServlet");
        assertEquals(ComponentState.DISABLED, inferred.start(() -> inferred.notConfigured("OIDF_AUTHORITY_ADMIN_TOKEN is unset")));

        this.kinds.put("OPERATOR_API", ComponentSwitches.Kind.ENABLED);
        ComponentParts.Part on = this.parts.begin("OPERATOR_API", "FederationAdminServlet");
        assertEquals(ComponentState.FAILED_CONFIG, on.start(() -> on.notConfigured("OIDF_AUTHORITY_ADMIN_TOKEN is unset")));
        assertEquals("OIDF_OPERATOR_API_ENABLED=true but OIDF_AUTHORITY_ADMIN_TOKEN is unset", on.status().reason());
    }

    @Test
    void whatAStartThrowsIsRecordedAndNeverReachesTheCaller() {
        ComponentParts.Part part = this.parts.begin("HOSTING", "HostedEntityServlet");
        assertEquals(ComponentState.FAILED_CONFIG, part.start(() -> {
            throw new IllegalArgumentException("authorityEntityId is not a URL");
        }));
        assertEquals("authorityEntityId is not a URL", part.status().reason());
        assertTrue(this.due.isEmpty(), "a configuration failure is never retried");

        assertEquals(ComponentState.FAILED_CONFIG, part.start(() -> {
            throw new StackOverflowError();
        }));
    }

    @Test
    void anInterruptedStartKeepsTheInterrupt() {
        ComponentParts.Part part = this.parts.begin("SSF", "SsfConfigurationServlet");
        try {
            part.start(() -> {
                throw new InterruptedException("shutting down");
            });
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void aDependencyFailureIsRetriedUntilTheStartSucceeds() {
        AtomicInteger runs = new AtomicInteger();
        ComponentParts.Part part = this.parts.begin("HOSTING", "HostedEntityServlet");
        assertEquals(ComponentState.FAILED_DEPENDENCY, part.start(() -> {
            if (runs.incrementAndGet() < 3) {
                throw new IOException("OpenBao is not answering");
            }
        }));
        assertEquals(1, this.due.size());

        this.due.removeFirst().run();
        assertEquals(ComponentState.FAILED_DEPENDENCY, part.status().state());
        assertEquals(1, this.due.size(), "still failing: retried again");

        this.due.removeFirst().run();
        assertEquals(ComponentState.READY, part.status().state());
        assertEquals(3, runs.get());
        assertTrue(this.due.isEmpty(), "ready: the supervisor stops");
    }

    @Test
    void aRetryThatFailsOnConfigurationStops() {
        AtomicInteger runs = new AtomicInteger();
        ComponentParts.Part part = this.parts.begin("HOSTING", "HostedEntityServlet");
        part.start(() -> {
            if (runs.incrementAndGet() == 1) {
                throw new IOException("the store is not answering");
            }
            throw new IllegalStateException("the store answers, and its schema is not ours");
        });
        this.due.removeFirst().run();
        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertTrue(this.due.isEmpty());
    }

    @Test
    void aRetiredPartIsNotRetried() {
        AtomicInteger runs = new AtomicInteger();
        ComponentParts.Part first = this.parts.begin("HOSTING", "HostedEntityServlet");
        first.start(() -> {
            runs.incrementAndGet();
            throw new IOException("down");
        });
        // A second init registers the part again; the first handle's retry finds itself retired and stops.
        this.parts.begin("HOSTING", "HostedEntityServlet");
        this.due.removeFirst().run();
        assertEquals(1, runs.get());
        assertTrue(this.due.isEmpty());
    }

    @Test
    void aPartRegisteredAgainDuringARetryEndsTheOldRetry() {
        AtomicInteger runs = new AtomicInteger();
        ComponentParts.Part first = this.parts.begin("HOSTING", "HostedEntityServlet");
        first.start(() -> {
            if (runs.incrementAndGet() == 2) {
                // A second init, mid-retry, whose own start also fails on a dependency.
                this.parts.begin("HOSTING", "HostedEntityServlet").failedDependency("its own failure");
            }
            throw new IOException("down");
        });
        this.due.removeFirst().run();
        assertEquals(2, runs.get());
        assertTrue(this.due.isEmpty(), "the retired handle's retry stops; the new registration has its own");
    }

    @Test
    void aPartWithAProbeIsLeftToItsProbe() {
        ComponentParts.Part part = this.parts.begin("SSF", "SsfConfigurationServlet");
        part.start(() -> {
            part.failedDependency("the store is down", () -> {
                throw new IOException("still down");
            });
        });
        assertEquals(ComponentState.FAILED_DEPENDENCY, part.status().state());
        assertTrue(this.due.isEmpty(), "the probe retries it, not the supervisor");
    }

    @Test
    void aCopyThatMayNotRetryKeepsTheFailure() {
        this.mayRetry = false;
        ComponentParts.Part part = this.parts.begin("HOSTING", "HostedEntityServlet");
        assertEquals(ComponentState.FAILED_DEPENDENCY, part.start(() -> {
            throw new IOException("down");
        }));
        assertEquals(ComponentState.FAILED_DEPENDENCY, part.status().state());
    }

    @Test
    void partsWithNoSupervisorAreNotRetried() {
        ComponentParts plain = new ComponentParts(this.registry, Clock.systemUTC());
        ComponentParts.Part part = plain.begin("HOSTING", "HostedEntityServlet");
        assertEquals(ComponentState.FAILED_DEPENDENCY, part.start(() -> {
            throw new IOException("down");
        }));
        assertEquals(ComponentSwitches.Kind.INFERRED, part.verdict().kind());
        assertTrue(this.due.isEmpty());
    }

    @Test
    void switchesThatCannotBeReadRefuseTheComponent() {
        ComponentParts broken = new ComponentParts(this.registry, Clock.systemUTC(), component -> {
            throw new IllegalStateException("components.json is missing");
        }, this.supervisor);
        ComponentParts.Part part = broken.begin("FAPI", "Fapi2ProfileFilter");
        assertEquals(ComponentState.FAILED_CONFIG, part.start(() -> { }));
        assertTrue(part.status().reason().contains("the enable switches could not be read"), part.status().reason());
    }

    @Test
    void aComponentWithNoStateYetReadsStarting() {
        ComponentParts.Part part = this.parts.begin("ATTESTATION_ISSUER", "AttestationIssuanceServlet");
        assertEquals(ComponentState.STARTING, part.componentState());
        assertThrows(NullPointerException.class, () -> part.start(null));
        assertFalse(this.parts.component("NOT_REGISTERED").isPresent());
    }

    @Test
    void mayStartAnswersForAComponentWithNoSwitch() {
        // No switch: always inferred, so another component's start function may configure it.
        assertTrue(Startup.mayStart("GM_API"));
    }
}
