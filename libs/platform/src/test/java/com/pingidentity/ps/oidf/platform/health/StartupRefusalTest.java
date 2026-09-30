/*
 * A part of a component the production profile refuses is REFUSED when it registers and its start configures nothing.
 */
package com.pingidentity.ps.oidf.platform.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.component.ComponentRegistry;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StartupRefusalTest {

    private final ComponentRegistry registry = new ComponentRegistry();
    private final Map<String, ComponentSwitches.Kind> kinds = new HashMap<>();
    private final ComponentParts parts = new ComponentParts(this.registry, Clock.systemUTC(),
            c -> new ComponentSwitches.Verdict(c, "OIDF_" + c + "_ENABLED", this.kinds.getOrDefault(c, ComponentSwitches.Kind.INFERRED),
                    ""), null);

    static final List<String> EVERY = List.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH", "ATTESTATION_ISSUER", "HOSTING",
            "SSF", "SSF_RECEIVER", "OPERATOR_API", "FAPI");

    static void publish(DeploymentProfile profile, ProfileAudit.Violation... violations) {
        ProfileRefusals.publish(new ProfileAudit.Result(profile, List.of(violations), List.of()));
    }

    static ProfileAudit.Violation forbidden(String setting, List<String> components) {
        return new ProfileAudit.Violation(ProfileAudit.Kind.FORBIDDEN, setting, setting + "=true, which the production profile"
                + " forbids", "Unset it", components);
    }

    @BeforeEach
    @AfterEach
    void forget() {
        ProfileRefusals.resetForTests();
    }

    private ComponentParts.Part begin(String component, String part) {
        ComponentParts.Part begun = this.parts.begin(component, part);
        Startup.refuseIfRefused(this.parts, begun);
        return begun;
    }

    @Test
    void aRefusedComponentsPartsAreRefusedAndTheirStartNeverRuns() {
        publish(DeploymentProfile.PRODUCTION, forbidden("OIDF_FEDERATION_IGNORE_SSL_ERRORS", List.of("FEDERATION", "AUTO_REGISTRATION")));
        AtomicInteger runs = new AtomicInteger();
        ComponentParts.Part servlet = begin("FEDERATION", "OpenIdFederationServlet");
        ComponentParts.Part registration = begin("FEDERATION", "OpenIdRegistrationServlet");
        assertEquals(ComponentState.REFUSED, servlet.start(runs::incrementAndGet));
        assertEquals(ComponentState.REFUSED, registration.start(runs::incrementAndGet));
        assertEquals(0, runs.get(), "its init configures nothing");
        assertEquals("refused by the production profile: OIDF_FEDERATION_IGNORE_SSL_ERRORS=true, which the production profile"
                + " forbids. Unset it", servlet.status().reason());
        assertTrue(servlet.componentRefused(), "so the gate answers 503 on its surfaces");
        assertEquals(ComponentState.REFUSED, this.registry.status("FEDERATION").orElseThrow().state());
        ComponentParts.Part fapi = begin("FAPI", "Fapi2ProfileFilter");
        assertEquals(ComponentState.READY, fapi.start(runs::incrementAndGet), "another component serves");
        assertEquals(1, runs.get());
    }

    @Test
    void aComponentSwitchedOffStaysDisabledAndAFailedSwitchStaysFailed() {
        publish(DeploymentProfile.PRODUCTION, forbidden("OIDF_X", List.of("FEDERATION", "SSF")));
        this.kinds.put("FEDERATION", ComponentSwitches.Kind.DISABLED);
        this.kinds.put("SSF", ComponentSwitches.Kind.FAILED_CONFIG);
        ComponentParts.Part off = begin("FEDERATION", "OpenIdFederationServlet");
        assertEquals(ComponentState.STARTING, off.status().state(), "disabling a component is never a violation");
        assertEquals(ComponentState.DISABLED, off.start(() -> { }));
        ComponentParts.Part failed = begin("SSF", "SsfConfigurationServlet");
        assertEquals(ComponentState.REFUSED, failed.status().state());
        assertEquals(ComponentState.FAILED_CONFIG, failed.start(() -> { }), "the switch's refusal is its answer");
    }

    @Test
    void aRequiredSettingRefusesOnlyAComponentSwitchedOn() {
        publish(DeploymentProfile.PRODUCTION, new ProfileAudit.Violation(ProfileAudit.Kind.REQUIRED, "OIDF_OPERATOR_AUDIENCE",
                "OIDF_OPERATOR_AUDIENCE is unset", "Set it", List.of("OPERATOR_API")));
        ComponentParts.Part inferred = begin("OPERATOR_API", "FederationAdminServlet");
        assertEquals(ComponentState.DISABLED, inferred.start(() -> inferred.notConfigured("nothing set")),
                "an unconfigured component its start disables stays disabled, and ready stays up");
        this.kinds.put("OPERATOR_API", ComponentSwitches.Kind.ENABLED);
        ComponentParts.Part on = begin("OPERATOR_API", "FederationAdminServlet");
        assertEquals(ComponentState.REFUSED, on.start(() -> { }));
    }

    @Test
    void developmentRefusesNothing() {
        publish(DeploymentProfile.DEVELOPMENT, forbidden("OIDF_X", EVERY));
        ComponentParts.Part part = begin("FEDERATION", "OpenIdFederationServlet");
        assertFalse(Startup.refuseIfRefused(this.parts, part));
        assertEquals(ComponentState.READY, part.start(() -> { }));
    }

    @Test
    void theJvmHostnameFlagRefusesEveryComponent() {
        publish(DeploymentProfile.PRODUCTION, forbidden("jdk.internal.httpclient.disableHostnameVerification", EVERY));
        for (String component : EVERY) {
            ComponentParts.Part part = begin(component, "Part");
            assertEquals(ComponentState.REFUSED, part.start(() -> { }), component);
        }
    }

    @Test
    void aStartThatThrowsTheProfilesRefusalLeavesItsPartRefused() {
        publish(DeploymentProfile.PRODUCTION);
        ComponentParts.Part part = begin("SSF", "SsfConfigurationServlet");
        assertEquals(ComponentState.REFUSED, part.start(() -> ProfileRefusals.refuse("SSF", "the store is in memory")));
        assertTrue(part.status().reason().startsWith("the store is in memory"), part.status().reason());
        ComponentParts.Part later = begin("SSF", "SsfReceiverServlet");
        assertEquals(ComponentState.REFUSED, later.status().state(), "a later part of the component is refused as it registers");
        assertEquals(ComponentState.REFUSED, ComponentParts.stateFor(new IllegalStateException("wrapped",
                new ProfileRefused(forbidden("x", List.of())))));
        assertEquals(ComponentState.FAILED_CONFIG, ComponentParts.stateFor(new IllegalStateException("not the profile's")));
    }

    @Test
    void aRefusedPartThatReportsItsOwnOutcomeCannotReportItselfPastTheRefusal() {
        publish(DeploymentProfile.PRODUCTION, forbidden("OIDF_SSF_X", List.of("SSF")));
        ComponentParts.Part ssf = begin("SSF", "SsfConfigurationServlet");
        assertFalse(ssf.ready(), "the SSF servlets report outside start until ST-5");
        assertFalse(ssf.finish());
        assertFalse(ssf.degraded("slow"));
        assertFalse(ssf.failedDependency("store down"));
        assertFalse(ssf.refused("again"), "the reason it was refused for stands");
        assertEquals(ComponentState.REFUSED, ssf.status().state());
        assertTrue(ssf.failedConfig("its own settings are wrong"), "a failed configuration is worse, and shown");
        ComponentParts.Part again = begin("SSF", "SsfReceiverServlet");
        assertTrue(again.disabled(), "switched off, it is disabled");
    }

    @Test
    void startupsOwnBeginAsksTheProfile() {
        publish(DeploymentProfile.PRODUCTION, forbidden("OIDF_X", List.of("FAPI")));
        ComponentParts.Part part = Startup.begin(Startup.FAPI, "StartupRefusalTestPart");
        ComponentState expected = Startup.parts().verdict(Startup.FAPI).kind() == ComponentSwitches.Kind.DISABLED
                ? ComponentState.STARTING : ComponentState.REFUSED;
        assertEquals(expected, part.status().state());
        part.disabled();
        assertEquals(ComponentState.DISABLED, part.status().state(), "out of this JVM's readiness for the tests after this one");
    }
}
