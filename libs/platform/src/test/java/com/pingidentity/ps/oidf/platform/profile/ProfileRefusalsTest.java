package com.pingidentity.ps.oidf.platform.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import com.pingidentity.ps.oidf.platform.settings.Catalogues;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * What a loader's copy refuses: the published sweep or its own lazy one, required settings only for a component
 * switched on, the refusals made in code, and nothing under development.
 */
class ProfileRefusalsTest {

    static ProfileAudit.Violation violation(ProfileAudit.Kind kind, String setting, String... components) {
        return new ProfileAudit.Violation(kind, setting, setting + " is wrong", "Fix it", List.of(components));
    }

    static ProfileAudit.Result production(ProfileAudit.Violation... violations) {
        return new ProfileAudit.Result(DeploymentProfile.PRODUCTION, List.of(violations), List.of());
    }

    @BeforeEach
    @AfterEach
    void forget() {
        ProfileRefusals.resetForTests();
    }

    @Test
    void aCopyNothingPublishedToEvaluatesOnceOnFirstUse() {
        AtomicInteger evaluations = new AtomicInteger();
        ProfileAudit.Result lazy = production(violation(ProfileAudit.Kind.FORBIDDEN, "OIDF_X", "FAPI"));
        ProfileRefusals.reset(() -> {
            evaluations.incrementAndGet();
            return lazy;
        });
        assertSame(lazy, ProfileRefusals.current());
        assertSame(lazy, ProfileRefusals.current());
        assertEquals(1, evaluations.get());
        assertTrue(ProfileRefusals.refused("FAPI", false));
        ProfileAudit.Result published = ProfileAudit.Result.empty(DeploymentProfile.PRODUCTION);
        ProfileRefusals.publish(published);
        assertSame(published, ProfileRefusals.current(), "a publish replaces it");
        assertFalse(ProfileRefusals.refused("FAPI", false));
    }

    @Test
    void theLazyEvaluationIsTheSweepTheListenerRunsOverThisProcess() {
        ClassLoader loader = ProfileRefusals.class.getClassLoader();
        ProfileAudit.Result listeners = ProfileAudit.evaluate(Sources.process(), Catalogues.onClassPath(loader),
                DeploymentProfile.current(), AcceptedRisks.current());
        ProfileAudit.Result engines = ProfileRefusals.current();
        assertEquals(listeners.profile(), engines.profile());
        assertEquals(listeners.violations(), engines.violations(), "the engine copy's answer is the webapp copy's");
        assertEquals(listeners.warnings(), engines.warnings());
    }

    @Test
    void aComponentIsRefusedForEachViolationNamingItAndTheReasonCountsThem() {
        ProfileRefusals.publish(production(violation(ProfileAudit.Kind.FORBIDDEN, "OIDF_A", "FEDERATION", "HOSTING"),
                violation(ProfileAudit.Kind.UNKNOWN_KEY, "OIDF_B", "FEDERATION")));
        assertEquals("refused by the production profile: OIDF_A is wrong. Fix it (and 1 more, listed in server.log and the start-up"
                + " audit)", ProfileRefusals.reason("FEDERATION", false));
        assertEquals("refused by the production profile: OIDF_A is wrong. Fix it", ProfileRefusals.reason("HOSTING", false));
        assertNull(ProfileRefusals.reason("SSF", true));
    }

    @Test
    void aRequiredSettingUnsetRefusesOnlyAComponentSwitchedOn() {
        ProfileRefusals.publish(production(violation(ProfileAudit.Kind.REQUIRED, "OIDF_OPERATOR_AUDIENCE", "OPERATOR_API")));
        assertNull(ProfileRefusals.reason("OPERATOR_API", false), "inferred: its start disables it, unconfigured");
        assertTrue(ProfileRefusals.reason("OPERATOR_API", true).contains("OIDF_OPERATOR_AUDIENCE"));
        ProfileAudit.Violation required = violation(ProfileAudit.Kind.REQUIRED, "OIDF_R", "OPERATOR_API", "SSF");
        assertTrue(ProfileRefusals.refuses(required, "SSF"::equals), "one of its components switched on");
        assertFalse(ProfileRefusals.refuses(required, c -> false));
        assertTrue(ProfileRefusals.refuses(violation(ProfileAudit.Kind.FORBIDDEN, "OIDF_F", "SSF"), c -> false));
    }

    @Test
    void developmentRefusesNothing() {
        ProfileRefusals.publish(new ProfileAudit.Result(DeploymentProfile.DEVELOPMENT,
                List.of(violation(ProfileAudit.Kind.FORBIDDEN, "OIDF_A", "FEDERATION")), List.of()));
        assertNull(ProfileRefusals.reason("FEDERATION", true));
        ProfileRefusals.refuse("SSF", "the SSF store is in memory");
        ProfileRefusals.refuse("SSF", "the SSF store is in memory");
        assertEquals(List.of(), ProfileRefusals.codeRefusals(), "under development a refusal in code only warns");
        ProfileRefusals.requireRisk("SSF", AcceptedRisk.IN_MEMORY_STATE, "the SSF store is in memory");
    }

    @Test
    void aRefusalInCodeRefusesItsComponentThrowsAndIsListedOnce() {
        ProfileRefusals.publish(production());
        ProfileRefused thrown = assertThrows(ProfileRefused.class, () -> ProfileRefusals.refuse("SSF", "the store is in memory"));
        assertEquals(ProfileAudit.Kind.CODE, thrown.violation().kind());
        assertEquals("the store is in memory. The start-up audit lists it", thrown.getMessage());
        assertThrows(ProfileRefused.class, () -> ProfileRefusals.refuse("SSF", "the store is in memory"));
        assertEquals(1, ProfileRefusals.codeRefusals().size(), "the same refusal twice is one");
        assertEquals("refused by the production profile: the store is in memory. The start-up audit lists it",
                ProfileRefusals.reason("SSF", false));
        assertNull(ProfileRefusals.reason("FAPI", false));
        assertThrows(NullPointerException.class, () -> ProfileRefusals.refuse(null, "x"));
        assertThrows(NullPointerException.class, () -> ProfileRefusals.refuse("SSF", null));
    }

    @Test
    void aStoreInMemoryNeedsTheInMemoryStateRiskInProduction() {
        ProfileRefusals.publish(production());
        LocalDate today = LocalDate.of(2026, 9, 30);
        ProfileRefusals.requireRisk("SSF", AcceptedRisk.IN_MEMORY_STATE, "the stream store is in memory",
                AcceptedRisks.parse("in-memory-state", today));
        assertEquals(List.of(), ProfileRefusals.codeRefusals());
        ProfileRefused refused = assertThrows(ProfileRefused.class, () -> ProfileRefusals.requireRisk("SSF",
                AcceptedRisk.IN_MEMORY_STATE, "the stream store is in memory", AcceptedRisks.none()));
        assertEquals("the stream store is in memory, which the production profile allows only with the risk 'in-memory-state'"
                + " accepted (a store keeps its state in this node's memory, lost on restart and invisible to any other node): add"
                + " in-memory-state to OIDF_ACCEPTED_RISKS", refused.violation().reason());
        assertThrows(ProfileRefused.class, () -> ProfileRefusals.requireRisk("HOSTING", AcceptedRisk.EXPIRY_LOG_MODE, "dated",
                AcceptedRisks.none()), "a dated risk asks for its date");
        assertTrue(ProfileRefusals.codeRefusals().get(1).reason().endsWith("add expiry-log-mode@YYYY-MM-DD to OIDF_ACCEPTED_RISKS"));
        assertThrows(ProfileRefused.class, () -> ProfileRefusals.requireRisk("SSF", AcceptedRisk.IN_MEMORY_STATE, "x"),
                "this process accepts no risk");
        assertThrows(NullPointerException.class, () -> ProfileRefusals.requireRisk("SSF", null, "x", AcceptedRisks.none()));
    }
}
