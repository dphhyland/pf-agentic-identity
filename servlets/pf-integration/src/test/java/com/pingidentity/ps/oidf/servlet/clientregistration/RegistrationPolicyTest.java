package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.FederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.NarrowingObligations;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecision;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionException;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionRequest;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpAuth;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import com.pingidentity.ps.oidf.pf.PfTracking;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** What a registration's policy consult sends, and what each answer - or no answer - does to the registration. */
class RegistrationPolicyTest {
    private static final String AGENT = "https://agent.example.com";
    private static final String OP = "https://op.example.com";
    private static final Map<String, Object> METADATA = Map.of("scope", "read write", "grant_types", List.of("client_credentials"),
            "client_name", "Agent");

    private final List<PolicyDecisionRequest> asked = new ArrayList<>();
    private TrustChainValidationResult validation;
    private EventCapture events;

    @BeforeEach
    void setUp() throws Exception {
        this.events = EventCapture.install();
        List<String> chain = RegistrationFixtures.chain(AGENT, RegistrationFixtures.ANCHOR, Clock.systemUTC());
        this.validation = RegistrationFixtures.result(AGENT, chain, Map.of("oauth_client", METADATA, "federation_entity", Map.of()),
                Set.of("oauth_client"), 1_900_000_000L);
    }

    @AfterEach
    void tearDown() {
        this.events.close();
        ThreadContext.remove(PfTracking.TRACKING_ID_KEY);
    }

    private static PdpSettings settings(boolean failOpen, boolean surfaceUserReason) {
        PdpSettings d = PdpSettings.DEFAULTS;
        return new PdpSettings(d.mode(), null, null, false, PdpAuth.NONE, null, d.authHeader(), failOpen, false, 0L, d.connectTimeoutMs(),
                d.requestTimeoutMs(), surfaceUserReason, null, d.decisionPoints());
    }

    private RegistrationPolicy policy(FederationPolicyDecisionPoint pdp, PdpSettings settings) {
        return new RegistrationPolicy(point -> request -> {
            this.asked.add(request);
            return pdp.decide(request);
        }, settings);
    }

    private NarrowingObligations decide(RegistrationPolicy policy) throws RegistrationRejectedException {
        return policy.decide(DecisionPoint.AUTOMATIC_REGISTRATION, AGENT, OP, "token", "oauth_client", this.validation, METADATA, null);
    }

    @Test
    void whenNobodyDecidesTheRegistrationGoesAheadUnnarrowed() throws Exception {
        NarrowingObligations obligations = this.decide(new RegistrationPolicy(point -> null, settings(false, false)));

        assertSame(NarrowingObligations.NONE, obligations);
        assertEquals(List.of(), this.events.codes(), "no consult, nothing to record");
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §5.5", "AUTHZEN-1.0 §5.5.1"})
    void aPermitReturnsWhatItNarrowsAndIsAudited() throws Exception {
        NarrowingObligations narrow = new NarrowingObligations(Set.of("read"), null, null, 600L, Set.of());
        PolicyDecision permit = new PolicyDecision(true, narrow, "tier 2 agent", null, "req-9", 12L, Set.of("advice"));

        NarrowingObligations obligations = this.decide(this.policy(request -> permit, settings(false, false)));

        assertEquals(narrow, obligations);
        FederationEvent consulted = this.events.only(FederationEvents.PDP_CONSULTED);
        assertFalse(consulted.isFailure());
        assertTrue(consulted.audit());
        assertEquals("federation.register.automatic", consulted.fields().get("action"));
        assertEquals("token", consulted.fields().get("endpoint"));
        assertEquals("permit", consulted.fields().get("decision"));
        assertEquals("12", consulted.fields().get("latency_ms"));
        assertEquals("req-9", consulted.fields().get("pdp_request_id"));
        assertEquals("scope registration_ttl_seconds", consulted.fields().get("obligations"), "their names, never their values");
        assertEquals("advice", consulted.fields().get("ignored_context"));
        assertEquals("tier 2 agent", consulted.description());
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §5.5", "AUTHZEN-1.0 §5.5.1"})
    void aDenialRefusesTheRegistrationAndKeepsTheAdministratorsReasonOutOfTheAnswer() {
        PolicyDecision deny = PolicyDecision.deny("agent on the watch list", "Your agent is not approved here");

        RegistrationRejectedException refused = assertThrows(RegistrationRejectedException.class,
                () -> this.decide(this.policy(request -> deny, settings(false, false))));

        assertEquals(400, refused.status());
        assertEquals("invalid_client_metadata", refused.error());
        assertEquals(RegistrationRejectedException.Kind.POLICY, refused.kind());
        assertEquals("this deployment's policy does not allow " + AGENT + " to be registered", refused.getMessage(),
                "the user's reason is shown only when the deployment says so");
        assertEquals("deny", this.events.only(FederationEvents.PDP_CONSULTED).fields().get("decision"));
        assertFalse(this.events.only(FederationEvents.PDP_CONSULTED).fields().containsKey("obligations"), "nothing to name, no field");
        assertFalse(this.events.only(FederationEvents.PDP_CONSULTED).fields().containsKey("ignored_context"));
        assertEquals("agent on the watch list", this.events.only(FederationEvents.PDP_CONSULTED).description());
        FederationEvent refusal = this.events.only(FederationEvents.REGISTRATION_REFUSED);
        assertEquals("policy_denied", refusal.reason());
        assertTrue(refusal.audit());
    }

    @Test
    @Requirement("AUTHZEN-1.0 §5.5.1")
    void theUsersReasonIsTheAnswerWhenTheDeploymentSurfacesIt() {
        RegistrationRejectedException withReason = assertThrows(RegistrationRejectedException.class, () -> this.decide(this.policy(
                request -> PolicyDecision.deny(null, "Your agent is not approved here"), settings(false, true))));
        RegistrationRejectedException withoutOne = assertThrows(RegistrationRejectedException.class, () -> this.decide(this.policy(
                request -> PolicyDecision.deny(null, null), settings(false, true))));

        assertEquals("Your agent is not approved here", withReason.getMessage());
        assertEquals("this deployment's policy does not allow " + AGENT + " to be registered", withoutOne.getMessage());
    }

    @Test
    @Requirement("AUTHZEN-1.0 §10.1.2")
    void noDecisionIsNeverAPermit() {
        FederationPolicyDecisionPoint unreachable = request -> {
            throw new PolicyDecisionException("the policy decision point answered 500, which is no decision");
        };

        RegistrationRejectedException refused = assertThrows(RegistrationRejectedException.class,
                () -> this.decide(this.policy(unreachable, settings(false, false))));

        assertEquals(503, refused.status());
        assertEquals("temporarily_unavailable", refused.error());
        assertTrue(refused.isRetryable(), "worth trying again, and no evidence against the client");
        assertTrue(refused.getCause() instanceof PolicyDecisionException);
        FederationEvent consulted = this.events.only(FederationEvents.PDP_CONSULTED);
        assertEquals("no_decision", consulted.reason());
        assertTrue(this.events.withCode(FederationEvents.PDP_FAIL_OPEN).isEmpty());
    }

    @Test
    void aDeploymentThatFailsOpenRegistersUnnarrowedAndSaysSo() throws Exception {
        NarrowingObligations obligations = this.decide(this.policy(request -> {
            throw new PolicyDecisionException("timed out");
        }, settings(true, false)));

        assertSame(NarrowingObligations.NONE, obligations);
        FederationEvent failOpen = this.events.only(FederationEvents.PDP_FAIL_OPEN);
        assertTrue(failOpen.isFailure() && failOpen.audit(), "a failed audit event: written at WARN");
        assertEquals("federation.register.automatic", failOpen.fields().get("action"));
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §5.1", "AUTHZEN-1.0 §5.2", "AUTHZEN-1.0 §5.3", "AUTHZEN-1.0 §6.1"})
    void thePdpHearsWhoIsAskingForWhatAndThroughWhichEndpoint() throws Exception {
        ThreadContext.put(PfTracking.TRACKING_ID_KEY, "tid-42");

        this.policy(request -> PolicyDecision.permit(NarrowingObligations.NONE), settings(false, false)).decide(
                DecisionPoint.EXPLICIT_REGISTRATION, AGENT, OP, "registration", "oauth_client", this.validation,
                Map.of("scope", "read", "redirect_uris", List.of(AGENT + "/cb"), "client_name", "Agent"), List.of("https://tm.example/certified"));

        Map<String, Object> body = this.asked.get(0).toAuthZen();
        assertEquals(Map.of("type", "federation_entity", "id", AGENT, "properties", Map.of("entity_types",
                new ArrayList<>(this.validation.resolvedMetadata().keySet()), "trust_anchor", RegistrationFixtures.ANCHOR,
                "trust_marks", List.of("https://tm.example/certified"))), body.get("subject"));
        assertEquals(Map.of("name", "federation.register.explicit", "properties", Map.of("endpoint", "registration", "entity_type",
                "oauth_client")), body.get("action"));
        assertEquals(Map.of("type", "openid_provider", "id", OP), body.get("resource"));
        assertEquals(Map.of("scope", "read", "redirect_uris", List.of(AGENT + "/cb"), "chain_expires_at", 1_900_000_000L,
                "request", Map.of("tracking_id", "tid-42")), body.get("context"), "what it asks for, never its keys or name");
        assertEquals("tid-42", this.asked.get(0).requestId());
    }

    @Test
    void offARequestThreadThereIsNoTrackingIdAndAChainWithoutExpiryHasNoneToSend() throws Exception {
        TrustChainValidationResult noExpiry = RegistrationFixtures.result(AGENT, this.validation.trustChain(), Map.of("oauth_client", METADATA),
                Set.of("oauth_client"), -1L);

        PolicyDecisionRequest request = RegistrationPolicy.request(DecisionPoint.AUTOMATIC_REGISTRATION, AGENT, OP, "token", "oauth_client",
                noExpiry, Map.of(), null);

        assertNull(request.requestId());
        assertEquals(Map.of(), request.context());
        assertFalse(request.subjectProperties().containsKey("trust_marks"), "marks nobody verified are not reported");
    }

    @Test
    void obligationsAreNamedForTheLog() {
        assertEquals(List.of(), RegistrationPolicy.obligationNames(NarrowingObligations.NONE));
        assertEquals(List.of("scope", "grant_types", "response_types", "registration_ttl_seconds", "require_trust_mark"),
                RegistrationPolicy.obligationNames(new NarrowingObligations(Set.of(), Set.of(), Set.of(), 0L, Set.of("m"))));
    }
}
