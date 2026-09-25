package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.authority.HostedEntity;
import com.pingidentity.ps.oidf.conformance.Requirement;
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
import com.pingidentity.ps.oidf.servlet.trustanchor.HostedEntityServlet.Refusal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** An enrolment's policy consult: what the PDP hears, and what a permit, a denial or no decision does. */
class HostedEntityEnrolPolicyTest {
    private static final String AUTHORITY = "https://pf.example";
    private static final HostedEntity ENTITY = HostedEntity.hosted(AUTHORITY + "/federation/agents/a1", "k1",
            Map.of("oauth_client", Map.of("client_name", "Agent")), null);
    private static final String ACTOR = "admin:0123abcd (dave)";

    private final List<PolicyDecisionRequest> asked = new ArrayList<>();
    private EventCapture events;

    @BeforeEach
    void setUp() {
        this.events = EventCapture.install();
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

    private Refusal ask(FederationPolicyDecisionPoint pdp, PdpSettings settings) {
        return HostedEntityServlet.askPolicy(request -> {
            this.asked.add(request);
            return pdp.decide(request);
        }, settings, ENTITY, AUTHORITY, ACTOR);
    }

    @Test
    void whenNobodyDecidesTheEnrolmentGoesAhead() {
        assertNull(HostedEntityServlet.askPolicy(null, settings(false, false), ENTITY, AUTHORITY, ACTOR));
        assertEquals(List.of(), this.events.codes());
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §5.1", "AUTHZEN-1.0 §5.2", "AUTHZEN-1.0 §5.3", "AUTHZEN-1.0 §10.1.3"})
    void aPermitLetsItThroughAndThePdpHeardWhoIsEnrollingWhat() {
        ThreadContext.put(PfTracking.TRACKING_ID_KEY, "tid-7");

        assertNull(this.ask(request -> PolicyDecision.permit(NarrowingObligations.NONE), settings(false, false)));

        Map<String, Object> body = this.asked.get(0).toAuthZen();
        assertEquals(Map.of("type", "federation_entity", "id", ENTITY.entityId(), "properties", Map.of("entity_types", List.of("oauth_client"),
                "listable", false)), body.get("subject"));
        assertEquals(Map.of("name", "federation.hosted_entity.enrol"), body.get("action"));
        assertEquals(Map.of("type", "federation_authority", "id", AUTHORITY), body.get("resource"));
        assertEquals(Map.of("metadata", ENTITY.metadata(), "actor", ACTOR, "request", Map.of("tracking_id", "tid-7")), body.get("context"));
        assertEquals("tid-7", this.asked.get(0).requestId());
        assertEquals("permit", this.events.only(FederationEvents.PDP_CONSULTED).fields().get("decision"));
        assertTrue(!this.events.only(FederationEvents.PDP_CONSULTED).fields().containsKey("ignored_context"));
    }

    @Test
    void contextThePdpSentThatThisDeploymentIgnoredIsRecorded() {
        this.ask(request -> new PolicyDecision(true, NarrowingObligations.NONE, null, null, null, 3L, Set.of("advice")), settings(false, false));

        assertEquals("advice", this.events.only(FederationEvents.PDP_CONSULTED).fields().get("ignored_context"));
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §5.5", "AUTHZEN-1.0 §5.5.1"})
    void aDenialIsForbiddenWithTheUsersReasonOnlyWhenTheDeploymentSurfacesIt() {
        FederationPolicyDecisionPoint deny = request -> PolicyDecision.deny("quota reached", "Enrolment is closed");

        Refusal hidden = this.ask(deny, settings(false, false));
        Refusal surfaced = this.ask(deny, settings(false, true));
        Refusal noReason = this.ask(request -> PolicyDecision.deny(null, null), settings(false, true));

        assertEquals(new Refusal(403, "access_denied", "this deployment's policy does not allow " + ENTITY.entityId() + " to be enrolled"), hidden);
        assertEquals("Enrolment is closed", surfaced.description());
        assertEquals(hidden, noReason);
        FederationEvent refused = this.events.withCode(FederationEvents.HOSTED_ENTITY_REFUSED).get(0);
        assertEquals("policy_denied", refused.reason());
        assertEquals(ACTOR, refused.fields().get("actor"));
        assertEquals("quota reached", this.events.withCode(FederationEvents.PDP_CONSULTED).get(0).description());
    }

    @Test
    @Requirement("AUTHZEN-1.0 §10.1.2")
    void noDecisionIsNeverAPermitUnlessTheDeploymentFailsOpen() {
        FederationPolicyDecisionPoint down = request -> {
            throw new PolicyDecisionException("the policy decision point could not be reached");
        };

        assertEquals(503, this.ask(down, settings(false, false)).status());
        assertTrue(this.events.withCode(FederationEvents.PDP_FAIL_OPEN).isEmpty());
        assertEquals("no_decision", this.events.withCode(FederationEvents.PDP_CONSULTED).get(0).reason());

        assertNull(this.ask(down, settings(true, false)));
        assertEquals(1, this.events.withCode(FederationEvents.PDP_FAIL_OPEN).size());
    }

    @Test
    void offARequestThreadThereIsNoTrackingIdToSend() {
        this.ask(request -> PolicyDecision.permit(NarrowingObligations.NONE), settings(false, false));

        assertNull(this.asked.get(0).requestId());
        assertEquals(Set.of("metadata", "actor"), this.asked.get(0).context().keySet());
    }
}
