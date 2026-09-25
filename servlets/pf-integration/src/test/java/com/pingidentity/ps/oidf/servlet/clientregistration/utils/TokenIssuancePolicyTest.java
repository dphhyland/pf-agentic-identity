package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * The token-issuance decision point: what the PDP hears about a token PingFederate is about to issue, and why a criterion
 * that can only say yes or no turns a permit's obligations into checks.
 */
class TokenIssuancePolicyTest {
    private static final String CLIENT = "https://agent.example.com";
    private static final String OP = "https://op.example.com";

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

    private static PdpSettings settings(boolean failOpen) {
        PdpSettings d = PdpSettings.DEFAULTS;
        return new PdpSettings(d.mode(), null, null, false, PdpAuth.NONE, null, d.authHeader(), failOpen, false, 0L, d.connectTimeoutMs(),
                d.requestTimeoutMs(), false, null, d.decisionPoints());
    }

    private static Map<String, Object> criteria(Map<String, Object> extra) {
        Map<String, Object> criteria = new HashMap<>();
        criteria.put(TokenIssuancePolicy.SCOPES, new AttributeValue(List.of("read", "write")));
        criteria.putAll(extra);
        return criteria;
    }

    private static HttpServletRequest request(String grantType) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("grant_type")).thenReturn(grantType);
        return request;
    }

    private boolean permits(Map<String, Object> criteria, String grantType, FederationPolicyDecisionPoint pdp, boolean failOpen) {
        return TokenIssuancePolicy.permits(criteria, CLIENT, OP, request(grantType), request -> {
            this.asked.add(request);
            return pdp.decide(request);
        }, settings(failOpen));
    }

    private boolean permits(FederationPolicyDecisionPoint pdp) {
        return this.permits(criteria(Map.of()), "client_credentials", pdp, false);
    }

    private static FederationPolicyDecisionPoint permitting(NarrowingObligations obligations) {
        return request -> PolicyDecision.permit(obligations);
    }

    @Test
    void whenNobodyDecidesTokensTheCriterionSaysYes() {
        assertTrue(TokenIssuancePolicy.permits(criteria(Map.of()), CLIENT, OP, request("client_credentials"), null, settings(false)));
        assertEquals(List.of(), this.events.codes());
    }

    @Test
    @Requirement("AUTHZEN-1.0 §5.5")
    void aPermitWhoseObligationsTheTokenMeetsIssuesIt() {
        assertTrue(this.permits(permitting(NarrowingObligations.NONE)));
        assertTrue(this.permits(permitting(new NarrowingObligations(Set.of("read", "write", "admin"), Set.of("client_credentials"), Set.of("code"),
                60L, Set.of()))), "response types and a registration's life say nothing about a token");

        FederationEvent consulted = this.events.withCode(FederationEvents.PDP_CONSULTED).get(0);
        assertEquals("federation.token.issue", consulted.fields().get("action"));
        assertEquals("permit", consulted.fields().get("decision"));
        assertTrue(consulted.audit());
        assertFalse(consulted.fields().containsKey("ignored_context"));
        assertTrue(this.events.withCode(FederationEvents.TOKEN_REFUSED).isEmpty());
    }

    @Test
    @Requirement("AUTHZEN-1.0 §5.5.1")
    void aCriterionCannotNarrowATokenSoAnObligationItDoesNotMeetRefusesIt() {
        assertFalse(this.permits(permitting(new NarrowingObligations(Set.of("read"), null, null, null, Set.of()))), "write was not permitted");
        assertFalse(this.permits(permitting(new NarrowingObligations(null, Set.of("authorization_code"), null, null, Set.of()))));
        assertFalse(this.permits(permitting(new NarrowingObligations(null, null, null, null, Set.of("https://ta.example/marks/x")))),
                "a mark cannot be verified at issuance");

        List<FederationEvent> refused = this.events.withCode(FederationEvents.TOKEN_REFUSED);
        assertEquals(List.of("scope", "grant_types", "require_trust_mark"), refused.stream().map(e -> e.fields().get("obligation")).toList());
        assertEquals("obligation_unmet", refused.get(0).reason());
        assertTrue(refused.get(0).audit());
    }

    @Test
    void contextThePdpSentThatThisDeploymentIgnoredIsRecorded() {
        assertTrue(this.permits(request -> new PolicyDecision(true, NarrowingObligations.NONE, null, null, "r-1", 4L, Set.of("advice"))));

        assertEquals("advice", this.events.only(FederationEvents.PDP_CONSULTED).fields().get("ignored_context"));
        assertEquals("r-1", this.events.only(FederationEvents.PDP_CONSULTED).fields().get("pdp_request_id"));
    }

    @Test
    void aGrantTypeObligationRefusesARequestThatNamesNoGrantType() {
        assertFalse(this.permits(criteria(Map.of()), null, permitting(new NarrowingObligations(null, Set.of("client_credentials"), null, null,
                Set.of())), false));
        assertTrue(this.permits(criteria(Map.of()), null, permitting(NarrowingObligations.NONE), false), "no obligation, nothing to check");
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §5.5", "AUTHZEN-1.0 §5.5.1"})
    void aDenialRefusesTheToken() {
        assertFalse(this.permits(request -> PolicyDecision.deny("agent suspended pending review", null)));

        assertEquals("deny", this.events.only(FederationEvents.PDP_CONSULTED).fields().get("decision"));
        assertEquals("agent suspended pending review", this.events.only(FederationEvents.PDP_CONSULTED).description());
        assertEquals("policy_denied", this.events.only(FederationEvents.TOKEN_REFUSED).reason());
    }

    @Test
    @Requirement("AUTHZEN-1.0 §10.1.2")
    void noDecisionRefusesTheTokenUnlessTheDeploymentFailsOpen() {
        FederationPolicyDecisionPoint down = request -> {
            throw new PolicyDecisionException("the policy decision point answered 502, which is no decision");
        };

        assertFalse(this.permits(criteria(Map.of()), "client_credentials", down, false));
        assertEquals("no_decision", this.events.only(FederationEvents.TOKEN_REFUSED).reason());

        assertTrue(this.permits(criteria(Map.of()), "client_credentials", down, true));
        assertEquals(1, this.events.withCode(FederationEvents.PDP_FAIL_OPEN).size());
        assertEquals(1, this.events.withCode(FederationEvents.TOKEN_REFUSED).size(), "failing open refuses nothing");
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §5.1", "AUTHZEN-1.0 §5.2", "AUTHZEN-1.0 §5.3", "AUTHZEN-1.0 §10.1.3"})
    void thePdpHearsTheClientTheGrantAndWhatTheTokenWouldCarry() {
        ThreadContext.put(PfTracking.TRACKING_ID_KEY, "tid-9");
        AttributeValue authn = new AttributeValue("PRIVATE_KEY_JWT");
        Map<String, Object> criteria = criteria(Map.of(
                TokenIssuancePolicy.RESOURCES, new AttributeValue(List.of("https://api.example.com")),
                TokenIssuancePolicy.CLIENT_IP, new AttributeValue("203.0.113.7"),
                TokenIssuancePolicy.CLIENT_AUTHN_TYPE, authn,
                TokenIssuancePolicy.TRUST_ANCHOR, new AttributeValue("https://ta.example.com"),
                TokenIssuancePolicy.ENTITY_TYPE, new AttributeValue("oauth_client")));

        this.permits(criteria, "client_credentials", permitting(NarrowingObligations.NONE), false);

        Map<String, Object> body = this.asked.get(0).toAuthZen();
        assertEquals(Map.of("type", "federation_entity", "id", CLIENT, "properties", Map.of("trust_anchor", "https://ta.example.com",
                "entity_type", "oauth_client")), body.get("subject"));
        assertEquals(Map.of("name", "federation.token.issue", "properties", Map.of("grant_type", "client_credentials",
                "client_authn_type", "PRIVATE_KEY_JWT")), body.get("action"));
        assertEquals(Map.of("type", "openid_provider", "id", OP), body.get("resource"));
        assertEquals(Map.of("scope", List.of("read", "write"), "resources", List.of("https://api.example.com"), "client_ip", "203.0.113.7",
                "request", Map.of("tracking_id", "tid-9")), body.get("context"));
        assertEquals("tid-9", this.asked.get(0).requestId());
        assertEquals(DecisionPoint.TOKEN_ISSUANCE, this.asked.get(0).point());
    }

    @Test
    void whatThePdpIsNotToldItIsNotTold() {
        Map<String, Object> criteria = new HashMap<>();
        criteria.put(TokenIssuancePolicy.TRUST_ANCHOR, new AttributeValue("null"));
        criteria.put(TokenIssuancePolicy.ENTITY_TYPE, new AttributeValue(" "));

        PolicyDecisionRequest request = TokenIssuancePolicy.request(criteria, CLIENT, OP, List.of(), null);

        assertEquals(Map.of(), request.subjectProperties(), "PF maps an extended property a client lacks as blank or \"null\"");
        assertEquals(Map.of(), request.actionProperties());
        assertEquals(Map.of("scope", List.of()), request.context());
        assertNull(request.requestId());
    }

    @Test
    void scopesReadTheSameAsOneValueOrMany() {
        assertEquals(List.of("read", "write"), TokenIssuancePolicy.values(Map.of("k", new AttributeValue("read  write")), "k"));
        assertEquals(List.of("read", "write"), TokenIssuancePolicy.values(Map.of("k", new AttributeValue(List.of("read", "write"))), "k"));
        assertEquals(List.of(), TokenIssuancePolicy.values(Map.of("k", "read"), "k"), "not an attribute, nothing read");
        assertEquals(List.of(), TokenIssuancePolicy.values(Map.of(), "k"));
        assertEquals(List.of(), TokenIssuancePolicy.values(Map.of("k", new AttributeValue((String) null)), "k"));
        assertEquals(List.of(), TokenIssuancePolicy.values(Map.of("k", new AttributeValue("")), "k"));
        assertNull(TokenIssuancePolicy.value(Map.of("k", "text"), "k"));
        assertNull(TokenIssuancePolicy.value(Map.of("k", new AttributeValue((String) null)), "k"));
    }
}
