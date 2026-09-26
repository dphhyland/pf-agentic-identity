package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.policy.AuthZenFederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.CachingPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.CompositePolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.FederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.LocalFederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecision;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionRequest;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.pf.FederationPolicySupport.Policies;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpAuth;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpMode;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import java.time.Clock;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Which decision point decides what, how the PDP is reached, and that the holder builds once from configuration. */
class FederationPolicySupportTest {
    private static final String PDP = "https://pdp.example.com";
    private static final PolicyDecisionRequest REQUEST = new PolicyDecisionRequest(DecisionPoint.AUTOMATIC_REGISTRATION,
            "https://agent.example.com", Map.of(), "openid_provider", "https://op.example.com", Map.of(), Map.of(), null);

    private final List<String> posted = new ArrayList<>();
    private final List<Map<String, String>> headers = new ArrayList<>();
    private final List<String> fetched = new ArrayList<>();
    private final HttpPostClient post = (url, contentType, body, sent, accept) -> {
        this.posted.add(url);
        this.headers.add(sent);
        return new HttpPostClient.Response(200, "{\"decision\":true}", Map.of());
    };
    private final HttpGetClient get = (url, accept) -> {
        this.fetched.add(url);
        return "{\"policy_decision_point\":\"" + PDP + "\",\"access_evaluation_endpoint\":\"" + PDP + "/discovered\"}";
    };

    @AfterEach
    void tearDown() {
        FederationPolicySupport.resetForTests();
        FederationRuntimeConfig.resetForTests();
    }

    private static PdpSettings settings(PdpMode mode, String url, String evaluationUrl, boolean discover, PdpAuth auth, long cacheTtl,
                                        Set<DecisionPoint> points) {
        return settings(mode, url, evaluationUrl, discover, auth, cacheTtl, points, null);
    }

    private static PdpSettings settings(PdpMode mode, String url, String evaluationUrl, boolean discover, PdpAuth auth, long cacheTtl,
                                        Set<DecisionPoint> points, Set<String> allowedScopes) {
        PdpSettings d = PdpSettings.DEFAULTS;
        return new PdpSettings(mode, url, evaluationUrl, discover, auth, auth == PdpAuth.NONE ? null : "t0ken", "X-Pdp-Secret", false, false,
                cacheTtl, d.connectTimeoutMs(), d.requestTimeoutMs(), false, allowedScopes, points);
    }

    private static PdpSettings authzen(Set<DecisionPoint> points) {
        return settings(PdpMode.AUTHZEN, PDP, null, false, PdpAuth.NONE, 0L, points);
    }

    private static PdpSettings local(Set<String> allowedScopes) {
        return settings(PdpMode.LOCAL, null, null, false, PdpAuth.NONE, 0L, PdpSettings.DEFAULTS.decisionPoints(), allowedScopes);
    }

    private Policies build(PdpSettings settings) {
        return FederationPolicySupport.build(settings, this.post, this.get, Clock.systemUTC());
    }

    @Test
    void offMeansNobodyDecides() {
        Policies policies = this.build(settings(PdpMode.OFF, null, null, false, PdpAuth.NONE, 0L, EnumSet.allOf(DecisionPoint.class)));

        for (DecisionPoint point : DecisionPoint.values()) {
            assertNull(policies.forPoint(point), point.name());
        }
    }

    @Test
    void theLocalPolicyDecidesRegistrationsAndNothingElse() {
        Policies policies = this.build(local(Set.of("openid")));

        assertInstanceOf(LocalFederationPolicyDecisionPoint.class, policies.forPoint(DecisionPoint.AUTOMATIC_REGISTRATION));
        assertSame(policies.local(), policies.forPoint(DecisionPoint.EXPLICIT_REGISTRATION));
        assertNull(policies.forPoint(DecisionPoint.HOSTED_ENTITY_ENROL), "an enrolment asks for nothing the local policy narrows");
        assertNull(policies.external());
    }

    @Test
    void aLocalPolicyWithNoAllowListIsNotAsked() {
        Policies policies = this.build(PdpSettings.DEFAULTS);

        assertNull(policies.forPoint(DecisionPoint.AUTOMATIC_REGISTRATION), "it would narrow nothing, and leave an audit line saying so");
        assertNull(policies.local());
    }

    @Test
    void thePdpIsAskedOnlyForTheDecisionsListedAndAfterTheLocalPolicy() {
        Policies registrationOnly = this.build(settings(PdpMode.AUTHZEN, PDP, null, false, PdpAuth.NONE, 0L,
                Set.of(DecisionPoint.AUTOMATIC_REGISTRATION), Set.of("openid")));
        Policies enrolmentToo = this.build(authzen(Set.of(DecisionPoint.AUTOMATIC_REGISTRATION, DecisionPoint.HOSTED_ENTITY_ENROL)));

        assertInstanceOf(CompositePolicyDecisionPoint.class, registrationOnly.forPoint(DecisionPoint.AUTOMATIC_REGISTRATION));
        assertSame(registrationOnly.local(), registrationOnly.forPoint(DecisionPoint.EXPLICIT_REGISTRATION), "not listed: local only");
        assertNull(registrationOnly.forPoint(DecisionPoint.HOSTED_ENTITY_ENROL));
        assertSame(enrolmentToo.external(), enrolmentToo.forPoint(DecisionPoint.HOSTED_ENTITY_ENROL));
        assertSame(enrolmentToo.external(), enrolmentToo.forPoint(DecisionPoint.AUTOMATIC_REGISTRATION), "no allow-list: the PDP alone");
        assertInstanceOf(AuthZenFederationPolicyDecisionPoint.class, enrolmentToo.external(), "no cache unless one is configured");
    }

    @Test
    void decisionsAreKeptOnlyWhenACacheTimeIsSet() {
        Policies cached = this.build(settings(PdpMode.AUTHZEN, PDP, null, false, PdpAuth.NONE, 30L, EnumSet.allOf(DecisionPoint.class)));

        assertInstanceOf(CachingPolicyDecisionPoint.class, cached.external());
    }

    @Test
    @Requirement("AUTHZEN-1.0 §10.1")
    void thePdpIsAskedAtItsDefaultPathUnlessTheEvaluationEndpointIsConfigured() throws Exception {
        this.build(authzen(EnumSet.allOf(DecisionPoint.class))).external().decide(REQUEST);
        this.build(settings(PdpMode.AUTHZEN, PDP, PDP + "/eval", false, PdpAuth.NONE, 0L, EnumSet.allOf(DecisionPoint.class))).external()
                .decide(REQUEST);
        this.build(settings(PdpMode.AUTHZEN, null, PDP + "/only", false, PdpAuth.NONE, 0L, EnumSet.allOf(DecisionPoint.class))).external()
                .decide(REQUEST);

        assertEquals(List.of(PDP + "/access/v1/evaluation", PDP + "/eval", PDP + "/only"), this.posted);
        assertEquals(List.of(), this.fetched);
    }

    @Test
    @Requirement("AUTHZEN-1.0 §9.2")
    void aDiscoveringDeploymentReadsTheEndpointFromThePdpsMetadata() throws Exception {
        FederationPolicyDecisionPoint pdp = this.build(settings(PdpMode.AUTHZEN, PDP, null, true, PdpAuth.NONE, 0L,
                EnumSet.allOf(DecisionPoint.class))).external();

        PolicyDecision decision = pdp.decide(REQUEST);

        assertTrue(decision.permitted());
        assertEquals(List.of(PDP + "/.well-known/authzen-configuration"), this.fetched);
        assertEquals(List.of(PDP + "/discovered"), this.posted);
    }

    @Test
    @Requirement("AUTHZEN-1.0 §11.2")
    void theDeploymentAuthenticatesWithABearerTokenOrASharedSecret() throws Exception {
        this.build(settings(PdpMode.AUTHZEN, PDP, null, false, PdpAuth.BEARER, 0L, EnumSet.allOf(DecisionPoint.class))).external().decide(REQUEST);
        this.build(settings(PdpMode.AUTHZEN, PDP, null, false, PdpAuth.HEADER, 0L, EnumSet.allOf(DecisionPoint.class))).external().decide(REQUEST);
        this.build(authzen(EnumSet.allOf(DecisionPoint.class))).external().decide(REQUEST);

        assertEquals(List.of(Map.of("Authorization", "Bearer t0ken"), Map.of("X-Pdp-Secret", "t0ken"), Map.of()), this.headers);
    }

    @Test
    void theUrlsAnOperatorConfiguredAreLetThroughIncludingTheMetadataAtTheHostsRoot() {
        assertArrayEquals(new String[0], FederationPolicySupport.trustedUrls(PdpSettings.DEFAULTS));
        assertArrayEquals(new String[] {PDP + "/eval"},
                FederationPolicySupport.trustedUrls(settings(PdpMode.AUTHZEN, null, PDP + "/eval", false, PdpAuth.NONE, 0L, Set.of())));
        assertArrayEquals(new String[] {PDP + "/tenant1", PDP + "/.well-known/authzen-configuration"},
                FederationPolicySupport.trustedUrls(settings(PdpMode.AUTHZEN, PDP + "/tenant1", null, true, PdpAuth.NONE, 0L, Set.of())));
        assertArrayEquals(new String[] {PDP, PDP + "/.well-known/authzen-configuration", "https://eval.example.com/e"},
                FederationPolicySupport.trustedUrls(settings(PdpMode.AUTHZEN, PDP, "https://eval.example.com/e", false, PdpAuth.NONE, 0L,
                        Set.of())));
    }

    @Test
    void theHolderBuildsOnceFromTheDeploymentsConfiguration() {
        FederationRuntimeConfig.install(FederationRuntimeConfig.from(Map.of(FederationRuntimeConfig.PDP_MODE_ENV, "off")::get, name -> null));

        assertNull(FederationPolicySupport.decisionPointFor(DecisionPoint.AUTOMATIC_REGISTRATION));
        FederationRuntimeConfig.install(FederationRuntimeConfig.from(Map.<String, String>of()::get, name -> null));
        assertEquals(PdpMode.OFF, FederationPolicySupport.settings().mode(), "built once: a later configuration is not picked up");

        FederationPolicySupport.resetForTests();
        assertEquals(PdpMode.LOCAL, FederationPolicySupport.settings().mode());
        FederationPolicySupport.configure(authzen(Set.of(DecisionPoint.EXPLICIT_REGISTRATION)), this.post, this.get, Clock.systemUTC());
        assertInstanceOf(AuthZenFederationPolicyDecisionPoint.class, FederationPolicySupport.decisionPointFor(DecisionPoint.EXPLICIT_REGISTRATION));
    }
}
