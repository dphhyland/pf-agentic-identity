package com.pingidentity.ps.oidf.federation.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

/**
 * Asking an AuthZEN 1.0 policy decision point: what is sent, what counts as a decision, and what a permit may narrow.
 * An HTTP error is never read as a decision, either way.
 */
class AuthZenFederationPolicyDecisionPointTest {
    private static final String PDP = "https://pdp.example.com";
    private final MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));
    private final List<Map<String, Object>> sent = new ArrayList<>();
    private final List<Map<String, String>> headersSent = new ArrayList<>();

    private static PolicyDecisionRequest request() {
        return new PolicyDecisionRequest(DecisionPoint.AUTOMATIC_REGISTRATION, "https://rp.example", Map.of(), "openid_provider",
                "https://pf.example", Map.of("endpoint", "token"), Map.of("trust_anchor", "https://ta.example"), "track-1");
    }

    private AuthZenFederationPolicyDecisionPoint pdp(int status, String body, Map<String, List<String>> headers, boolean rejectUnknown) {
        HttpPostClient http = (url, contentType, requestBody, requestHeaders, accept) -> {
            assertEquals(PDP + "/access/v1/evaluation", url);
            assertEquals("application/json", contentType);
            assertEquals("application/json", accept);
            this.sent.add(JsonUtil.parseJson(requestBody));
            this.headersSent.add(requestHeaders);
            return new HttpPostClient.Response(status, body, headers);
        };
        return new AuthZenFederationPolicyDecisionPoint(http, AuthZenFederationPolicyDecisionPoint.at(PDP + "/"),
                Map.of("Authorization", "Bearer pep-token"), rejectUnknown, this.clock);
    }

    private AuthZenFederationPolicyDecisionPoint pdp(String body) {
        return this.pdp(200, body, Map.of("X-Request-ID", List.of("track-1")), false);
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §6.1", "AUTHZEN-1.0 §10.1", "AUTHZEN-1.0 §10.1.3"})
    void theRequestIsPostedAsJsonWithItsIdAndTheDeploymentsCredential() throws Exception {
        this.pdp("{\"decision\": true}").decide(request());

        assertEquals(request().toAuthZen(), this.sent.get(0));
        assertEquals("track-1", this.headersSent.get(0).get("X-Request-ID"));
        assertEquals("Bearer pep-token", this.headersSent.get(0).get("Authorization"));
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §5.5", "AUTHZEN-1.0 §5.5.1"})
    void aPermitCarriesWhatItNarrows() throws Exception {
        PolicyDecision decision = this.pdp("{\"decision\": true, \"context\": {\"scope\": \"openid  read\", \"grant_types\": [\"authorization_code\"],"
                + " \"response_types\": [\"code\"], \"registration_ttl_seconds\": 600, \"require_trust_mark\": \"https://ta.example/marks/audited\"}}")
                .decide(request());

        assertTrue(decision.permitted());
        assertEquals(Set.of("openid", "read"), decision.obligations().scopes());
        assertEquals(Set.of("authorization_code"), decision.obligations().grantTypes());
        assertEquals(Set.of("code"), decision.obligations().responseTypes());
        assertEquals(600L, decision.obligations().maxTtlSeconds());
        assertEquals(Set.of("https://ta.example/marks/audited"), decision.obligations().requiredTrustMarks());
        assertEquals("track-1", decision.pdpRequestId());

        PolicyDecision arrays = this.pdp("{\"decision\": true, \"context\": {\"scope\": [\"read\"], \"require_trust_mark\": [\"https://m/one\"]}}")
                .decide(request());
        assertEquals(Set.of("read"), arrays.obligations().scopes());
        assertEquals(Set.of("https://m/one"), arrays.obligations().requiredTrustMarks());
        assertEquals(Set.of(), this.pdp("{\"decision\": true, \"context\": {\"scope\": \" \"}}").decide(request()).obligations().scopes(),
                "an empty scope string allows no scope");
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §5.5", "AUTHZEN-1.0 §5.5.1"})
    void aDenialIsFinalAndItsReasonsAreKept() throws Exception {
        PolicyDecision decision = this.pdp("{\"decision\": false, \"context\": {\"reason_admin\": {\"403\": \"policy C076E82F\"},"
                + " \"reason_user\": \"Contact your administrator\", \"scope\": \"read\"}}").decide(request());

        assertFalse(decision.permitted());
        assertEquals(NarrowingObligations.NONE, decision.obligations());
        assertEquals("{\"403\":\"policy C076E82F\"}", decision.reasonAdmin());
        assertEquals("Contact your administrator", decision.reasonUser());
        assertEquals("{\"reason\":\"[1]\"}", this.pdp("{\"decision\": false, \"context\": {\"reason_admin\": [1]}}").decide(request()).reasonAdmin(),
                "any other reason is flattened, never dropped");
    }

    @Test
    @Requirement("AUTHZEN-1.0 §10.1.2")
    void anHttpErrorIsNoDecisionEitherWay() {
        for (int status : new int[]{400, 401, 403, 500, 201}) {
            assertThrows(PolicyDecisionException.class, () -> this.pdp(status, "{\"decision\": false}", Map.of(), false).decide(request()),
                    "status " + status);
        }
    }

    @Test
    void anAnswerThatIsNotADecisionIsNoDecision() {
        for (String body : List.of("not json", "{}", "{\"decision\": \"true\"}", "{\"decision\": true, \"context\": {\"scope\": 1}}",
                "{\"decision\": true, \"context\": {\"grant_types\": [1]}}", "{\"decision\": true, \"context\": {\"registration_ttl_seconds\": -1}}",
                "{\"decision\": true, \"context\": {\"registration_ttl_seconds\": 1.5}}",
                "{\"decision\": true, \"context\": {\"registration_ttl_seconds\": \"soon\"}}")) {
            assertThrows(PolicyDecisionException.class, () -> this.pdp(body).decide(request()), body);
        }
    }

    @Test
    void aDecisionPointThatCannotBeReachedIsNoDecision() {
        AuthZenFederationPolicyDecisionPoint unreachable = new AuthZenFederationPolicyDecisionPoint((url, c, b, h, a) -> {
            throw new IOException("connection refused");
        }, AuthZenFederationPolicyDecisionPoint.exactly(PDP + "/evaluate"), null, false, this.clock);

        assertThrows(PolicyDecisionException.class, () -> unreachable.decide(request()));
    }

    /** §5.5: "If the PEP does not understand information in the context response object, the PEP MAY choose to reject". */
    @Test
    @Requirement("AUTHZEN-1.0 §5.5")
    void aPermitWithContextThisDeploymentDoesNotUnderstandIsIgnoredOrRefusedAsConfigured() throws Exception {
        String body = "{\"decision\": true, \"context\": {\"step_up\": \"acr:mfa\"}}";

        PolicyDecision ignoring = this.pdp(body).decide(request());
        PolicyDecision refusing = this.pdp(200, body, Map.of(), true).decide(request());

        assertTrue(ignoring.permitted());
        assertEquals(Set.of("step_up"), ignoring.ignoredContextKeys());
        assertFalse(refusing.permitted());
        assertTrue(refusing.reasonAdmin().contains("step_up"));
        assertNull(refusing.pdpRequestId(), "and nothing was echoed");
        assertTrue(this.pdp(200, "{\"decision\": true, \"context\": {\"scope\": \"read\"}}", Map.of(), true).decide(request()).permitted(),
                "context it does understand is no reason to refuse");
    }

    @Test
    void aRequestWithoutAnIdSendsNone() throws Exception {
        PolicyDecisionRequest anonymous = new PolicyDecisionRequest(DecisionPoint.EXPLICIT_REGISTRATION, "https://rp.example", null,
                "openid_provider", "https://pf.example", null, null, null);

        this.pdp("{\"decision\": true}").decide(anonymous);

        assertFalse(this.headersSent.get(0).containsKey("X-Request-ID"));
    }

    // ---- discovery (§9.2) -----------------------------------------------------------------------

    @Test
    @Requirement({"AUTHZEN-1.0 §9.2", "AUTHZEN-1.0 §9.2.3"})
    void theEvaluationEndpointIsReadFromTheDecisionPointsOwnMetadataOnce() throws Exception {
        List<String> fetched = new ArrayList<>();
        HttpGetClient metadata = (url, accept) -> {
            fetched.add(url);
            return "{\"policy_decision_point\": \"https://pdp.example.com/tenant1\","
                    + " \"access_evaluation_endpoint\": \"https://pdp.example.com/tenant1/v1/evaluate\"}";
        };
        AuthZenFederationPolicyDecisionPoint.Endpoint endpoint = AuthZenFederationPolicyDecisionPoint.discovered(metadata, "https://pdp.example.com/tenant1");

        assertEquals(URI.create("https://pdp.example.com/tenant1/v1/evaluate"), endpoint.resolve());
        endpoint.resolve();

        assertEquals(List.of("https://pdp.example.com/.well-known/authzen-configuration/tenant1"), fetched, "the well-known path goes after the host");
    }

    @Test
    @Requirement("AUTHZEN-1.0 §9.2.3")
    void metadataThatNamesAnotherDecisionPointIsNotUsed() throws Exception {
        assertThrows(PolicyDecisionException.class, () -> AuthZenFederationPolicyDecisionPoint.discover((url, accept) ->
                "{\"policy_decision_point\": \"https://evil.example\", \"access_evaluation_endpoint\": \"https://evil.example/e\"}", PDP));
        assertThrows(PolicyDecisionException.class, () -> AuthZenFederationPolicyDecisionPoint.discover((url, accept) ->
                "{\"policy_decision_point\": \"" + PDP + "\"}", PDP));
        assertThrows(PolicyDecisionException.class, () -> AuthZenFederationPolicyDecisionPoint.discover((url, accept) ->
                "{\"policy_decision_point\": \"" + PDP + "\", \"access_evaluation_endpoint\": \"http://pdp.example.com/e\"}", PDP));
        assertThrows(PolicyDecisionException.class, () -> AuthZenFederationPolicyDecisionPoint.discover((url, accept) -> {
            throw new IOException("down");
        }, PDP));
        assertThrows(PolicyDecisionException.class, () -> AuthZenFederationPolicyDecisionPoint.discover((url, accept) -> {
            throw new AssertionError("nothing to fetch from an identifier with no host");
        }, "urn:pdp:example"));
        assertEquals(URI.create(PDP + "/access/v1/evaluation"), discoveredAt(PDP + "/"), "a root identifier, trailing slash and all");
    }

    private static URI discoveredAt(String pdp) throws Exception {
        return AuthZenFederationPolicyDecisionPoint.discover((url, accept) -> {
            assertEquals(PDP + "/.well-known/authzen-configuration", url);
            return "{\"policy_decision_point\": \"" + pdp + "\", \"access_evaluation_endpoint\": \"" + PDP + "/access/v1/evaluation\"}";
        }, pdp);
    }
}
