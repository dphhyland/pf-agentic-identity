package com.pingidentity.ps.oidf.federation.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** A federation question, as an AuthZEN 1.0 Access Evaluation request (§6.1). */
class PolicyDecisionRequestTest {

    @Test
    @Requirement({"AUTHZEN-1.0 §5.1", "AUTHZEN-1.0 §5.2", "AUTHZEN-1.0 §5.3", "AUTHZEN-1.0 §6.1"})
    void theSubjectIsTheFederationEntityAndTheActionTheDecisionPoint() {
        PolicyDecisionRequest request = new PolicyDecisionRequest(DecisionPoint.AUTOMATIC_REGISTRATION, "https://rp.example",
                Map.of("entity_types", java.util.List.of("openid_relying_party")), "openid_provider", "https://pf.example",
                Map.of("endpoint", "par"), Map.of("trust_anchor", "https://ta.example", "request", Map.of("tracking_id", "t-1")), "t-1");

        Map<String, Object> body = request.toAuthZen();

        assertEquals(Map.of("type", "federation_entity", "id", "https://rp.example", "properties",
                Map.of("entity_types", java.util.List.of("openid_relying_party"))), body.get("subject"));
        assertEquals(Map.of("name", "federation.register.automatic", "properties", Map.of("endpoint", "par")), body.get("action"));
        assertEquals(Map.of("type", "openid_provider", "id", "https://pf.example"), body.get("resource"));
        assertEquals(Map.of("trust_anchor", "https://ta.example", "request", Map.of("tracking_id", "t-1")), body.get("context"));
    }

    @Test
    void aCachedDecisionIsKeyedOnTheRequestLessWhatIsParticularToIt() {
        PolicyDecisionRequest one = new PolicyDecisionRequest(DecisionPoint.EXPLICIT_REGISTRATION, "https://rp.example", null, "openid_provider",
                "https://pf.example", null, Map.of("request", Map.of("tracking_id", "t-1")), "t-1");
        PolicyDecisionRequest two = new PolicyDecisionRequest(DecisionPoint.EXPLICIT_REGISTRATION, "https://rp.example", null, "openid_provider",
                "https://pf.example", null, Map.of("request", Map.of("tracking_id", "t-2")), "t-2");

        assertEquals(one.cacheKey(), two.cacheKey());
        assertFalse(one.cacheKey().containsKey("context"), "nothing but the request context, so no context at all");
        assertFalse(((Map<?, ?>) one.toAuthZen().get("subject")).containsKey("properties"));
        assertFalse(((Map<?, ?>) one.toAuthZen().get("action")).containsKey("properties"));
        assertEquals("hosted_entity_enrol", DecisionPoint.HOSTED_ENTITY_ENROL.settingName());
        assertThrows(NullPointerException.class, () -> new PolicyDecisionRequest(null, "s", null, "t", "i", null, null, null));
    }
}
