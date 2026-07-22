package com.pingidentity.ps.oidf.rar;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthZenRequestBuilderTest {

    private final GovernanceEngineConfig config = GovernanceEngineConfig.builder()
            .pdpUrl("https://pdp/access/v1/evaluation")
            .build();
    private final AuthZenRequestBuilder builder = new AuthZenRequestBuilder(config);

    @SuppressWarnings("unchecked")
    private static Map<String, Object> node(Map<String, Object> req, String key) {
        return (Map<String, Object>) req.get(key);
    }

    @Test
    void resourceOwnerIsTheSubjectAndAttestationSubjectIsTheActor() {
        // RFC 8693 delegation: the authenticated principal is the subject; the attested agent is the
        // actor in context — never disguised as the subject.
        AttestationSubject agent = new AttestationSubject("payments-agent", "https://rp.example.com",
                List.of(), Map.of(), null);
        Map<String, Object> req = builder.build("payment_initiation",
                Map.of("type", "payment_initiation", "amount", "50.00"), agent, "alice", "northwind-webapp");

        assertEquals(Map.of("type", "user", "id", "alice"), node(req, "subject"));
        Map<String, Object> context = node(req, "context");
        assertEquals(Map.of("type", "agent", "id", "payments-agent"), context.get("actor"));
        assertEquals("https://rp.example.com", context.get("client_id"));
    }

    @Test
    void attestationSubjectIsTheSubjectWhenNoResourceOwner() {
        AttestationSubject agent = new AttestationSubject("agent-123", "https://rp.example.com",
                List.of(), Map.of(), null);
        Map<String, Object> req = builder.build("sales_agent", Map.of("type", "sales_agent"),
                agent, null, "fallback-client");

        assertEquals(Map.of("type", "agent", "id", "agent-123"), node(req, "subject"));
        // The subject IS the agent — no separate actor entry.
        assertFalse(node(req, "context").containsKey("actor"));
    }

    @Test
    void fallsBackToClientSubjectWhenAttestationEmpty() {
        Map<String, Object> req = builder.build("sales_agent", Map.of("type", "sales_agent"),
                AttestationSubject.empty(), null, "fallback-client");
        assertEquals(Map.of("type", "client", "id", "fallback-client"), node(req, "subject"));
    }

    @Test
    void resourceCarriesTheDetailAsStructuredProperties() {
        Map<String, Object> detail = Map.of(
                "type", "payment_initiation",
                "identifier", "intent-42",
                "amount", "50.00",
                "actions", List.of("initiate"));
        Map<String, Object> req = builder.build("payment_initiation", detail,
                AttestationSubject.empty(), "alice", "client-1");

        Map<String, Object> resource = node(req, "resource");
        assertEquals("payment_initiation", resource.get("type"));
        assertEquals("intent-42", resource.get("id"));
        Map<String, Object> props = node(resource, "properties");
        assertNull(props.get("type"));
        assertEquals("50.00", props.get("amount"));
        assertEquals(List.of("initiate"), props.get("actions"));   // structured JSON, not stringified
        assertEquals(Map.of("name", "authorize"), node(req, "action"));
    }

    @Test
    void attestedEntitlementRidesInContext() {
        List<Map<String, Object>> entitlement = List.of(Map.of("type", "sales_agent",
                "sales_regions", List.of("EMEA")));
        AttestationSubject subject = new AttestationSubject("agent-123", "https://rp.example.com",
                entitlement, Map.of("environment", "demo"), "thumb-xyz");
        Map<String, Object> req = builder.build("sales_agent", Map.of("type", "sales_agent"),
                subject, "alice", null);

        @SuppressWarnings("unchecked")
        Map<String, Object> attestation = (Map<String, Object>) node(req, "context").get("attestation");
        assertEquals(entitlement, attestation.get("entitlement"));
        assertEquals(Map.of("environment", "demo"), attestation.get("workload"));
        assertEquals("thumb-xyz", attestation.get("cnf_thumbprint"));
        assertTrue(node(req, "context").containsKey("actor"));
    }
}
