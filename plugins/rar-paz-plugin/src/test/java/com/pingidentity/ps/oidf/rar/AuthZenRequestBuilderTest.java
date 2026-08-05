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
    void resourceOwnerIsTheSubjectAndAgentIdIsTheActor() {
        // RFC 8693 delegation: the authenticated principal is the subject; the attester-minted agent_id
        // is the actor in context — never disguised as the subject.
        AttestationSubject agent = new AttestationSubject("https://rp.example.com", "https://rp.example.com",
                List.of(), Map.of(), null, "payments-agent");
        Map<String, Object> req = builder.build("payment_initiation",
                Map.of("type", "payment_initiation", "amount", "50.00"), agent, "alice", "northwind-webapp");

        assertEquals(Map.of("type", "user", "id", "alice"), node(req, "subject"));
        Map<String, Object> context = node(req, "context");
        assertEquals(Map.of("type", "agent", "id", "payments-agent"), context.get("actor"));
        assertEquals("https://rp.example.com", context.get("client_id"));
    }

    @Test
    void clientIsTheSubjectWhenNoResourceOwner() {
        // Pin (Phase 2.9): the attestation 'sub' (always == client_id) must never be labelled "agent" as
        // the subject — that was the PDP actor-labelling bug. With no agent_id minted either, there is no
        // actor at all: a bare client_credentials call, no delegation in play.
        AttestationSubject noAgent = new AttestationSubject("https://rp.example.com", "https://rp.example.com",
                List.of(), Map.of(), null);
        Map<String, Object> req = builder.build("sales_agent", Map.of("type", "sales_agent"),
                noAgent, null, "fallback-client");

        assertEquals(Map.of("type", "client", "id", "https://rp.example.com"), node(req, "subject"));
        assertFalse(node(req, "context").containsKey("actor"));
    }

    @Test
    void agentIdStillSurfacesAsActorEvenWithoutAResourceOwner() {
        // A machine-to-machine call with no human in the loop still names the specific instance acting,
        // when the attester minted one — this is exactly what lets policy express "refuse when there is
        // no actor" or a per-agent_id rate limit, neither expressible on client_id alone.
        AttestationSubject agent = new AttestationSubject("https://rp.example.com", "https://rp.example.com",
                List.of(), Map.of(), null, "agent-123");
        Map<String, Object> req = builder.build("sales_agent", Map.of("type", "sales_agent"),
                agent, null, "fallback-client");

        assertEquals(Map.of("type", "client", "id", "https://rp.example.com"), node(req, "subject"));
        Map<String, Object> context = node(req, "context");
        assertEquals(Map.of("type", "agent", "id", "agent-123"), context.get("actor"));
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
        AttestationSubject subject = new AttestationSubject("https://rp.example.com", "https://rp.example.com",
                entitlement, Map.of("environment", "demo"), "thumb-xyz", "agent-123");
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
