package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GovernanceEngineRequestBuilderTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final GovernanceEngineConfig config = GovernanceEngineConfig.builder()
            .pdpUrl("https://pdp/governance-engine")
            .domainPrefix("idpartners.authorization_details")
            .attributePrefix("idp")
            .build();
    private final GovernanceEngineRequestBuilder builder = new GovernanceEngineRequestBuilder(config, mapper);

    @Test
    void buildsDomainServiceActionAndPrefixedAttributes() {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "payment_initiation");
        detail.put("actions", List.of("initiate"));
        detail.put("creditorName", "Acme");
        List<Map<String, Object>> entitlement =
                List.of(Map.of("type", "payment_initiation", "actions", List.of("initiate", "status")));
        AttestationSubject subject = new AttestationSubject("agent-123", "https://rp.example.com",
                entitlement, Map.of("environment", "demo"), "thumb-xyz");

        DecisionRequest req = builder.build("payment_initiation", detail, subject, "fallback-client");

        assertEquals("idpartners.authorization_details.payment_initiation", req.getDomain());
        assertEquals("Authorization", req.getService());
        assertEquals("authorize", req.getAction());

        Map<String, Object> attrs = req.getAttributes();
        assertEquals("agent-123", attrs.get("UserID"));
        assertEquals("https://rp.example.com", attrs.get("client_id"));
        assertEquals("[\"initiate\"]", attrs.get("idp.payment_initiation.actions"));
        assertEquals("Acme", attrs.get("idp.payment_initiation.creditorName"));
        assertFalse(attrs.containsKey("idp.payment_initiation.type"));
        assertTrue(attrs.containsKey("attestation.entitlement"));
        assertEquals("thumb-xyz", attrs.get("attestation.cnf_thumbprint"));
        // flat, dot-free mirrors for PingAuthorize policy
        assertEquals("initiate", attrs.get("req_actions"));
        assertEquals("initiate status", attrs.get("att_actions"));
    }

    @Test
    void fallsBackToClientIdForSubjectWhenAttestationEmpty() {
        DecisionRequest req = builder.build("sales_agent", Map.of("type", "sales_agent"),
                AttestationSubject.empty(), "fallback-client");
        assertEquals("fallback-client", req.getAttributes().get("UserID"));
    }
}
