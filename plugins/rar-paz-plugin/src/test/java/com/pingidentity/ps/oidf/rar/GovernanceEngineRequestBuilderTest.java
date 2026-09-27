package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        // agentId (not "subject") is the delegated agent, Phase 2.9 — the attestation 'sub' is never
        // itself an actor/UserID candidate; it always equals client_id.
        AttestationSubject subject = new AttestationSubject("https://rp.example.com", "https://rp.example.com",
                entitlement, Map.of("environment", "demo"), "thumb-xyz", "agent-123");

        DecisionRequest req = builder.build("payment_initiation", detail, subject, null, "fallback-client", "authenticated");

        assertEquals("idpartners.authorization_details.payment_initiation", req.getDomain());
        assertEquals("Authorization", req.getService());
        assertEquals("authorize", req.getAction());

        Map<String, Object> attrs = req.getAttributes();
        // No resource owner supplied -> UserID falls back to the client, never to the agent_id — and the
        // agent_id still surfaces as 'actor' even on a bare machine-to-machine call, since that is exactly
        // what lets policy rate-limit or attribute a specific instance (Phase 2.9's own worked example).
        assertEquals("https://rp.example.com", attrs.get("UserID"));
        assertEquals("agent-123", attrs.get("actor"));
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
    @Requirement("PROFILE §6(1)")
    void withNoAgentIdTheAttestationSubjectNeverBecomesUserIdOrActor() {
        // Pin (Phase 2.9): even though the attestation 'sub' field is set, it must never surface as
        // UserID or actor — only agent_id (absent here) can.
        AttestationSubject subject = new AttestationSubject("https://rp.example.com", "https://rp.example.com",
                List.of(), Map.of(), null);
        DecisionRequest req = builder.build("sales_agent", Map.of("type", "sales_agent"),
                subject, null, "fallback-client", "authenticated");
        Map<String, Object> attrs = req.getAttributes();
        assertEquals("https://rp.example.com", attrs.get("UserID"));
        assertFalse(attrs.containsKey("actor"));
    }

    @Test
    void fallsBackToClientIdForSubjectWhenAttestationEmpty() {
        DecisionRequest req = builder.build("sales_agent", Map.of("type", "sales_agent"),
                AttestationSubject.empty(), null, "fallback-client", "authenticated");
        assertEquals("fallback-client", req.getAttributes().get("UserID"));
    }

    @Test
    @Requirement({"RFC8693 §1.1", "PROFILE §6(3)"})
    void resourceOwnerBecomesUserIdAndAgentIdIsTheActor() {
        // The authenticated principal (e.g. the signed-in user consenting to a payment) is the UserID; the
        // attester-minted agent_id (the delegated agent) is recorded as 'actor' — RFC 8693 delegation, not
        // impersonation. This is the fix for PF's AuthorizationDetailContext exposing no resource owner.
        AttestationSubject agent = new AttestationSubject("https://rp.example.com", "https://rp.example.com",
                List.of(), Map.of(), null, "payments-agent");
        DecisionRequest req = builder.build("payment_initiation", Map.of("type", "payment_initiation"),
                agent, "alice", "northwind-webapp", "authenticated");
        Map<String, Object> attrs = req.getAttributes();
        assertEquals("alice", attrs.get("UserID"));
        assertEquals("payments-agent", attrs.get("actor"));
        assertEquals("https://rp.example.com", attrs.get("client_id"));
    }

    // ---- the server's attributes are written last, and a detail may not name one ---------------------

    @Test
    void aDetailFieldThatWouldOverwriteAServerAttributeIsRefused() {
        GovernanceEngineConfig bare = GovernanceEngineConfig.builder().pdpUrl("https://pdp")
                .attributePrefix("").prefixAttributesWithType(false).build();
        GovernanceEngineRequestBuilder unprefixed = new GovernanceEngineRequestBuilder(bare, mapper);
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "sales_agent");
        detail.put("UserID", "mallory");
        detail.put("principal_source", "authenticated");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> unprefixed.build("sales_agent", detail, AttestationSubject.empty(), "alice", "client-1", "client"));
        assertTrue(e.getMessage().contains("UserID"), e.getMessage());
        assertTrue(e.getMessage().contains("principal_source"), e.getMessage());

        // A mirror name, too: req_actions is what the builder derives from "actions".
        Map<String, Object> mirror = new LinkedHashMap<>();
        mirror.put("type", "sales_agent");
        mirror.put("actions", List.of("read"));
        mirror.put("req_actions", "write");
        assertThrows(IllegalArgumentException.class,
                () -> unprefixed.build("sales_agent", mirror, AttestationSubject.empty(), "alice", "client-1", "authenticated"));
    }

    /**
     * The attested-ceiling mirror is the builder's alone even when it writes none. An attestation that
     * constrains no actions produces no {@code att_actions}; before 2026-09-27 a detail carrying its own
     * {@code att_actions} then reached the PDP as the ceiling a {@code req_actions ⊆ att_actions} rule reads.
     */
    @Test
    void aMirrorNameIsReservedEvenWhenThisRequestWritesNoMirror() {
        GovernanceEngineConfig bare = GovernanceEngineConfig.builder().pdpUrl("https://pdp")
                .attributePrefix("").prefixAttributesWithType(false).build();
        GovernanceEngineRequestBuilder unprefixed = new GovernanceEngineRequestBuilder(bare, mapper);
        Map<String, Object> forged = new LinkedHashMap<>();
        forged.put("type", "sales_agent");
        forged.put("actions", List.of("transfer"));
        forged.put("att_actions", "transfer");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> unprefixed.build("sales_agent", forged, AttestationSubject.empty(), "alice", "client-1", "authenticated"));
        assertTrue(e.getMessage().contains("att_actions"), e.getMessage());

        Map<String, Object> requested = new LinkedHashMap<>();
        requested.put("type", "sales_agent");
        requested.put("req_locations", "https://anywhere.example");
        assertThrows(IllegalArgumentException.class,
                () -> unprefixed.build("sales_agent", requested, AttestationSubject.empty(), "alice", "client-1", "authenticated"));

        assertEquals(2 * RarContainment.SET_FIELDS.length, GovernanceEngineRequestBuilder.MIRROR_ATTRIBUTES.size());
        for (String field : RarContainment.SET_FIELDS) {
            assertTrue(GovernanceEngineRequestBuilder.MIRROR_ATTRIBUTES.contains("req_" + field), field);
            assertTrue(GovernanceEngineRequestBuilder.MIRROR_ATTRIBUTES.contains("att_" + field), field);
        }
    }

    @Test
    void withAPrefixTheSameFieldNamesAreOrdinaryAndTheServerWritesLast() {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "sales_agent");
        detail.put("UserID", "mallory");
        DecisionRequest req = builder.build("sales_agent", detail, AttestationSubject.empty(), "alice", "client-1", "authenticated");
        assertEquals("mallory", req.getAttributes().get("idp.sales_agent.UserID"));
        assertEquals("alice", req.getAttributes().get("UserID"));
        List<String> order = new java.util.ArrayList<>(req.getAttributes().keySet());
        assertTrue(order.indexOf("idp.sales_agent.UserID") < order.indexOf("UserID"), order.toString());
        assertEquals("authenticated", req.getAttributes().get("principal_source"));
    }

    @Test
    void theAttesterIssuerIsSentBesideTheActorAndTheAttestation() {
        AttestationSubject agent = new AttestationSubject("https://rp.example.com", "https://rp.example.com",
                List.of(), Map.of(), null, "payments-agent", "https://attester.example", null);
        Map<String, Object> attrs = builder.build("payment_initiation", Map.of("type", "payment_initiation"),
                agent, "alice", "northwind-webapp", "authenticated").getAttributes();
        assertEquals("payments-agent", attrs.get("actor"));
        assertEquals("https://attester.example", attrs.get("actor_iss"));
        assertEquals("https://attester.example", attrs.get("attestation.iss"));

        AttestationSubject noIss = new AttestationSubject("https://rp.example.com", "https://rp.example.com",
                List.of(), Map.of(), null, "payments-agent");
        Map<String, Object> without = builder.build("payment_initiation", Map.of("type", "payment_initiation"),
                noIss, "alice", "northwind-webapp", "authenticated").getAttributes();
        assertFalse(without.containsKey("actor_iss"));
        assertFalse(without.containsKey("attestation.iss"));
    }

    @Test
    void aNullSubjectOrDetailIsTolerated() {
        Map<String, Object> attrs = builder.build("sales_agent", null, null, null, null, null).getAttributes();
        assertEquals("unknown", attrs.get("UserID"));
        assertFalse(attrs.containsKey("principal_source"));
        assertFalse(attrs.containsKey("client_id"));
    }

    @Test
    void resourceOwnerBecomesUserIdWhenNoAttestation() {
        // Browser payment-consent flow: no attestation present, so without the fix UserID would degrade to
        // the OAuth client id. With the resource owner threaded through, UserID is correctly the principal.
        DecisionRequest req = builder.build("payment_initiation", Map.of("type", "payment_initiation"),
                AttestationSubject.empty(), "alice", "northwind-webapp", "authenticated");
        Map<String, Object> attrs = req.getAttributes();
        assertEquals("alice", attrs.get("UserID"));
        assertFalse(attrs.containsKey("actor"));
    }
}
