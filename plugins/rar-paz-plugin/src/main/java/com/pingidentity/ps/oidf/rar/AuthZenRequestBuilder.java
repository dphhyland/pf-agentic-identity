/*
 * Builds the OpenID AuthZEN 1.0 evaluation request for one authorization_details entry.
 */
package com.pingidentity.ps.oidf.rar;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maps one {@code authorization_details} entry into the AuthZEN evaluation shape:
 * <pre>
 * { "subject":  { "type": "user|client", "id": "&lt;principal&gt;" },
 *   "action":   { "name": "&lt;configured action&gt;" },
 *   "resource": { "type": "&lt;detail type&gt;", "id": "&lt;detail identifier | type&gt;",
 *                 "properties": { …the requested detail, minus "type"… } },
 *   "context":  { "client_id": "…",
 *                 "actor": { "type": "agent", "id": "&lt;agent_id&gt;" },   // when minted and ≠ subject
 *                 "attestation": { "entitlement": […], "workload": {…}, "cnf_thumbprint": "…" } } }
 * </pre>
 *
 * <p>The subject is the <b>principal</b> the decision is about — the authenticated resource owner
 * first, then the OAuth client — with {@code subject.type} recording which one won. The attestation
 * {@code sub} is never itself a subject.type candidate: it always names the registered client/agent
 * TYPE (equal to {@code client_id}), never a per-instance identity, so treating it as a distinct
 * "attestation subject" tier — and worse, labelling that tier {@code "agent"} — was a PDP
 * actor-labelling bug (Phase 2.9 fixed it here). The genuine delegated <b>agent</b> — the specific
 * running instance, when the attester minted an {@code agent_id} for it (Phase 2.1/2.2) — is carried as
 * {@code context.actor} (RFC 8693 delegation: principal in the subject, agent as actor), never
 * masquerading as, or conflated with, the subject.
 *
 * <p>Unlike the governance-engine dialect (whose Trust Framework wants JSON-stringified attribute
 * values), AuthZEN carries structured JSON natively — detail fields, entitlement, and workload go in
 * as-is.
 */
public final class AuthZenRequestBuilder {

    private final GovernanceEngineConfig config;

    public AuthZenRequestBuilder(GovernanceEngineConfig config) {
        this.config = config;
    }

    public Map<String, Object> build(String type, Map<String, Object> detail, AttestationSubject subject,
                                     String resourceOwner, String fallbackClientId) {
        AttestationSubject subj = subject == null ? AttestationSubject.empty() : subject;
        String agentId = subj.getAgentId();

        // Phase 2.9: the attestation 'sub' (subj.getSubject()) is deliberately NOT consulted here — it
        // always equals client_id (the registered client/agent TYPE), so a prior "attestation subject"
        // tier labelled "agent" was mislabelling the client as an agent. The only genuine agent identity
        // is agentId, and it belongs in context.actor below, never in the principal.
        String principal;
        String principalType;
        if (notBlank(resourceOwner)) {
            principal = resourceOwner;
            principalType = "user";
        } else if (notBlank(subj.getClientId())) {
            principal = subj.getClientId();
            principalType = "client";
        } else {
            principal = fallbackClientId == null || fallbackClientId.isBlank() ? "unknown" : fallbackClientId;
            principalType = "client";
        }

        Map<String, Object> subjectNode = new LinkedHashMap<>();
        subjectNode.put("type", principalType);
        subjectNode.put("id", principal);

        Map<String, Object> actionNode = new LinkedHashMap<>();
        actionNode.put("name", config.getAction());

        Map<String, Object> properties = new LinkedHashMap<>();
        Object identifier = null;
        if (detail != null) {
            for (Map.Entry<String, Object> e : detail.entrySet()) {
                if ("type".equals(e.getKey())) {
                    continue;
                }
                if ("identifier".equals(e.getKey())) {
                    identifier = e.getValue();
                }
                properties.put(e.getKey(), e.getValue());
            }
        }
        Map<String, Object> resourceNode = new LinkedHashMap<>();
        resourceNode.put("type", type);
        resourceNode.put("id", identifier != null ? String.valueOf(identifier) : type);
        if (!properties.isEmpty()) {
            resourceNode.put("properties", properties);
        }

        Map<String, Object> context = new LinkedHashMap<>();
        String clientId = notBlank(subj.getClientId()) ? subj.getClientId() : fallbackClientId;
        if (notBlank(clientId)) {
            context.put("client_id", clientId);
        }
        if (notBlank(agentId) && !agentId.equals(principal)) {
            Map<String, Object> actor = new LinkedHashMap<>();
            actor.put("type", "agent");
            actor.put("id", agentId);
            context.put("actor", actor);
        }
        Map<String, Object> attestation = new LinkedHashMap<>();
        if (!subj.getEntitlement().isEmpty()) {
            attestation.put("entitlement", subj.getEntitlement());
        }
        if (!subj.getWorkload().isEmpty()) {
            attestation.put("workload", subj.getWorkload());
        }
        if (subj.getCnfThumbprint() != null) {
            attestation.put("cnf_thumbprint", subj.getCnfThumbprint());
        }
        if (!attestation.isEmpty()) {
            context.put("attestation", attestation);
        }

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("subject", subjectNode);
        request.put("action", actionNode);
        request.put("resource", resourceNode);
        if (!context.isEmpty()) {
            request.put("context", context);
        }
        return request;
    }

    private static boolean notBlank(String v) {
        return v != null && !v.isBlank();
    }
}
