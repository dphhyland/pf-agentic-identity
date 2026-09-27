/*
 * Builds the native PingAuthorize governance-engine ("JSON API") decision request.
 */
package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Maps one {@code authorization_details} entry into the governance-engine request shape:
 * <pre>
 * { "domain":  "&lt;domainPrefix&gt;.&lt;type&gt;",
 *   "service": "&lt;service&gt;",
 *   "action":  "&lt;action&gt;",
 *   "attributes": {
 *     "&lt;attrPrefix&gt;.&lt;field&gt;": "&lt;json-stringified value&gt;",   // each requested field, written first
 *     "req_&lt;field&gt;": "…", "att_&lt;field&gt;": "…",                  // flat mirrors of the set-valued fields
 *     "UserID": "&lt;resource owner | client_id&gt;",                   // the server's attributes, written last
 *     "principal_source": "authenticated | client | …",
 *     "actor":  "&lt;agent_id&gt;", "actor_iss": "&lt;attester iss&gt;",     // when minted and ≠ UserID
 *     "client_id": "&lt;client_id&gt;",
 *     "attestation.entitlement": "&lt;json&gt;",                       // the attested ceiling
 *     "attestation.workload":    "&lt;json&gt;",
 *     "attestation.cnf_thumbprint": "&lt;thumbprint&gt;",
 *     "attestation.iss": "&lt;attester iss&gt;" } }
 * </pre>
 *
 * <p>Attribute <em>values</em> are JSON-stringified (matching the reference plugin), which is how the
 * PingAuthorize Trust Framework consumes them. Unlike the reference, the subject is the resource owner
 * (or the client id) rather than a hardcoded {@code "joe"}, and the attested entitlement is included so
 * policy can enforce {@code requested ⊆ attested}.
 *
 * <p>The requested fields go in first and the server's attributes last, and a requested field whose
 * attribute name is one the server writes is refused ({@link #RESERVED_ATTRIBUTES}, plus the {@code req_}
 * and {@code att_} mirrors of this request). With an empty attribute prefix and the type prefix off, a
 * caller could otherwise send {@code "UserID": "alice"} inside the detail and have it land on the PDP as
 * the principal. Written last, the server's value would win anyway; refusing as well means the request
 * that tried is denied rather than quietly corrected.
 */
public final class GovernanceEngineRequestBuilder implements DecisionRequestBuilder {

    /** The attribute names this builder writes itself; a requested field may not map onto any of them. */
    static final Set<String> RESERVED_ATTRIBUTES = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
            "UserID", "principal_source", "actor", "actor_iss", "client_id",
            "attestation.entitlement", "attestation.workload", "attestation.cnf_thumbprint", "attestation.iss")));

    private final GovernanceEngineConfig config;
    private final ObjectMapper mapper;

    /**
     * RFC 9396 set-valued fields mirrored as flat, dot-free scalars for PingAuthorize policy.
     *
     * <p>The same list containment uses, not a copy of it. These two travel together by construction:
     * the {@code att_*}/{@code req_*} attributes below are what a policy compares, so a field the
     * builder mirrors but containment ignores (or the reverse) is a rule that looks enforced and is not.
     */
    private static final String[] SET_FIELDS = RarContainment.SET_FIELDS;

    public GovernanceEngineRequestBuilder(GovernanceEngineConfig config, ObjectMapper mapper) {
        this.config = config;
        this.mapper = mapper;
    }

    @Override
    public DecisionRequest build(String type, Map<String, Object> detail, AttestationSubject subject,
                                 String resourceOwner, String fallbackClientId, String principalSource) {
        AttestationSubject subj = subject == null ? AttestationSubject.empty() : subject;
        String domain = join(config.getDomainPrefix(), type);
        String attrPrefix = config.isPrefixAttributesWithType() ? join(config.getAttributePrefix(), type) : config.getAttributePrefix();

        // The requested detail first: each field under its prefixed name, then the flat mirrors.
        Map<String, Object> attributes = new LinkedHashMap<>();
        if (detail != null) {
            for (Map.Entry<String, Object> e : detail.entrySet()) {
                if ("type".equals(e.getKey())) {
                    continue;
                }
                attributes.put(prefixed(attrPrefix, e.getKey()), serialize(e.getValue()));
            }
        }
        // Flat, dot-free scalar mirrors of the RFC 9396 set-fields. PingAuthorize attribute names cannot
        // contain '.', so a policy reads these directly (space-separated): req_<field> (requested) and
        // att_<field> (union across the attested entitlement) — enabling a simple containment rule.
        Map<String, Object> mirrors = new LinkedHashMap<>();
        if (detail != null) {
            for (String f : SET_FIELDS) {
                if (detail.containsKey(f)) {
                    mirrors.put("req_" + f, spaceJoin(detail.get(f)));
                }
            }
        }
        for (String f : SET_FIELDS) {
            String attested = spaceJoin(union(subj.getEntitlement(), f));
            if (!attested.isEmpty()) {
                mirrors.put("att_" + f, attested);
            }
        }
        refuseCollisions(attributes.keySet(), mirrors.keySet());
        attributes.putAll(mirrors);

        // The server's attributes last, so nothing requested can have written them first. UserID is the
        // PRINCIPAL the decision is about: the resolved principal (the person who consents to the payment)
        // first, then the OAuth client. The delegated AGENT — the specific running instance, when the
        // attester minted one — is the agent_id, recorded separately as 'actor' (RFC 8693 delegation:
        // principal in the subject, agent in act) with the attester that minted it as 'actor_iss', because
        // an agent_id is unique only within its issuing authority.
        String clientId = firstNonBlank(subj.getClientId(), fallbackClientId);
        String userId = firstNonBlank(resourceOwner, clientId);
        attributes.put("UserID", userId == null ? "unknown" : userId);
        // How that UserID was established. Without it the engine cannot tell an authenticated principal
        // from a client, a hint or one the caller simply named, and a rule about "the user" covers them all.
        if (principalSource != null && !principalSource.isBlank()) {
            attributes.put("principal_source", principalSource);
        }
        String agentId = subj.getAgentId();
        if (agentId != null && !agentId.isBlank() && !agentId.equals(userId)) {
            attributes.put("actor", agentId);
            if (subj.getAttesterIssuer() != null) {
                attributes.put("actor_iss", subj.getAttesterIssuer());
            }
        }
        if (clientId != null) {
            attributes.put("client_id", clientId);
        }
        if (!subj.getEntitlement().isEmpty()) {
            attributes.put("attestation.entitlement", serialize(subj.getEntitlement()));
        }
        if (!subj.getWorkload().isEmpty()) {
            attributes.put("attestation.workload", serialize(subj.getWorkload()));
        }
        if (subj.getCnfThumbprint() != null) {
            attributes.put("attestation.cnf_thumbprint", subj.getCnfThumbprint());
        }
        if (subj.getAttesterIssuer() != null) {
            attributes.put("attestation.iss", subj.getAttesterIssuer());
        }

        return new DecisionRequest(domain, config.getService(), config.getAction(), attributes);
    }

    /**
     * A requested field whose attribute name is one the server writes - a reserved name, or a mirror this
     * request produces - is refused with the names, and the processor turns that into a denial.
     */
    static void refuseCollisions(Set<String> requested, Set<String> mirrors) {
        List<String> collisions = new ArrayList<>();
        for (String name : requested) {
            if (RESERVED_ATTRIBUTES.contains(name) || mirrors.contains(name)) {
                collisions.add(name);
            }
        }
        if (!collisions.isEmpty()) {
            throw new IllegalArgumentException("authorization_details field(s) collide with attributes the server sets: "
                    + collisions + " (reserved: " + RESERVED_ATTRIBUTES + ", plus req_*/att_* mirrors)");
        }
    }

    private String serialize(Object value) {
        if (value instanceof String) {
            return (String) value;
        }
        try {
            return mapper.writeValueAsString(value);
        } catch (Exception e) {
            return String.valueOf(value);
        }
    }

    private static String join(String prefix, String suffix) {
        if (prefix == null || prefix.isBlank()) {
            return suffix;
        }
        return suffix == null || suffix.isBlank() ? prefix : prefix + "." + suffix;
    }

    private static String prefixed(String prefix, String key) {
        return prefix == null || prefix.isBlank() ? key : prefix + "." + key;
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    private static String spaceJoin(Object value) {
        return String.join(" ", asStrings(value));
    }

    private static List<String> asStrings(Object value) {
        List<String> out = new ArrayList<>();
        if (value instanceof Collection<?> c) {
            for (Object o : c) {
                if (o != null) {
                    out.add(String.valueOf(o));
                }
            }
        } else if (value != null) {
            out.add(String.valueOf(value));
        }
        return out;
    }

    private static List<String> union(List<Map<String, Object>> details, String field) {
        LinkedHashSet<String> set = new LinkedHashSet<>();
        if (details != null) {
            for (Map<String, Object> d : details) {
                if (d != null) {
                    set.addAll(asStrings(d.get(field)));
                }
            }
        }
        return new ArrayList<>(set);
    }
}
