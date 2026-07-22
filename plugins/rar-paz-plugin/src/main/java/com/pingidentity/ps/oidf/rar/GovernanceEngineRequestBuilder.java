/*
 * Builds the native PingAuthorize governance-engine ("JSON API") decision request.
 */
package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Maps one {@code authorization_details} entry into the governance-engine request shape:
 * <pre>
 * { "domain":  "&lt;domainPrefix&gt;.&lt;type&gt;",
 *   "service": "&lt;service&gt;",
 *   "action":  "&lt;action&gt;",
 *   "attributes": {
 *     "UserID": "&lt;attestation sub | client_id&gt;",
 *     "client_id": "&lt;client_id&gt;",
 *     "&lt;attrPrefix&gt;.&lt;field&gt;": "&lt;json-stringified value&gt;",   // each requested field
 *     "attestation.entitlement": "&lt;json&gt;",                       // the attested ceiling
 *     "attestation.workload":    "&lt;json&gt;",
 *     "attestation.cnf_thumbprint": "&lt;thumbprint&gt;" } }
 * </pre>
 *
 * <p>Attribute <em>values</em> are JSON-stringified (matching the reference plugin), which is how the
 * PingAuthorize Trust Framework consumes them. Unlike the reference, the subject is the attestation
 * subject (or the client id) rather than a hardcoded {@code "joe"}, and the attested entitlement is
 * included so policy can enforce {@code requested ⊆ attested}.
 */
public final class GovernanceEngineRequestBuilder implements DecisionRequestBuilder {

    private final GovernanceEngineConfig config;
    private final ObjectMapper mapper;

    /** RFC 9396 set-valued fields mirrored as flat, dot-free scalars for PingAuthorize policy. */
    private static final String[] SET_FIELDS = {"actions", "locations", "datatypes", "privileges", "sales_regions"};

    public GovernanceEngineRequestBuilder(GovernanceEngineConfig config, ObjectMapper mapper) {
        this.config = config;
        this.mapper = mapper;
    }

    @Override
    public DecisionRequest build(String type, Map<String, Object> detail, AttestationSubject subject,
                                 String resourceOwner, String fallbackClientId) {
        AttestationSubject subj = subject == null ? AttestationSubject.empty() : subject;
        String domain = join(config.getDomainPrefix(), type);
        String attrPrefix = config.isPrefixAttributesWithType() ? join(config.getAttributePrefix(), type) : config.getAttributePrefix();

        Map<String, Object> attributes = new LinkedHashMap<>();
        // UserID is the PRINCIPAL the decision is about: the authenticated resource owner (the human who
        // consents to the payment) first, then the attestation subject, then the OAuth client. The
        // attestation subject is the delegated agent — recorded separately as 'actor' (RFC 8693 delegation:
        // principal in the subject, agent in act) rather than masquerading as the UserID.
        String attestationSub = subj.getSubject();
        String userId = firstNonBlank(resourceOwner, attestationSub, subj.getClientId(), fallbackClientId);
        attributes.put("UserID", userId == null ? "unknown" : userId);
        if (attestationSub != null && !attestationSub.equals(userId)) {
            attributes.put("actor", attestationSub);
        }
        String clientId = firstNonBlank(subj.getClientId(), fallbackClientId);
        if (clientId != null) {
            attributes.put("client_id", clientId);
        }

        if (detail != null) {
            for (Map.Entry<String, Object> e : detail.entrySet()) {
                if ("type".equals(e.getKey())) {
                    continue;
                }
                attributes.put(prefixed(attrPrefix, e.getKey()), serialize(e.getValue()));
            }
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

        // Flat, dot-free scalar mirrors of the RFC 9396 set-fields. PingAuthorize attribute names cannot
        // contain '.', so a policy reads these directly (space-separated): req_<field> (requested) and
        // att_<field> (union across the attested entitlement) — enabling a simple containment rule.
        if (detail != null) {
            for (String f : SET_FIELDS) {
                if (detail.containsKey(f)) {
                    attributes.put("req_" + f, spaceJoin(detail.get(f)));
                }
            }
        }
        for (String f : SET_FIELDS) {
            String attested = spaceJoin(union(subj.getEntitlement(), f));
            if (!attested.isEmpty()) {
                attributes.put("att_" + f, attested);
            }
        }

        return new DecisionRequest(domain, config.getService(), config.getAction(), attributes);
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
