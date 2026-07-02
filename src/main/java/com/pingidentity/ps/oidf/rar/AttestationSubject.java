/*
 * Attestation-derived context passed from the client-attestation hook to this RAR processor.
 */
package com.pingidentity.ps.oidf.rar;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * The attester-vouched context the decision should be bounded by: the authenticated {@code subject}
 * (attestation {@code sub}), the {@code client_id}, the attested entitlement ceiling (RFC 9396
 * {@code authorization_details}), the {@code workload} attributes, and the {@code cnf} thumbprint.
 *
 * <p>The client-attestation issuance hook publishes this as a {@code Map} request attribute under
 * {@link #REQUEST_ATTRIBUTE}; this processor reads it back via {@code AuthorizationDetailContext.getRequest()}.
 * Kept servlet-free (takes the raw attribute value) so it is unit-testable without a container.
 */
public final class AttestationSubject {

    /** {@code HttpServletRequest} attribute key the attestation hook writes and this processor reads. */
    public static final String REQUEST_ATTRIBUTE = "com.pingidentity.ps.oidf.rar.attestation_context";

    private final String subject;
    private final String clientId;
    private final List<Map<String, Object>> entitlement;
    private final Map<String, Object> workload;
    private final String cnfThumbprint;

    public AttestationSubject(String subject, String clientId, List<Map<String, Object>> entitlement,
                              Map<String, Object> workload, String cnfThumbprint) {
        this.subject = subject;
        this.clientId = clientId;
        this.entitlement = entitlement == null ? List.of() : entitlement;
        this.workload = workload == null ? Map.of() : workload;
        this.cnfThumbprint = cnfThumbprint;
    }

    public String getSubject() { return subject; }
    public String getClientId() { return clientId; }
    public List<Map<String, Object>> getEntitlement() { return entitlement; }
    public Map<String, Object> getWorkload() { return workload; }
    public String getCnfThumbprint() { return cnfThumbprint; }

    public boolean isPresent() {
        return subject != null || clientId != null || !entitlement.isEmpty();
    }

    public static AttestationSubject empty() {
        return new AttestationSubject(null, null, List.of(), Map.of(), null);
    }

    /**
     * Parses whatever the hook stashed on the request. Accepts a {@code Map} with keys {@code sub}/{@code subject},
     * {@code client_id}, {@code entitlement}/{@code authorization_details}, {@code workload},
     * {@code cnf_thumbprint}. Returns {@link #empty()} for anything else (including {@code null}).
     */
    @SuppressWarnings("unchecked")
    public static AttestationSubject fromAttribute(Object attr) {
        if (!(attr instanceof Map)) {
            return empty();
        }
        Map<String, Object> m = (Map<String, Object>) attr;
        String sub = str(m.get("sub"));
        if (sub == null) {
            sub = str(m.get("subject"));
        }
        String clientId = str(m.get("client_id"));
        List<Map<String, Object>> ent = asObjectList(m.get("entitlement"));
        if (ent.isEmpty()) {
            ent = asObjectList(m.get("authorization_details"));
        }
        Map<String, Object> workload = m.get("workload") instanceof Map ? (Map<String, Object>) m.get("workload") : Map.of();
        String cnf = str(m.get("cnf_thumbprint"));
        return new AttestationSubject(sub, clientId, ent, workload, cnf);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> asObjectList(Object value) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (value instanceof Collection<?> c) {
            for (Object o : c) {
                if (o instanceof Map) {
                    out.add((Map<String, Object>) o);
                }
            }
        }
        return out;
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }
}
