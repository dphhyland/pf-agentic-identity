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
 * (attestation {@code sub} — the registered client/agent TYPE, never a per-instance identity), the
 * {@code client_id}, the attested entitlement ceiling (RFC 9396 {@code authorization_details}), the
 * {@code workload} attributes, the {@code cnf} thumbprint, {@code agent_id} — the attester-minted identifier
 * of the specific running instance, when one was minted — and {@code iss}, the attester that minted it:
 * {@code agent_id} and {@code client_id} are unique only within an issuing authority, so the acting party's
 * full identity is the pair. {@code subject} and {@code clientId} are, today, always the same value (see
 * {@code ClientAttestationUtils.attestationContext}). The context also names the RAR model set the filter checked
 * the request with, by its fingerprint ({@link #RAR_MODELS_FINGERPRINT_KEY}).
 *
 * <p>The client-attestation issuance hook publishes this as a {@code Map} request attribute under
 * {@link #REQUEST_ATTRIBUTE}; this processor reads it back via {@code AuthorizationDetailContext.getJakartaRequest()}.
 * Kept servlet-free (takes the raw attribute value) so it is unit-testable without a container.
 */
public final class AttestationSubject {

    /** {@code HttpServletRequest} attribute key the attestation hook writes and this processor reads. */
    public static final String REQUEST_ATTRIBUTE = "com.pingidentity.ps.oidf.rar.attestation_context";

    /**
     * The key under which the token-endpoint filter publishes the subject of a token-exchange
     * {@code subject_token} it has verified as PingFederate-signed. Read by {@link PrincipalResolver} for the
     * {@code subject_token} principal source, and from this attribute alone - the filter's map is built
     * server-side from what it verified, and nothing a caller sends reaches it. From 0.6.0 the filter and the
     * criterion publish it for a subject token that verifies against PingFederate's signing keys and issuer (F-0074);
     * any other token exchange resolves to {@code none}.
     */
    public static final String VERIFIED_SUBJECT_TOKEN_KEY = "verified_subject_token_sub";

    /**
     * The key under which the filter publishes its {@code RarModels.fingerprint()} (lower-case hex SHA-256), which
     * the plugin compares with its own model set's before it asks the model anything ({@link ModelGate}).
     */
    public static final String RAR_MODELS_FINGERPRINT_KEY = ModelGate.FINGERPRINT_MEMBER;

    private final String subject;
    private final String clientId;
    private final List<Map<String, Object>> entitlement;
    private final Map<String, Object> workload;
    private final String cnfThumbprint;
    private final String agentId;
    private final String attesterIssuer;
    private final String verifiedSubjectTokenSubject;
    private final String rarModelsFingerprint;
    private final boolean contextPresent;

    public AttestationSubject(String subject, String clientId, List<Map<String, Object>> entitlement,
                              Map<String, Object> workload, String cnfThumbprint) {
        this(subject, clientId, entitlement, workload, cnfThumbprint, null);
    }

    public AttestationSubject(String subject, String clientId, List<Map<String, Object>> entitlement,
                              Map<String, Object> workload, String cnfThumbprint, String agentId) {
        this(subject, clientId, entitlement, workload, cnfThumbprint, agentId, null, null);
    }

    public AttestationSubject(String subject, String clientId, List<Map<String, Object>> entitlement,
                              Map<String, Object> workload, String cnfThumbprint, String agentId,
                              String attesterIssuer, String verifiedSubjectTokenSubject) {
        this(subject, clientId, entitlement, workload, cnfThumbprint, agentId, attesterIssuer,
                verifiedSubjectTokenSubject, null, false);
    }

    /**
     * Every member, and whether the attestation filter published a context at all: {@link #fromAttribute} is the
     * one caller that knows, because it saw the request attribute.
     */
    AttestationSubject(String subject, String clientId, List<Map<String, Object>> entitlement,
                       Map<String, Object> workload, String cnfThumbprint, String agentId,
                       String attesterIssuer, String verifiedSubjectTokenSubject,
                       String rarModelsFingerprint, boolean contextPresent) {
        this.subject = subject;
        this.clientId = clientId;
        this.entitlement = entitlement == null ? List.of() : entitlement;
        this.workload = workload == null ? Map.of() : workload;
        this.cnfThumbprint = cnfThumbprint;
        this.agentId = agentId;
        this.attesterIssuer = attesterIssuer;
        this.verifiedSubjectTokenSubject = verifiedSubjectTokenSubject;
        this.rarModelsFingerprint = rarModelsFingerprint;
        this.contextPresent = contextPresent;
    }

    public String getSubject() { return subject; }
    public String getClientId() { return clientId; }
    public List<Map<String, Object>> getEntitlement() { return entitlement; }
    public Map<String, Object> getWorkload() { return workload; }
    public String getCnfThumbprint() { return cnfThumbprint; }

    /** The attester-minted identifier of the specific running instance, or {@code null} if none was minted. */
    public String getAgentId() { return agentId; }

    /** The attester's own issuer, the {@code iss} of the attestation the filter verified; {@code null} if unknown. */
    public String getAttesterIssuer() { return attesterIssuer; }

    /** The verified subject of a token-exchange subject token, or {@code null}: see {@link #VERIFIED_SUBJECT_TOKEN_KEY}. */
    public String getVerifiedSubjectTokenSubject() { return verifiedSubjectTokenSubject; }

    /**
     * The filter's {@code RarModels.fingerprint()} ({@link #RAR_MODELS_FINGERPRINT_KEY}), or {@code null} when the
     * context carries none, or carries something other than a non-blank string.
     */
    public String getRarModelsFingerprint() { return rarModelsFingerprint; }

    /**
     * Whether the request carried an attestation context at all - the filter verified an attestation on it - as
     * opposed to a request the filter never saw. A context that is there but unreadable counts as there.
     */
    public boolean isContextPresent() { return contextPresent; }

    /** This context with a different agent id and the rest unchanged. */
    public AttestationSubject withAgentId(String newAgentId) {
        return new AttestationSubject(subject, clientId, entitlement, workload, cnfThumbprint, newAgentId,
                attesterIssuer, verifiedSubjectTokenSubject, rarModelsFingerprint, contextPresent);
    }

    public boolean isPresent() {
        return subject != null || clientId != null || !entitlement.isEmpty();
    }

    public static AttestationSubject empty() {
        return new AttestationSubject(null, null, List.of(), Map.of(), null, null, null, null, null, false);
    }

    /**
     * Parses whatever the hook stashed on the request. Accepts a {@code Map} with keys {@code sub}/{@code subject},
     * {@code client_id}, {@code entitlement}/{@code authorization_details}, {@code workload},
     * {@code cnf_thumbprint}, {@code agent_id}, {@code iss}, {@link #VERIFIED_SUBJECT_TOKEN_KEY} and
     * {@link #RAR_MODELS_FINGERPRINT_KEY}. {@code null} - no context - is {@link #empty()}. Anything else that is not
     * a {@code Map} is a context that is there and says nothing: no member is read from it, and it still counts as
     * present, so the fingerprint comparison refuses it rather than treating the request as one the filter never saw.
     */
    @SuppressWarnings("unchecked")
    public static AttestationSubject fromAttribute(Object attr) {
        if (attr == null) {
            return empty();
        }
        if (!(attr instanceof Map)) {
            return new AttestationSubject(null, null, List.of(), Map.of(), null, null, null, null, null, true);
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
        String agentId = str(m.get("agent_id"));
        String iss = str(m.get("iss"));
        String subjectTokenSub = str(m.get(VERIFIED_SUBJECT_TOKEN_KEY));
        Object fingerprint = m.get(RAR_MODELS_FINGERPRINT_KEY);
        String rarModels = fingerprint instanceof String f && !f.isBlank() ? f : null;
        return new AttestationSubject(sub, clientId, ent, workload, cnf, agentId, iss, subjectTokenSub, rarModels, true);
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
        if (o == null) {
            return null;
        }
        String s = String.valueOf(o);
        return s.isBlank() ? null : s;
    }
}
