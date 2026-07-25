/*
 * Shared: project one SPIFFE-ID → client mapping entry onto an AttestationIssuanceConfig.
 */
package com.pingidentity.ps.oidf.common;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;

/**
 * Turns a single mapping entry — {@code spiffe_id}, {@code client_id}, evidence trust config and an
 * {@code entitlement} ceiling — into an {@link AttestationIssuanceConfig} with one binding. Shared by the
 * {@link CimdClientResolver} (entries from a hosted JSON document) and the
 * {@link OpenIdFederationClientResolver} (entries from a signed federation entity statement), so both
 * mapping sources produce identical issuance configs. The attester signing key is supplied by deployment
 * config ({@code defaultSigningJwk}) and never read from the (public) mapping document.
 */
final class CimdMapping {

    private CimdMapping() {
    }

    static AttestationIssuanceConfig toConfig(Map<String, Object> entry, String spiffeId, String defaultSigningJwk)
            throws IssuanceException {
        Map<String, String> props = new LinkedHashMap<>();
        putIf(props, AttestationIssuanceConfig.P_ISSUER, str(entry.get("issuer")));
        putIf(props, AttestationIssuanceConfig.P_EVIDENCE, str(entry.get("evidence_type")));
        putIf(props, AttestationIssuanceConfig.P_TRUST_DOMAIN, str(entry.get("trust_domain")));
        putIf(props, AttestationIssuanceConfig.P_EVIDENCE_ISSUER, str(entry.get("evidence_issuer")));
        putIf(props, AttestationIssuanceConfig.P_BUNDLE_URL, str(entry.get("bundle_url")));
        putIf(props, AttestationIssuanceConfig.P_BUNDLE, json(entry.get("bundle")));
        putIf(props, AttestationIssuanceConfig.P_SIGNING_JWK, defaultSigningJwk);
        putIf(props, AttestationIssuanceConfig.P_SIGNING_KEY_REF, str(entry.get("signing_key_ref")));
        Object ttl = entry.get("ttl");
        if (ttl instanceof Number) {
            props.put(AttestationIssuanceConfig.P_TTL, String.valueOf(((Number) ttl).longValue()));
        }
        // The one binding this entry declares: the SPIFFE ID, its entitlement ceiling, and any metadata
        // (workload attributes carried into the attestation).
        Map<String, Object> binding = new LinkedHashMap<>();
        binding.put("spiffe_id", spiffeId);
        Object entitlement = entry.get("entitlement");
        if (entitlement instanceof List) {
            binding.put("entitlement", entitlement);
        }
        Object metadata = entry.get("metadata");
        if (metadata instanceof Map) {
            binding.put("metadata", metadata);
        }
        props.put(AttestationIssuanceConfig.P_INSTANCES, jsonArray(List.of(binding)));
        return AttestationIssuanceConfig.fromProperties(props);
    }

    private static void putIf(Map<String, String> props, String key, String value) {
        if (value != null && !value.isBlank()) {
            props.put(key, value);
        }
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    @SuppressWarnings("unchecked")
    private static String json(Object o) {
        if (!(o instanceof Map)) {
            return null;
        }
        return JsonUtil.toJson((Map<String, Object>) o);
    }

    /** Serializes a List to a JSON array string (jose4j's toJson takes a Map, so wrap-and-slice). */
    private static String jsonArray(List<?> list) {
        Map<String, Object> holder = new LinkedHashMap<>();
        holder.put("v", list);
        String json = JsonUtil.toJson(holder);
        return json.substring(json.indexOf(':') + 1, json.lastIndexOf('}'));
    }
}
