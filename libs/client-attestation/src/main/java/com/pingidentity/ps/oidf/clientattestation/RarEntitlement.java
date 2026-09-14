/*
 * RFC 9396 Rich Authorization Requests — attestation-bound entitlement checking.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

/**
 * Enforces an entitlement ceiling carried in the Client Attestation as an
 * <a href="https://www.rfc-editor.org/rfc/rfc9396">RFC 9396</a> {@code authorization_details} array.
 *
 * <p>The attester vouches for what the client (e.g. a sales agent) is entitled to — for instance a
 * {@code sales_agent} entitlement limited to a {@code sales_regions} of {@code ["EMEA"]}. At the token
 * request the client presents its own {@code authorization_details}; a request is authorized only if
 * every requested detail is <em>contained within</em> some attested detail of the same {@code type}:
 * for each set-valued field the entitlement specifies, the requested values must be a subset. Fields
 * the entitlement omits are unconstrained.
 *
 * <p>A field the entitlement constrains and the request <em>omits</em> is inherited into the grant: the
 * granted detail carries the entitlement's values for it. Silence on a field is a request for the whole
 * of what the ceiling allows there, never for more than it. Granting the request verbatim used to turn
 * an EMEA-only {@code sales_agent} into a {@code sales_agent} with no region at all, which everything
 * downstream reads as "any region" — narrowing by omission produced a wider grant than the ceiling
 * (CAS §7: the issued details MUST be a subset of the ceiling).
 */
public final class RarEntitlement {
    private RarEntitlement() {
    }

    /** Set-valued fields compared as subsets when present in the entitled detail. */
    private static final String[] SET_FIELDS = {"actions", "locations", "datatypes", "privileges", "sales_regions"};

    /**
     * Authorizes requested {@code authorization_details} against the attested entitlement.
     *
     * @param requested the token request's {@code authorization_details} (may be null/empty)
     * @param entitled  the attestation's asserted entitlement (may be null/empty)
     * @return the granted {@code authorization_details}: each requested detail, with any set-valued
     *         field the matching entitlement constrains and the request omitted filled in from the
     *         entitlement; empty if none requested
     * @throws ClientAttestationException {@code access_denied} if the request exceeds the entitlement,
     *                                    {@code invalid_authorization_details} if a request entry is malformed
     */
    public static List<Map<String, Object>> authorize(List<Map<String, Object>> requested,
                                                       List<Map<String, Object>> entitled)
            throws ClientAttestationException {
        if (requested == null || requested.isEmpty()) {
            return List.of();
        }
        if (entitled == null || entitled.isEmpty()) {
            throw ClientAttestationException.accessDenied(
                    "authorization_details requested but the attestation asserts no entitlement");
        }
        List<Map<String, Object>> granted = new ArrayList<>(requested.size());
        for (Map<String, Object> req : requested) {
            String type = str(req.get("type"));
            if (type == null || type.isBlank()) {
                throw ClientAttestationException.invalidAuthorizationDetails(
                        "authorization_details entry is missing its 'type'");
            }
            Map<String, Object> ceiling = findContaining(req, type, entitled);
            if (ceiling == null) {
                throw ClientAttestationException.accessDenied(
                        "requested authorization_details of type '" + type + "' exceeds the attested entitlement");
            }
            granted.add(narrowedTo(req, ceiling));
        }
        return granted;
    }

    /**
     * The requested detail with every {@link #SET_FIELDS set-valued field} the ceiling constrains and
     * the request omits copied in from the ceiling. Fields the request names are already known to be
     * within the ceiling ({@link #within}) and are kept as requested.
     */
    private static Map<String, Object> narrowedTo(Map<String, Object> req, Map<String, Object> ceiling) {
        LinkedHashMap<String, Object> out = new LinkedHashMap<>(req);
        for (String field : SET_FIELDS) {
            if (ceiling.containsKey(field) && !req.containsKey(field)) {
                out.put(field, ceiling.get(field));
            }
        }
        return out;
    }

    private static Map<String, Object> findContaining(Map<String, Object> req, String type,
                                                       List<Map<String, Object>> entitled) {
        for (Map<String, Object> ent : entitled) {
            if (type.equals(str(ent.get("type"))) && within(req, ent)) {
                return ent;
            }
        }
        return null;
    }

    /** True when every SET_FIELD the entitlement specifies is a superset of the request's values. */
    private static boolean within(Map<String, Object> req, Map<String, Object> ent) {
        for (String field : SET_FIELDS) {
            if (ent.containsKey(field) && !asStrings(ent.get(field)).containsAll(asStrings(req.get(field)))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Parses an {@code authorization_details} JSON array (as sent on the token request) into a list of
     * objects. Returns empty for null/blank. Uses jose4j by wrapping the array in an object.
     */
    public static List<Map<String, Object>> parseArray(String json) throws ClientAttestationException {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            Object value = JsonUtil.parseJson("{\"v\":" + json + "}").get("v");
            return asObjectList(value);
        } catch (JoseException e) {
            throw ClientAttestationException.invalidAuthorizationDetails("authorization_details is not valid JSON");
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> asObjectList(Object value) throws ClientAttestationException {
        if (!(value instanceof List)) {
            throw ClientAttestationException.invalidAuthorizationDetails("authorization_details must be a JSON array");
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (!(item instanceof Map)) {
                throw ClientAttestationException.invalidAuthorizationDetails(
                        "each authorization_details entry must be a JSON object");
            }
            out.add((Map<String, Object>) item);
        }
        return out;
    }

    private static List<String> asStrings(Object value) {
        ArrayList<String> out = new ArrayList<>();
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

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }
}
