/*
 * IssuanceClientResolver backed by a Client ID Metadata Document (CIMD): a hosted JSON document that
 * maps SPIFFE IDs to OAuth clients. The attester fetches it; the workload never sees it.
 */
package com.pingidentity.ps.oidf.common;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;

/**
 * Resolves the attester's clients from a <strong>Client ID Metadata Document</strong> fetched by URL,
 * rather than from PingFederate's client store. The document externalizes the attester's private mapping
 * — <em>which SPIFFE identity belongs to which OAuth client</em> — so it can live in git / a hosted file
 * and be changed without touching the AS. The workload still presents only its evidence; this resolver is
 * simply where the attester looks up the answer.
 *
 * <p>Document shape (fetched from {@code cimdUrl}):
 * <pre>
 * { "spiffe_mappings": [
 *     { "spiffe_id": "spiffe://railway.demo/workload/payment-agent",
 *       "client_id": "demo-attest-railway",
 *       "evidence_type": "spiffe-jwt",
 *       "issuer": "https://attester.example.com",
 *       "trust_domain": "railway.demo",
 *       "bundle": { "keys": [ ... ] },            // or "bundle_url": "https://…/jwks"
 *       "evidence_issuer": "https://…",            // optional (gke-sa-token / gcp-id-token)
 *       "entitlement": [ { "type": "sales_agent", "sales_regions": ["EMEA"] } ],
 *       "ttl": 300,
 *       "signing_jwk": { ... }                     // or "signing_key_ref": "attestation-es256"
 *     } ] }
 * </pre>
 * Each mapping becomes one {@link AttesterClient} whose {@link AttestationIssuanceConfig} carries a single
 * binding for the mapped SPIFFE ID. The result is cached for a short TTL (the document changes rarely);
 * a fetch failure after the first success serves the stale copy rather than dropping all clients.
 */
public final class CimdClientResolver implements IssuanceClientResolver {

    public static final long DEFAULT_TTL_SECONDS = 300L;

    private final String cimdUrl;
    private final HttpGetClient http;
    private final long ttlSeconds;
    private final String defaultSigningJwk;

    private volatile List<AttesterClient> cached;
    private volatile long cachedAtEpochSeconds;

    public CimdClientResolver(String cimdUrl) {
        this(cimdUrl, new JdkHttpGetClient(false), DEFAULT_TTL_SECONDS, null);
    }

    public CimdClientResolver(String cimdUrl, String defaultSigningJwk) {
        this(cimdUrl, new JdkHttpGetClient(false), DEFAULT_TTL_SECONDS, defaultSigningJwk);
    }

    public CimdClientResolver(String cimdUrl, HttpGetClient http, long ttlSeconds) {
        this(cimdUrl, http, ttlSeconds, null);
    }

    /**
     * @param defaultSigningJwk the attester's signing key (inline private JWK), applied to CIMD entries
     *                          that specify none. The attester key is a deployment secret and must NOT
     *                          live in the public CIMD document — it is configured here instead.
     */
    public CimdClientResolver(String cimdUrl, HttpGetClient http, long ttlSeconds, String defaultSigningJwk) {
        this.cimdUrl = cimdUrl;
        this.http = http;
        this.ttlSeconds = ttlSeconds;
        this.defaultSigningJwk = defaultSigningJwk;
    }

    @Override
    public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
        for (AttesterClient c : attestationClients()) {
            if (c.clientId().equals(clientId)) {
                return c.config();
            }
        }
        throw IssuanceException.invalidClient("unknown client: " + clientId);
    }

    @Override
    public List<AttesterClient> attestationClients() throws IssuanceException {
        long now = System.currentTimeMillis() / 1000L;
        List<AttesterClient> local = this.cached;
        if (local != null && now - this.cachedAtEpochSeconds < this.ttlSeconds) {
            return local;
        }
        String body;
        try {
            body = this.http.get(this.cimdUrl, "application/json");
        } catch (Exception e) {
            if (local != null) {
                return local; // stale-on-error: the document was valid recently
            }
            throw IssuanceException.serverError("client-id metadata document could not be fetched: " + this.cimdUrl);
        }
        List<AttesterClient> parsed = parse(body);
        this.cached = parsed;
        this.cachedAtEpochSeconds = now;
        return parsed;
    }

    @SuppressWarnings("unchecked")
    private List<AttesterClient> parse(String body) throws IssuanceException {
        Map<String, Object> doc;
        try {
            doc = JsonUtil.parseJson(body);
        } catch (Exception e) {
            throw IssuanceException.serverError("client-id metadata document is not valid JSON");
        }
        Object mappings = doc.get("spiffe_mappings");
        if (!(mappings instanceof List)) {
            throw IssuanceException.serverError("client-id metadata document has no 'spiffe_mappings' array");
        }
        List<AttesterClient> out = new ArrayList<>();
        for (Object item : (List<Object>) mappings) {
            if (!(item instanceof Map)) {
                continue;
            }
            Map<String, Object> entry = (Map<String, Object>) item;
            String clientId = str(entry.get("client_id"));
            String spiffeId = str(entry.get("spiffe_id"));
            if (clientId == null || spiffeId == null) {
                continue; // a mapping needs both ends
            }
            out.add(new AttesterClient(clientId, toConfig(entry, spiffeId, this.defaultSigningJwk)));
        }
        return out;
    }

    /** Projects a CIMD mapping entry onto the {@code attestation_*} property map an issuance config parses. */
    private static AttestationIssuanceConfig toConfig(Map<String, Object> entry, String spiffeId,
            String defaultSigningJwk) throws IssuanceException {
        Map<String, String> props = new LinkedHashMap<>();
        putIf(props, AttestationIssuanceConfig.P_ISSUER, str(entry.get("issuer")));
        putIf(props, AttestationIssuanceConfig.P_EVIDENCE, str(entry.get("evidence_type")));
        putIf(props, AttestationIssuanceConfig.P_TRUST_DOMAIN, str(entry.get("trust_domain")));
        putIf(props, AttestationIssuanceConfig.P_EVIDENCE_ISSUER, str(entry.get("evidence_issuer")));
        putIf(props, AttestationIssuanceConfig.P_BUNDLE_URL, str(entry.get("bundle_url")));
        putIf(props, AttestationIssuanceConfig.P_BUNDLE, json(entry.get("bundle")));
        // The attester's signing key comes from deployment config, not the public CIMD. A per-entry
        // signing_key_ref (a vault key name, not a secret) is still honoured if present.
        putIf(props, AttestationIssuanceConfig.P_SIGNING_JWK, defaultSigningJwk);
        putIf(props, AttestationIssuanceConfig.P_SIGNING_KEY_REF, str(entry.get("signing_key_ref")));
        Object ttl = entry.get("ttl");
        if (ttl != null) {
            props.put(AttestationIssuanceConfig.P_TTL, String.valueOf(((Number) ttl).longValue()));
        }
        // The one binding this mapping declares: the SPIFFE ID and its entitlement ceiling.
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
        // P_INSTANCES is a JSON array; wrap the single binding and serialize via a Map (jose4j's toJson
        // takes a Map) by nesting under a throwaway key, then slice the array out.
        Map<String, Object> arrayHolder = new LinkedHashMap<>();
        arrayHolder.put("v", List.of(binding));
        String holderJson = JsonUtil.toJson(arrayHolder);
        String instancesJson = holderJson.substring(holderJson.indexOf(':') + 1, holderJson.lastIndexOf('}'));
        props.put(AttestationIssuanceConfig.P_INSTANCES, instancesJson);
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
            return null; // only object-shaped fields (bundle, signing_jwk) are stringified this way
        }
        return JsonUtil.toJson((Map<String, Object>) o);
    }
}
