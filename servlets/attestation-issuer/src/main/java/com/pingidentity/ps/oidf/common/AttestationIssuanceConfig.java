/*
 * Per-client configuration for the attestation issuance endpoint, parsed from extended properties.
 */
package com.pingidentity.ps.oidf.common;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

/**
 * Typed view of a client's attestation-issuance configuration, parsed from its {@code attestation_*}
 * extended properties. Holds the attester identity, the SPIFFE trust bundle used to validate SVIDs, the
 * signer selection (OpenBao transit key reference or inline JWK), the issued-attestation TTL, an optional
 * client-level RFC 9396 entitlement ceiling, and the one-to-many list of {@link SpiffeBinding}s.
 *
 * <p>This class is pure data + parsing (no PingFederate types), so it is unit-testable offline. In the
 * runtime a resolver reads the properties off a PF {@code Client} and calls {@link #fromProperties}; the
 * <em>source</em> of the bundle is that resolver's concern (an inline JWKS today, federation metadata
 * later) — the validation and minting downstream never change.
 */
public final class AttestationIssuanceConfig {

    // Extended-property keys (the OGNL hook sees these under the "extproperties." namespace).
    public static final String P_ISSUER = "attestation_issuer";
    public static final String P_TTL = "attestation_issued_ttl";
    public static final String P_BUNDLE = "attestation_spiffe_bundle";
    public static final String P_ENTITLEMENT = "attestation_entitlement";
    public static final String P_SIGNING_KEY_REF = "attestation_signing_key_ref";
    public static final String P_SIGNING_JWK = "attestation_signing_jwk";
    public static final String P_INSTANCES = "attestation_instances";
    public static final String P_TRUST_DOMAIN = "attestation_trust_domain";
    public static final String P_EVIDENCE = "attestation_evidence";
    public static final String P_BUNDLE_URL = "attestation_bundle_url";
    public static final String P_EVIDENCE_ISSUER = "attestation_evidence_issuer";

    /** Evidence type: a SPIFFE JWT-SVID (the default). */
    public static final String EVIDENCE_SPIFFE_JWT = "spiffe-jwt";
    /** Evidence type: a GKE-projected Kubernetes service-account token (Google-native identity). */
    public static final String EVIDENCE_GKE_SA_TOKEN = "gke-sa-token";
    /** Evidence type: a Google-signed GCP service-account ID token (Agent Engine / Cloud Run / GCE). */
    public static final String EVIDENCE_GCP_ID_TOKEN = "gcp-id-token";
    /** Evidence type: an EKS-projected Kubernetes service-account token (IRSA). */
    public static final String EVIDENCE_EKS_SA_TOKEN = "eks-sa-token";
    /** Evidence type: an AWS-signed OIDC token from {@code sts:GetWebIdentityToken} (any AWS workload,
     *  including Bedrock AgentCore). */
    public static final String EVIDENCE_AWS_STS_WEB_IDENTITY = "aws-sts-web-identity";
    /** Evidence type: a digital wallet's Wallet Instance Attestation, signed by its Wallet Provider. */
    public static final String EVIDENCE_WALLET_INSTANCE_ATTESTATION = "wallet-instance-attestation";

    public static final long DEFAULT_TTL_SECONDS = 300L;

    private final String issuer;
    private final long ttlSeconds;
    private final List<JsonWebKey> bundleKeys;
    private final List<Map<String, Object>> clientCeiling;
    private final String signingKeyRef;
    private final Map<String, Object> signingJwk;
    private final String expectedTrustDomain;
    private final List<SpiffeBinding> bindings;
    private final String evidenceType;
    private final String bundleUrl;
    private final String evidenceIssuer;

    private AttestationIssuanceConfig(String issuer, long ttlSeconds, List<JsonWebKey> bundleKeys,
                                      List<Map<String, Object>> clientCeiling, String signingKeyRef,
                                      Map<String, Object> signingJwk, String expectedTrustDomain,
                                      List<SpiffeBinding> bindings, String evidenceType, String bundleUrl,
                                      String evidenceIssuer) {
        this.issuer = issuer;
        this.ttlSeconds = ttlSeconds;
        this.bundleKeys = bundleKeys;
        this.clientCeiling = clientCeiling;
        this.signingKeyRef = signingKeyRef;
        this.signingJwk = signingJwk;
        this.expectedTrustDomain = expectedTrustDomain;
        this.bindings = bindings;
        this.evidenceType = evidenceType;
        this.bundleUrl = bundleUrl;
        this.evidenceIssuer = evidenceIssuer;
    }

    /**
     * Parses the {@code attestation_*} property map into a config, validating the required shape.
     *
     * @throws IssuanceException {@code invalid_client} if a required property is missing or malformed
     */
    public static AttestationIssuanceConfig fromProperties(Map<String, String> props) throws IssuanceException {
        String issuer = trimmed(props.get(P_ISSUER));
        if (issuer == null) {
            throw IssuanceException.invalidClient("missing " + P_ISSUER);
        }
        long ttl = DEFAULT_TTL_SECONDS;
        String ttlRaw = trimmed(props.get(P_TTL));
        if (ttlRaw != null) {
            try {
                ttl = Long.parseLong(ttlRaw);
            } catch (NumberFormatException e) {
                throw IssuanceException.invalidClient(P_TTL + " is not a number: " + ttlRaw);
            }
            if (ttl <= 0) {
                throw IssuanceException.invalidClient(P_TTL + " must be positive");
            }
        }

        // What a given evidence type is and requires is the validator's own declaration — see
        // InstanceAttestationValidators. Nothing about the supported set is restated here.
        InstanceAttestationValidators known = InstanceAttestationValidators.defaults();
        String evidenceType = trimmed(props.get(P_EVIDENCE));
        if (evidenceType == null) {
            evidenceType = EVIDENCE_SPIFFE_JWT;
        } else if (!known.supports(evidenceType)) {
            throw IssuanceException.invalidClient(P_EVIDENCE + " is not a supported evidence type: " + evidenceType);
        }

        // The bundle source: an inline JWKS, or a URL fetched (and cached) at issuance time. Formats that
        // establish trust elsewhere (a wallet WIA trusts its provider) need none.
        String bundleUrl = trimmed(props.get(P_BUNDLE_URL));
        String bundleJson = trimmed(props.get(P_BUNDLE));
        if (bundleJson == null && bundleUrl == null && known.requiresTrustBundle(evidenceType)) {
            throw IssuanceException.invalidClient(
                    "missing " + P_BUNDLE + " or " + P_BUNDLE_URL + " (trust bundle source)");
        }
        List<JsonWebKey> bundleKeys = List.of();
        if (bundleJson != null) {
            try {
                bundleKeys = new JsonWebKeySet(bundleJson).getJsonWebKeys();
            } catch (JoseException e) {
                throw IssuanceException.invalidClient(P_BUNDLE + " is not a valid JWKS");
            }
            if (bundleKeys.isEmpty()) {
                throw IssuanceException.invalidClient(P_BUNDLE + " carries no keys");
            }
        }

        List<Map<String, Object>> ceiling = parseAuthDetails(trimmed(props.get(P_ENTITLEMENT)), P_ENTITLEMENT);
        String signingKeyRef = trimmed(props.get(P_SIGNING_KEY_REF));
        Map<String, Object> signingJwk = parseObject(trimmed(props.get(P_SIGNING_JWK)), P_SIGNING_JWK);
        String trustDomain = trimmed(props.get(P_TRUST_DOMAIN));
        if (known.requiresTrustDomain(evidenceType) && trustDomain == null) {
            // The mapped SPIFFE ID's namespace comes from the trust domain; without it the binding
            // identifiers would be unanchored.
            throw IssuanceException.invalidClient(P_TRUST_DOMAIN + " is required when " + P_EVIDENCE
                    + " is " + evidenceType);
        }
        String evidenceIssuer = trimmed(props.get(P_EVIDENCE_ISSUER));
        List<SpiffeBinding> bindings = parseInstances(trimmed(props.get(P_INSTANCES)), ceiling);

        return new AttestationIssuanceConfig(issuer, ttl, bundleKeys, ceiling, signingKeyRef, signingJwk,
                trustDomain, bindings, evidenceType, bundleUrl, evidenceIssuer);
    }

    public String issuer() {
        return this.issuer;
    }

    public long ttlSeconds() {
        return this.ttlSeconds;
    }

    public List<JsonWebKey> bundleKeys() {
        return this.bundleKeys;
    }

    /** The client-level entitlement ceiling; empty if none configured. */
    public List<Map<String, Object>> clientCeiling() {
        return this.clientCeiling;
    }

    public String signingKeyRef() {
        return this.signingKeyRef;
    }

    public Map<String, Object> signingJwk() {
        return this.signingJwk;
    }

    /** The expected SVID trust domain, if the client pins one; else null (any). */
    public String expectedTrustDomain() {
        return this.expectedTrustDomain;
    }

    public List<SpiffeBinding> bindings() {
        return this.bindings;
    }

    /** The evidence type this client presents ({@link #EVIDENCE_SPIFFE_JWT} unless configured otherwise). */
    public String evidenceType() {
        return this.evidenceType;
    }

    /** The trust-bundle JWKS URL, if the client's bundle is fetched rather than inline; else null. */
    public String bundleUrl() {
        return this.bundleUrl;
    }

    /** The pinned evidence {@code iss} (e.g. the GKE cluster issuer URL), if configured; else null. */
    public String evidenceIssuer() {
        return this.evidenceIssuer;
    }

    /** Finds the binding for a validated SPIFFE ID, or empty if the id is not registered for this client. */
    public Optional<SpiffeBinding> bindingFor(String spiffeId) {
        for (SpiffeBinding b : this.bindings) {
            if (b.spiffeId().equals(spiffeId)) {
                return Optional.of(b);
            }
        }
        return Optional.empty();
    }

    /** The effective entitlement ceiling for a binding: its own if set, else the client-level ceiling. */
    public List<Map<String, Object>> effectiveCeiling(SpiffeBinding binding) {
        return binding.entitlement().isEmpty() ? this.clientCeiling : binding.entitlement();
    }

    private static List<SpiffeBinding> parseInstances(String json, List<Map<String, Object>> clientCeiling)
            throws IssuanceException {
        if (json == null) {
            return List.of();
        }
        Object parsed;
        try {
            parsed = JsonUtil.parseJson("{\"v\":" + json + "}").get("v");
        } catch (JoseException e) {
            throw IssuanceException.invalidClient(P_INSTANCES + " is not valid JSON");
        }
        if (!(parsed instanceof List)) {
            throw IssuanceException.invalidClient(P_INSTANCES + " must be a JSON array");
        }
        List<SpiffeBinding> out = new ArrayList<>();
        for (Object item : (List<?>) parsed) {
            if (!(item instanceof Map)) {
                throw IssuanceException.invalidClient(P_INSTANCES + " entries must be JSON objects");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> entry = (Map<String, Object>) item;
            // The instance subject: a SPIFFE ID, or a wallet instance id. Accept any of the aliases so a
            // wallet binding reads naturally; they populate the same format-neutral binding subject.
            Object idValue = entry.get("spiffe_id");
            if (idValue == null) {
                idValue = entry.get("subject");
            }
            if (idValue == null) {
                idValue = entry.get("wallet_instance");
            }
            String subject = idValue == null ? null : String.valueOf(idValue).trim();
            if (subject == null || subject.isBlank()) {
                throw IssuanceException.invalidClient(
                        P_INSTANCES + " entry is missing an instance id (spiffe_id / subject / wallet_instance)");
            }
            List<Map<String, Object>> entitlement = asObjectList(entry.get("entitlement"), "entitlement");
            Map<String, Object> metadata = asObject(entry.get("metadata"), "metadata");
            // Defense: a per-instance entitlement must sit within the client-level ceiling.
            if (!entitlement.isEmpty() && clientCeiling != null && !clientCeiling.isEmpty()) {
                try {
                    RarEntitlement.authorize(entitlement, clientCeiling);
                } catch (ClientAttestationException e) {
                    throw IssuanceException.invalidClient(
                            "instance '" + subject + "' entitlement exceeds the client-level ceiling");
                }
            }
            out.add(new SpiffeBinding(subject, entitlement, metadata));
        }
        return out;
    }

    private static List<Map<String, Object>> parseAuthDetails(String json, String field) throws IssuanceException {
        if (json == null) {
            return List.of();
        }
        try {
            return RarEntitlement.parseArray(json);
        } catch (ClientAttestationException e) {
            throw IssuanceException.invalidClient(field + " is not a valid authorization_details array");
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> asObjectList(Object value, String field) throws IssuanceException {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List)) {
            throw IssuanceException.invalidClient(P_INSTANCES + " '" + field + "' must be a JSON array");
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (!(item instanceof Map)) {
                throw IssuanceException.invalidClient(P_INSTANCES + " '" + field + "' entries must be JSON objects");
            }
            out.add((Map<String, Object>) item);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object value, String field) throws IssuanceException {
        if (value == null) {
            return Map.of();
        }
        if (!(value instanceof Map)) {
            throw IssuanceException.invalidClient(P_INSTANCES + " '" + field + "' must be a JSON object");
        }
        return (Map<String, Object>) value;
    }

    private static Map<String, Object> parseObject(String json, String field) throws IssuanceException {
        if (json == null) {
            return null;
        }
        try {
            return JsonUtil.parseJson(json);
        } catch (JoseException e) {
            throw IssuanceException.invalidClient(field + " is not a valid JSON object");
        }
    }

    private static String trimmed(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}
