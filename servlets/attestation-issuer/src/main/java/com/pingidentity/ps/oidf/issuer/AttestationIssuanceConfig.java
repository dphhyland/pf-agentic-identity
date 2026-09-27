/*
 * Per-client configuration for the attestation issuance endpoint, parsed from extended properties.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.rar.model.Json;
import com.pingidentity.ps.oidf.rar.model.Omission;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;

/**
 * Typed view of a client's attestation-issuance configuration, parsed from its {@code attestation_*}
 * extended properties. Holds the attester identity, the SPIFFE trust bundle used to validate SVIDs, the
 * signer selection (OpenBao transit key reference or inline JWK), the issued-attestation TTL, an optional
 * client-level RFC 9396 entitlement ceiling, and the one-to-many list of {@link SpiffeBinding}s.
 *
 * <p>Both ceilings are read by the containment model's own reader ({@code libs/rar-model}), so a limit is
 * compared exactly as configured, and held to the model when the configuration is parsed: a ceiling the model
 * refuses - a type with no model, an undeclared field, a value its rule cannot compare - makes the client's
 * configuration invalid here, rather than failing every issuance later. An instance's ceiling is
 * {@code authorize(instance, client, INHERIT)}: it must sit within the client's, and it is kept as authorized,
 * with every field the client's ceiling constrains and the instance's leaves out filled from the client's
 * (CAS §7: "instances[i].entitlement ⊆ entitlement MUST hold at registration time").
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
    /** Opts a client into a second-stage {@link AssertedContextResolver}, named by id; absent = feature off. */
    public static final String P_ASSERTED_CONTEXT_RESOLVER = "attestation_asserted_context_resolver";

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
    /** Evidence type: an AKS-projected Kubernetes service-account token (Azure Workload Identity Federation). */
    public static final String EVIDENCE_AKS_SA_TOKEN = "aks-sa-token";
    /** Evidence type: an Entra-signed Azure managed-identity token (Container Apps / VM / Functions), obtained
     *  from Azure IMDS. */
    public static final String EVIDENCE_AZURE_MI_TOKEN = "azure-mi-token";
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
    private final String assertedContextResolverId;

    private AttestationIssuanceConfig(String issuer, long ttlSeconds, List<JsonWebKey> bundleKeys,
                                      List<Map<String, Object>> clientCeiling, String signingKeyRef,
                                      Map<String, Object> signingJwk, String expectedTrustDomain,
                                      List<SpiffeBinding> bindings, String evidenceType, String bundleUrl,
                                      String evidenceIssuer, String assertedContextResolverId) {
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
        this.assertedContextResolverId = assertedContextResolverId;
    }

    /**
     * Parses the {@code attestation_*} property map into a config, validating the required shape, with this
     * classloader's containment models ({@link AttestationRarModels}).
     *
     * @throws IssuanceException {@code invalid_client} if a required property is missing or malformed;
     *                           {@code server_error} if the containment models could not be loaded
     */
    public static AttestationIssuanceConfig fromProperties(Map<String, String> props) throws IssuanceException {
        RarModels models;
        try {
            models = AttestationRarModels.get();
        } catch (RarModelException e) {
            throw IssuanceException.serverError("the RAR containment models could not be loaded: " + e.getMessage());
        }
        return fromProperties(props, models);
    }

    /**
     * As {@link #fromProperties(Map)}, holding the ceilings to the model set given.
     *
     * @throws IssuanceException {@code invalid_client} if a required property is missing or malformed, or a
     *                           ceiling is one the model refuses
     */
    public static AttestationIssuanceConfig fromProperties(Map<String, String> props, RarModels models)
            throws IssuanceException {
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

        List<Map<String, Object>> ceiling = clientCeiling(trimmed(props.get(P_ENTITLEMENT)), models);
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
        List<SpiffeBinding> bindings = parseInstances(trimmed(props.get(P_INSTANCES)), ceiling, models);
        String assertedContextResolverId = trimmed(props.get(P_ASSERTED_CONTEXT_RESOLVER));

        return new AttestationIssuanceConfig(issuer, ttl, bundleKeys, ceiling, signingKeyRef, signingJwk,
                trustDomain, bindings, evidenceType, bundleUrl, evidenceIssuer, assertedContextResolverId);
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

    /** The {@link AssertedContextResolver} id this client opts into, if any; null = feature off (default). */
    public String assertedContextResolverId() {
        return this.assertedContextResolverId;
    }

    /**
     * Finds the archetype matching a validated instance subject, or empty if none of this client's
     * {@link SpiffeBinding} entries match. More than one archetype may match the same subject (an exact
     * entry alongside a covering wildcard); the most specific match wins — see
     * {@link SpiffeBinding#specificity()} — so a wildcard archetype never shadows an instance's own,
     * more specific entry.
     */
    public Optional<SpiffeBinding> bindingFor(String subject) {
        SpiffeBinding best = null;
        for (SpiffeBinding b : this.bindings) {
            if (b.matches(subject) && (best == null || b.specificity() > best.specificity())) {
                best = b;
            }
        }
        return Optional.ofNullable(best);
    }

    /** The effective entitlement ceiling for a binding: its own if set, else the client-level ceiling. */
    public List<Map<String, Object>> effectiveCeiling(SpiffeBinding binding) {
        return binding.entitlement().isEmpty() ? this.clientCeiling : binding.entitlement();
    }

    private static List<SpiffeBinding> parseInstances(String json, List<Map<String, Object>> clientCeiling,
                                                      RarModels models) throws IssuanceException {
        if (json == null) {
            return List.of();
        }
        Object parsed;
        try {
            // The model's reader, not jose4j's: a ceiling in here is compared by the model, and jose4j would read
            // its decimals as doubles.
            parsed = Json.parse(json);
        } catch (IllegalArgumentException e) {
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
            List<Map<String, Object>> declared = asObjectList(entry.get("entitlement"), "entitlement");
            Map<String, Object> metadata = asObject(entry.get("metadata"), "metadata");
            // Phase 2.3: the same firewall as the request-time checks in AttestationIssuanceServlet,
            // applied at config-parse time. Binding metadata rides unmodified into the minted
            // attestation's workload.attributes; an operator (or a config mistake) setting metadata
            // .agent_id there would sit confusingly close to the real, attester-minted top-level agent_id
            // claim, so it is rejected outright rather than merely harmless-but-misleading.
            if (metadata.containsKey("agent_id")) {
                throw IssuanceException.invalidClient(
                        P_INSTANCES + " entry '" + subject + "' metadata must not set agent_id: "
                                + "it is minted by the attester, never configured");
            }
            out.add(new SpiffeBinding(subject, instanceCeiling(subject, declared, clientCeiling, models), metadata));
        }
        return out;
    }

    /**
     * The client-level ceiling: read by the model's reader and held to the model, or empty when none is
     * configured.
     */
    private static List<Map<String, Object>> clientCeiling(String json, RarModels models) throws IssuanceException {
        try {
            return models.validate(RarModels.parseDetails(json), P_ENTITLEMENT);
        } catch (RarModelException e) {
            throw IssuanceException.invalidClient(
                    P_ENTITLEMENT + " is not a valid authorization_details array: " + e.getMessage());
        }
    }

    /**
     * An instance's ceiling as it is kept. With a client-level ceiling it is
     * {@code authorize(instance, client, INHERIT)} and the result is what the binding holds: within the client's
     * ceiling, in the instance's order, with every field the client's constrains and the instance's leaves out
     * taken from the client's. This used to check the instance's against the client's and keep the instance's
     * as written, so a field the instance left out was unconstrained for it however the client's constrained
     * it - an instance ceiling wider than its client's (the plan's "Found while designing" item 5, F-0034).
     * Without one, the instance's is held to the model and kept as written.
     */
    static List<Map<String, Object>> instanceCeiling(String subject, List<Map<String, Object>> entitlement,
                                                     List<Map<String, Object>> clientCeiling, RarModels models)
            throws IssuanceException {
        if (entitlement.isEmpty()) {
            return entitlement;
        }
        try {
            return clientCeiling.isEmpty()
                    ? models.validate(entitlement, P_INSTANCES + " entitlement")
                    : models.authorize(entitlement, clientCeiling, Omission.INHERIT);
        } catch (RarModelException e) {
            if (e.reason() == RarModelException.Reason.EXCEEDS_CEILING) {
                throw IssuanceException.invalidClient(
                        "instance '" + subject + "' entitlement exceeds the client-level ceiling");
            }
            throw IssuanceException.invalidClient("instance '" + subject
                    + "' entitlement is not a valid authorization_details array: " + e.getMessage());
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
