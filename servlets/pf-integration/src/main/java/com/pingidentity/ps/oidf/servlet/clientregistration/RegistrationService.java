package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.BridgeKey;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;
import com.pingidentity.ps.oidf.pf.PfJwksSigningKeyProvider;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.federation.SubordinateStatementCache;
import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ClientAuthenticationType;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * Core of the explicit client-registration flow. Validates the RP's trust chain, provisions a
 * PingFederate {@link Client} from the leaf metadata (mapping attestation clients to public
 * clients), and builds the signed explicit-registration-response JWT returned to the RP.
 */
final class RegistrationService {
    private static final String ENTITY_STATEMENT_TYP = "entity-statement+jwt";
    private static final long REGISTRATION_LIFETIME_MINUTES = 60L;
    private final RegistrationConfiguration configuration;
    private final TrustChainValidator trustChainValidator;
    private final ClientStore clientStore;
    private final SigningKeyProvider signingKeyProvider;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    static final Log LOGGER = LogFactory.getLog(RegistrationService.class);

    RegistrationService(RegistrationConfiguration configuration) {
        this(configuration, new TrustChainValidator(new HttpTrustControllerGateway(new JdkHttpGetClient(configuration.ignoreSslErrors(), OutboundUrlPolicy.fromEnvironment()
                        .trusting(configuration.trustControllerBaseUrl(), configuration.trustControllerHost())), configuration.trustControllerBaseUrl(), configuration.trustControllerHost(), new SubordinateStatementCache(configuration.subordinateStatementCacheMaxEntries())), configuration.trustControllerHost(), configuration.acceptedSigningAlgorithms()), new PfMgmtClientStore(), null);
    }

    RegistrationService(RegistrationConfiguration configuration, TrustChainValidator trustChainValidator, ClientStore clientStore) {
        this(configuration, trustChainValidator, clientStore, null);
    }

    RegistrationService(RegistrationConfiguration configuration, TrustChainValidator trustChainValidator, ClientStore clientStore, SigningKeyProvider signingKeyProvider) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.trustChainValidator = Objects.requireNonNull(trustChainValidator, "trustChainValidator");
        this.clientStore = Objects.requireNonNull(clientStore, "clientStore");
        this.signingKeyProvider = signingKeyProvider;
    }

    /**
     * OIDF §12.2 explicit registration. Order matters and is the whole point: the trust chain is
     * validated to the configured anchor <em>first</em>; only then is the client store consulted.
     * A client this module did not register (no {@code status} extended param — a console or
     * Terraform client) is never modified: 409, no side effect. A client this module did register
     * (explicitly or automatically) is refreshed from the re-validated chain — the federation, not the
     * stored copy, is the authority. Nothing is ever disabled: a repeat registration is not evidence
     * of compromise, and a request that fails verification must leave no trace.
     */
    RegisteredClient explicitRegister(ExplicitRegistrationRequest request, String opIssuer) throws Exception {
        Objects.requireNonNull(request, "request");
        TrustChainValidationResult validation = this.trustChainValidator.validate(request.trustChain(), request.issuer(), opIssuer, -1L, -1L, this.configuration.trustChainEntryMaxAgeSeconds());
        String clientId = request.sub();
        String trustAnchorIssuer = validation.trustAnchorIssuer();
        String rpSubject = validation.leafSubject();
        Map<String, Object> leafMetadata = federationClientMetadata(validation, clientId);
        requireRegistrationType(leafMetadata, clientId, "explicit");

        Client existing = this.clientStore.get(clientId);
        if (existing != null && !isFederationRegistered(existing)) {
            throw new RegistrationRejectedException(409, "invalid_client_metadata",
                    "client_id " + clientId + " is administered outside OpenID Federation and cannot be registered through it");
        }
        // Deliberately after the 409: a client that is not ours to touch should be told so, rather than
        // told its chain lacks a policy - the first is the actionable answer and the more specific one.
        requireConstrainedByPolicy(validation, clientEntityType(validation), clientId);

        JwtClaims leafEntityStatement = validation.leafEntityStatement();
        Map jwks = leafEntityStatement.getClaimValue("jwks", Map.class);
        LinkedHashMap<String, Object> responseRpMetadata = new LinkedHashMap<String, Object>(leafMetadata);
        responseRpMetadata.put("client_id", clientId);
        responseRpMetadata.put("client_id_issued_at", Instant.now().getEpochSecond());
        String signedJwt = this.buildSignedRegistrationResponse(opIssuer, rpSubject, trustAnchorIssuer, responseRpMetadata);
        Client client = buildClient(clientId, leafMetadata, opIssuer, jwks, validation.trustChain(), this.configuration, "registered");
        if (existing != null) {
            this.clientStore.update(client);
            LOGGER.info((Object)("Refreshed federation client " + clientId + " via explicit registration (trust anchor " + trustAnchorIssuer + ")"));
        } else {
            this.clientStore.add(client);
            LOGGER.info((Object)("Explicitly registered federation client " + clientId + " (trust anchor " + trustAnchorIssuer + ")"));
        }
        return new RegisteredClient(clientId, rpSubject, trustAnchorIssuer, request.trustChain(), responseRpMetadata, "registered", signedJwt);
    }

    /**
     * The leaf's client metadata: {@code oauth_client} (agents) or {@code openid_relying_party} (OIDC
     * RPs) — a federation leaf carries one or the other, and the deprecated single-block view only saw
     * the latter.
     */
    private static Map<String, Object> federationClientMetadata(TrustChainValidationResult validation, String clientId) {
        Map<String, Object> leafMetadata = validation.metadataFor(clientEntityType(validation));
        if (leafMetadata == null || leafMetadata.isEmpty()) {
            throw new IllegalStateException("resolved leaf has no oauth_client/openid_relying_party metadata; cannot register " + clientId);
        }
        return leafMetadata;
    }

    /**
     * Which entity type this registration actually consumes: {@code oauth_client} when the leaf carries
     * it, otherwise {@code openid_relying_party}. Kept next to {@link #federationClientMetadata} because
     * the two must agree — the policy check is only meaningful against the block being used.
     */
    private static String clientEntityType(TrustChainValidationResult validation) {
        Map<String, Object> oauthClient = validation.metadataFor("oauth_client");
        return oauthClient != null && !oauthClient.isEmpty() ? "oauth_client" : "openid_relying_party";
    }

    /**
     * Refuses a client whose metadata no superior in the trust chain constrained.
     *
     * <p>{@link com.pingidentity.ps.oidf.federation.MetadataPolicy} applies a {@code metadata_policy}
     * faithfully — but a chain is under no obligation to declare one, and when none does, the leaf's
     * self-published metadata is resolved verbatim. Everything this method's caller then writes onto a
     * PF client — {@code scope}, {@code grant_types}, {@code response_types} — is whatever the entity
     * asked for. The trust chain still proves the entity is who it says and that the anchor vouches for
     * its existence; it does not, on its own, say what the entity may do.
     *
     * <p>So this fails closed by default: an anchor that has not published a policy for the entity type
     * being registered gets a rejection rather than a client with unbounded scope. The policy itself is
     * anchor configuration and lives with whoever deploys the federation; the DEFAULT belongs here,
     * because a permissive default is invisible in exactly the deployments least likely to notice.
     *
     * <p>Note the type checked is the one actually consumed: {@code federationClientMetadata} prefers
     * {@code oauth_client}, so an anchor that publishes only an {@code openid_relying_party} policy has
     * constrained nothing for an agent, and is treated as such.
     */
    private static void requireConstrainedByPolicy(TrustChainValidationResult validation, String entityType, String clientId)
            throws RegistrationRejectedException {
        if (validation.isPoliced(entityType) || !FederationRuntimeConfig.get().requireMetadataPolicy()) {
            return;
        }
        throw new RegistrationRejectedException(400, "invalid_client_metadata",
                "no superior in the trust chain declares a metadata_policy for " + entityType + ", so "
                        + clientId + " would be registered with the scope, grant_types and response_types "
                        + "it published about itself. Publish a metadata_policy at the trust anchor (or an "
                        + "intermediate), or set " + FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV
                        + "=false to accept unconstrained federation metadata.");
    }

    private static void requireRegistrationType(Map<String, Object> leafMetadata, String clientId, String type) throws RegistrationRejectedException {
        Object regTypes = leafMetadata.get("client_registration_types");
        if (!(regTypes instanceof List) || !((List<?>) regTypes).contains(type)) {
            throw new RegistrationRejectedException(400, "invalid_client_metadata",
                    "client " + clientId + " does not advertise client_registration_types=" + type + "; refusing " + type + " registration");
        }
    }

    /** True when this module registered the client (explicitly or automatically); false for console/Terraform clients. */
    private static boolean isFederationRegistered(Client client) {
        String status = extendedParamValue(client, FederationClientParams.STATUS);
        return "registered".equals(status) || "auto_registered".equals(status);
    }

    /**
     * OIDF §12.1 automatic registration: provision the client just-in-time from its resolved federation
     * metadata. Returns null when the client already exists (idempotent); requires the resolved leaf to
     * advertise {@code client_registration_types} ⊇ {@code automatic}.
     */
    RegisteredClient automaticRegister(List<String> trustChain, String clientId, String opIssuer) throws Exception {
        Objects.requireNonNull(clientId, "clientId");
        if (trustChain == null || trustChain.isEmpty()) {
            throw new IllegalArgumentException("trust_chain is required for automatic registration");
        }
        Client existing = this.clientStore.get(clientId);
        if (existing != null && !"auto_registered".equals(extendedParamValue(existing, FederationClientParams.STATUS))) {
            // Manually-registered clients are never touched by automatic registration.
            return null;
        }
        TrustChainValidationResult validation = this.trustChainValidator.validate(trustChain, clientId, opIssuer, -1L, -1L, this.configuration.trustChainEntryMaxAgeSeconds());
        Map<String, Object> leafMetadata = federationClientMetadata(validation, clientId);
        Object regTypes = leafMetadata.get("client_registration_types");
        if (!(regTypes instanceof List) || !((List)regTypes).contains("automatic")) {
            throw new IllegalStateException("client " + clientId + " does not advertise client_registration_types=automatic; refusing automatic registration");
        }
        requireConstrainedByPolicy(validation, clientEntityType(validation), clientId);
        JwtClaims leafEntityStatement = validation.leafEntityStatement();
        Map jwks = leafEntityStatement.getClaimValue("jwks", Map.class);
        Client client = buildClient(clientId, leafMetadata, opIssuer, jwks, validation.trustChain(), this.configuration, "auto_registered");
        if (existing != null) {
            // An auto-registered client is wholly derived from its (just re-validated) trust chain, so a
            // chain presenting new keys/metadata refreshes the record — this is how §12.1 key rotation
            // works: the federation, not the stored copy, is the authority.
            this.clientStore.update(client);
            LOGGER.info((Object)("Refreshed auto-registered federation client " + clientId + " (trust anchor " + validation.trustAnchorIssuer() + ")"));
        } else {
            this.clientStore.add(client);
            LOGGER.info((Object)("Automatically registered federation client " + clientId + " (trust anchor " + validation.trustAnchorIssuer() + ")"));
        }
        return new RegisteredClient(clientId, validation.leafSubject(), validation.trustAnchorIssuer(), validation.trustChain(), leafMetadata, "auto_registered", null);
    }

    private String buildSignedRegistrationResponse(String opIssuer, String rpIssuer, String trustAnchorIssuer, Map<String, Object> rpMetadata) throws JoseException {
        SigningKeyProvider signingKeys = this.resolveSigningKeyProvider();
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(opIssuer);
        claims.setSubject(rpIssuer);
        claims.setAudience(rpIssuer);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(60.0f);
        claims.setClaim("trust_anchor", trustAnchorIssuer);
        claims.setClaim("jwks", buildInlineJwks(signingKeys, this.configuration.signingAlgorithm()));
        claims.setClaim("metadata", Map.of("openid_relying_party", rpMetadata));
        String algorithm = this.configuration.signingAlgorithm();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKeys.privateKey());
        jws.setAlgorithmHeaderValue(algorithm);
        jws.setHeader("typ", "explicit-registration-response+jwt");
        jws.setKeyIdHeaderValue(signingKeys.keyId());
        return jws.getCompactSerialization();
    }

    private SigningKeyProvider resolveSigningKeyProvider() {
        return this.signingKeyProvider != null ? this.signingKeyProvider : new PfJwksSigningKeyProvider(this.configuration.signingAlgorithm());
    }

    private static Map<String, Object> buildInlineJwks(SigningKeyProvider signingKeys, String algorithm) throws JoseException {
        RSAPublicKey pub = signingKeys.publicKey();
        Objects.requireNonNull(pub, "signingKeys.publicKey()");
        RsaJsonWebKey jwk = new RsaJsonWebKey(pub);
        jwk.setUse("sig");
        jwk.setAlgorithm(algorithm);
        jwk.setKeyId(signingKeys.keyId());
        String jwksJson = new JsonWebKeySet(new JsonWebKey[]{jwk}).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        return JsonUtil.parseJson(jwksJson);
    }

    /**
     * The leaf's own JWKS plus the deployment's bridge public key(s), so PF will accept the assertion
     * ClientAttestationAuthFilter mints on this client's behalf. A previous bridge key is included
     * during a rotation overlap; clients pick the new one up on their next chain-driven refresh.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> withBridgeKeys(Map<String, Object> leafJwks, String clientId) {
        List<Map<String, Object>> bridge = BridgeKey.publicJwksForClients();
        if (bridge.isEmpty()) {
            throw new IllegalStateException("cannot register " + clientId + " for attest_jwt_client_auth: "
                    + FederationRuntimeConfig.BRIDGE_KEY_ENV + " is not set, so the client would be "
                    + "registered with no usable credential. Set it, or register the client with a "
                    + "different token_endpoint_auth_method.");
        }
        List<Object> keys = new ArrayList<Object>();
        Object existing = leafJwks == null ? null : leafJwks.get("keys");
        if (existing instanceof List) {
            keys.addAll((List<Object>) existing);
        }
        keys.addAll(bridge);
        LinkedHashMap<String, Object> merged = new LinkedHashMap<String, Object>();
        merged.put("keys", keys);
        return merged;
    }

    private static Client buildClient(String clientId, Map<String, Object> metadata, String opIssuer, Map<String, Object> jwks, List<String> trustChain, RegistrationConfiguration configuration, String status) throws Exception {
        Client client = new Client();
        Map<String, Object> oidcRPMetadata = metadata;
        String tokenEndpointAuthMethod = metadataString(oidcRPMetadata, "token_endpoint_auth_method");
        boolean attestationAuth = "attest_jwt_client_auth".equals(tokenEndpointAuthMethod) || "attest_jwt_client_auth_dpop".equals(tokenEndpointAuthMethod);
        // PingFederate has no native attest_jwt_client_auth type. It used to be mapped to NONE - a
        // PUBLIC client - on the theory that ClientAttestationAuthFilter and the OGNL issuance
        // criterion would authenticate it instead. But the filter passes through when no bridge key is
        // configured, and no environment in this repo sets one, so that composition produced
        // JIT-registered clients PF would accept with no credential at all. Attestation clients are
        // now PRIVATE_KEY_JWT, carrying the bridge public key alongside their own federation keys:
        // the filter mints an assertion under that key, so PF's native authenticator makes the
        // decision, and without the bridge key the client simply cannot authenticate (fail closed)
        // rather than authenticating trivially.
        client.setClientAuthnType(ClientAuthenticationType.PRIVATE_KEY_JWT);
        client.setJwks(OBJECT_MAPPER.writeValueAsString(attestationAuth ? withBridgeKeys(jwks, clientId) : jwks));
        // String.valueOf(null) is the string "null", not null. Every one of these used to write that
        // literal into PF whenever the leaf omitted the field - a client actually named "null", signing
        // algorithms of "null", and (worst) a client restricted to a scope called "null", which is a
        // scope no token will ever carry. metadataString is the null-safe reader; use it.
        client.setName(metadataString(oidcRPMetadata, "client_name"));
        // An oauth_client doing client_credentials legitimately has no redirect_uris / response_types,
        // but PF's XML client store iterates these lists unguarded at save time — never pass null.
        List redirectUris = (List)oidcRPMetadata.get("redirect_uris");
        client.setRedirectUris(redirectUris != null ? redirectUris : new ArrayList<>());
        List responseTypes = (List)oidcRPMetadata.get("response_types");
        client.setRestrictedResponseTypes(responseTypes != null ? responseTypes : new ArrayList<>());
        List grantTypes = (List)oidcRPMetadata.get("grant_types");
        client.setGrantTypes(grantTypes != null ? new HashSet(grantTypes) : new HashSet());
        client.setTokenEndpointAuthSigningAlgorithm(metadataString(oidcRPMetadata, "token_endpoint_auth_signing_alg"));
        client.setIdTokenSigningAlgorithm(metadataString(oidcRPMetadata, "id_token_signed_response_alg"));
        client.setRequestObjectSigningAlgorithm(metadataString(oidcRPMetadata, "request_object_signing_alg"));
        String scope = metadataString(oidcRPMetadata, "scope");
        List<String> scopes = scope == null ? List.of()
                : Arrays.stream(scope.trim().split(" +")).filter(s -> !s.isBlank()).toList();
        client.setRestrictedScopes(scopes);
        client.setBypassApprovalPage(bypassApprovalPage(grantTypes));
        HashMap<String, ParamValues> extendedParams = new HashMap<String, ParamValues>();
        // Every name written here must be declared in extended-properties.tf or PF rejects/drops it -
        // see FederationClientParams, which both this and that file are checked against.
        addParamValue(extendedParams, FederationClientParams.STATUS, status);
        addParamValue(extendedParams, oidcRPMetadata, "application_type");
        addParamValue(extendedParams, oidcRPMetadata, "subject_type");
        addParamValue(extendedParams, oidcRPMetadata, "contacts");
        addParamValues(extendedParams, "trust_chain", trustChain);
        if (attestationAuth) {
            addParamValue(extendedParams, "token_endpoint_auth_method", tokenEndpointAuthMethod);
            addParamValue(extendedParams, "attestation_required", "true");
        }
        client.setExtendedParams(extendedParams);
        if (clientId != null) {
            client.setClientId(clientId);
        }
        return client;
    }

    /**
     * Whether to skip the approval page. Previously always true, which silently suppressed consent for
     * every federation-registered client - including one running authorization_code with a real user in
     * front of it.
     *
     * <p>The honest rule is whether there is anyone to ask. A client whose only grant is
     * {@code client_credentials} acts with no resource owner present, so an approval page has no one to
     * show and bypassing is correct. Any user-facing grant gets the page.
     *
     * <p>This is a behaviour change, in the safer direction: some clients that skipped consent will now
     * ask for it. A deployment that genuinely wants consent suppressed for a user-facing client should
     * configure that on the client in PF, where it is visible, rather than inherit it from a default
     * that applied to everything.
     */
    private static boolean bypassApprovalPage(List<?> grantTypes) {
        if (grantTypes == null || grantTypes.isEmpty()) {
            return false;
        }
        for (Object g : grantTypes) {
            if (!"client_credentials".equals(String.valueOf(g))) {
                return false;
            }
        }
        return true;
    }

    private static String metadataString(Map<String, Object> oidcRPMetadata, String key) {
        Object value = oidcRPMetadata.get(key);
        return value == null ? null : String.valueOf(value);
    }

    private static void addParamValue(Map<String, ParamValues> extendedParams, Map<String, Object> oidcRPMetadata, String paramName) {
        if (!oidcRPMetadata.containsKey(paramName)) {
            return;
        }
        Object rpMetadataValue = oidcRPMetadata.get(paramName);
        if (rpMetadataValue instanceof List) {
            addParamValues(extendedParams, paramName, (List)rpMetadataValue);
        } else {
            String paramValue = String.valueOf(rpMetadataValue);
            addParamValue(extendedParams, paramName, paramValue);
        }
    }

    private static void addParamValue(Map<String, ParamValues> extendedParams, String paramName, String paramValue) {
        ParamValues existing = extendedParams.get(paramName);
        if (existing != null) {
            existing.getElements().add(paramValue);
            return;
        }
        ParamValues paramValues = new ParamValues();
        ArrayList<String> elements = new ArrayList<String>();
        elements.add(paramValue);
        paramValues.setElements(elements);
        extendedParams.put(paramName, paramValues);
    }

    /** First value of a client's extended param, or null when absent — the read twin of addParamValue. */
    private static String extendedParamValue(Client client, String paramName) {
        Map<String, ParamValues> params = client.getExtendedParams();
        ParamValues values = params != null ? params.get(paramName) : null;
        List<String> elements = values != null ? values.getElements() : null;
        return elements != null && !elements.isEmpty() ? elements.get(0) : null;
    }

    private static void addParamValues(Map<String, ParamValues> extendedParams, String paramName, List<String> paramValues1) {
        ParamValues existing = extendedParams.get(paramName);
        if (existing != null) {
            existing.getElements().addAll(paramValues1);
            return;
        }
        ParamValues paramValues = new ParamValues();
        ArrayList<String> elements = new ArrayList<String>();
        elements.addAll(paramValues1);
        paramValues.setElements(elements);
        extendedParams.put(paramName, paramValues);
    }
}

