package com.pingidentity.ps.oidf.servlet.clientregistration;

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
        Map<String, Object> leafMetadata = validation.metadataFor("oauth_client");
        if (leafMetadata == null || leafMetadata.isEmpty()) {
            leafMetadata = validation.metadataFor("openid_relying_party");
        }
        if (leafMetadata == null || leafMetadata.isEmpty()) {
            throw new IllegalStateException("resolved leaf has no oauth_client/openid_relying_party metadata; cannot register " + clientId);
        }
        return leafMetadata;
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
        String status = extendedParamValue(client, "status");
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
        if (existing != null && !"auto_registered".equals(extendedParamValue(existing, "status"))) {
            // Manually-registered clients are never touched by automatic registration.
            return null;
        }
        TrustChainValidationResult validation = this.trustChainValidator.validate(trustChain, clientId, opIssuer, -1L, -1L, this.configuration.trustChainEntryMaxAgeSeconds());
        Map<String, Object> leafMetadata = federationClientMetadata(validation, clientId);
        Object regTypes = leafMetadata.get("client_registration_types");
        if (!(regTypes instanceof List) || !((List)regTypes).contains("automatic")) {
            throw new IllegalStateException("client " + clientId + " does not advertise client_registration_types=automatic; refusing automatic registration");
        }
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

    private static Client buildClient(String clientId, Map<String, Object> metadata, String opIssuer, Map<String, Object> jwks, List<String> trustChain, RegistrationConfiguration configuration, String status) throws Exception {
        Client client = new Client();
        Map<String, Object> oidcRPMetadata = metadata;
        String tokenEndpointAuthMethod = metadataString(oidcRPMetadata, "token_endpoint_auth_method");
        boolean attestationAuth = "attest_jwt_client_auth".equals(tokenEndpointAuthMethod) || "attest_jwt_client_auth_dpop".equals(tokenEndpointAuthMethod);
        // PingFederate has no native attest_jwt_client_auth type; attestation clients are registered as
        // public clients (NONE) and authenticated at runtime by ClientAttestationUtils via issuance criteria.
        client.setClientAuthnType(attestationAuth ? ClientAuthenticationType.NONE : ClientAuthenticationType.PRIVATE_KEY_JWT);
        client.setJwks(OBJECT_MAPPER.writeValueAsString(jwks));
        client.setName(String.valueOf(oidcRPMetadata.get("client_name")));
        // An oauth_client doing client_credentials legitimately has no redirect_uris / response_types,
        // but PF's XML client store iterates these lists unguarded at save time — never pass null.
        List redirectUris = (List)oidcRPMetadata.get("redirect_uris");
        client.setRedirectUris(redirectUris != null ? redirectUris : new ArrayList<>());
        List responseTypes = (List)oidcRPMetadata.get("response_types");
        client.setRestrictedResponseTypes(responseTypes != null ? responseTypes : new ArrayList<>());
        List grantTypes = (List)oidcRPMetadata.get("grant_types");
        client.setGrantTypes(grantTypes != null ? new HashSet(grantTypes) : new HashSet());
        client.setTokenEndpointAuthSigningAlgorithm(String.valueOf(oidcRPMetadata.get("token_endpoint_auth_signing_alg")));
        client.setIdTokenSigningAlgorithm(String.valueOf(oidcRPMetadata.get("id_token_signed_response_alg")));
        client.setRequestObjectSigningAlgorithm(String.valueOf(oidcRPMetadata.get("request_object_signing_alg")));
        List<String> scopes = Arrays.stream(String.valueOf(oidcRPMetadata.get("scope")).trim().split(" +")).filter(s -> !s.isBlank()).toList();
        client.setRestrictedScopes(scopes);
        client.setBypassApprovalPage(true);
        HashMap<String, ParamValues> extendedParams = new HashMap<String, ParamValues>();
        addParamValue(extendedParams, "status", status);
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

