package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.common.ClientStore;
import com.pingidentity.ps.oidf.common.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.common.JdkHttpGetClient;
import com.pingidentity.ps.oidf.common.PfJwksSigningKeyProvider;
import com.pingidentity.ps.oidf.common.PfMgmtClientStore;
import com.pingidentity.ps.oidf.common.SigningKeyProvider;
import com.pingidentity.ps.oidf.common.SubordinateStatementCache;
import com.pingidentity.ps.oidf.common.TrustChainValidationResult;
import com.pingidentity.ps.oidf.common.TrustChainValidator;
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
        this(configuration, new TrustChainValidator(new HttpTrustControllerGateway(new JdkHttpGetClient(configuration.ignoreSslErrors()), configuration.trustControllerBaseUrl(), configuration.trustControllerHost(), new SubordinateStatementCache(configuration.subordinateStatementCacheMaxEntries())), configuration.trustControllerHost(), configuration.acceptedSigningAlgorithms()), new PfMgmtClientStore(), null);
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

    RegisteredClient explicitRegister(ExplicitRegistrationRequest request, String opIssuer) throws Exception {
        Objects.requireNonNull(request, "request");
        TrustChainValidationResult validation = this.trustChainValidator.validate(request.trustChain(), request.issuer(), opIssuer, -1L, -1L, this.configuration.trustChainEntryMaxAgeSeconds());
        String clientId = request.sub();
        String trustAnchorIssuer = validation.trustAnchorIssuer();
        String rpSubject = validation.leafSubject();
        Map<String, Object> leafMetadata = validation.metadataFor("openid_relying_party");
        JwtClaims leafEntityStatement = validation.leafEntityStatement();
        Map jwks = leafEntityStatement.getClaimValue("jwks", Map.class);
        LinkedHashMap<String, Object> responseRpMetadata = new LinkedHashMap<String, Object>(leafMetadata != null ? leafMetadata : Map.of());
        responseRpMetadata.put("client_id", clientId);
        responseRpMetadata.put("client_id_issued_at", Instant.now().getEpochSecond());
        String signedJwt = this.buildSignedRegistrationResponse(opIssuer, rpSubject, trustAnchorIssuer, responseRpMetadata);
        RegisteredClient registeredClient = new RegisteredClient(clientId, rpSubject, trustAnchorIssuer, request.trustChain(), responseRpMetadata, "registered", signedJwt);
        this.clientStore.add(buildClient(clientId, leafMetadata, opIssuer, jwks, validation.trustChain(), this.configuration, "registered"));
        return registeredClient;
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
        if (this.clientStore.get(clientId) != null) {
            return null;
        }
        TrustChainValidationResult validation = this.trustChainValidator.validate(trustChain, clientId, opIssuer, -1L, -1L, this.configuration.trustChainEntryMaxAgeSeconds());
        Map<String, Object> leafMetadata = validation.leafMetadata();
        if (leafMetadata == null || leafMetadata.isEmpty()) {
            throw new IllegalStateException("resolved leaf has no oauth_client/openid_relying_party metadata; cannot automatically register " + clientId);
        }
        Object regTypes = leafMetadata.get("client_registration_types");
        if (!(regTypes instanceof List) || !((List)regTypes).contains("automatic")) {
            throw new IllegalStateException("client " + clientId + " does not advertise client_registration_types=automatic; refusing automatic registration");
        }
        JwtClaims leafEntityStatement = validation.leafEntityStatement();
        Map jwks = leafEntityStatement.getClaimValue("jwks", Map.class);
        this.clientStore.add(buildClient(clientId, leafMetadata, opIssuer, jwks, validation.trustChain(), this.configuration, "auto_registered"));
        LOGGER.info((Object)("Automatically registered federation client " + clientId + " (trust anchor " + validation.trustAnchorIssuer() + ")"));
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
        client.setRedirectUris((List)oidcRPMetadata.get("redirect_uris"));
        client.setRestrictedResponseTypes((List)oidcRPMetadata.get("response_types"));
        client.setGrantTypes(new HashSet((List)oidcRPMetadata.get("grant_types")));
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

