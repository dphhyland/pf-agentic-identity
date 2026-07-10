package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.common.SigningKeyProvider;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

/**
 * Builds and signs the trust-anchor federation's own artifacts: its entity configuration,
 * entity/subordinate statements, {@code .well-known} federation metadata, and resolved trust
 * chains. Statements are RSA-signed with the configured algorithm and an inline JWKS derived
 * from the {@link SigningKeyProvider}.
 */
final class FederationService {
    private static final String ENTITY_STATEMENT_TYP = "entity-statement+jwt";
    private final FederationConfiguration configuration;
    private final SigningKeyProvider signingKeyProvider;

    FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.signingKeyProvider = Objects.requireNonNull(signingKeyProvider, "signingKeyProvider");
    }

    Map<String, Object> federationWellKnownMetadata(String oidcIssuer) {
        return Map.of("issuer", oidcIssuer, "federation_entity_endpoint", oidcIssuer + "/federation/entity", "federation_fetch_endpoint", oidcIssuer + "/federation/fetch", "federation_list_endpoint", oidcIssuer + "/federation/list", "federation_resolve_endpoint", oidcIssuer + "/federation/resolve", "authority_hints", this.configuration.authorityHints());
    }

    String createEntityConfigurationJwt(String oidcIssuer) throws JoseException {
        JwtClaims claims = baseClaims(oidcIssuer, oidcIssuer);
        claims.setClaim("jwks", this.buildInlineJwks());
        LinkedHashMap<String, Map<String, Object>> metadata = new LinkedHashMap<String, Map<String, Object>>();
        metadata.put("federation_entity", Map.of("federation_fetch_endpoint", oidcIssuer + "/federation/fetch", "federation_list_endpoint", oidcIssuer + "/federation/list", "federation_resolve_endpoint", oidcIssuer + "/federation/resolve"));
        AttestationMetadataConfig attestationMetadata = this.configuration.attestationMetadata();
        LinkedHashMap<String, Object> openidProvider = new LinkedHashMap<String, Object>();
        openidProvider.put("issuer", oidcIssuer);
        openidProvider.put("authorization_endpoint", oidcIssuer + "/as/authorization.oauth2");
        openidProvider.put("token_endpoint", oidcIssuer + "/as/token.oauth2");
        openidProvider.put("pushed_authorization_request_endpoint", oidcIssuer + "/as/par.oauth2");
        openidProvider.put("client_registration_types_supported", List.of("explicit"));
        openidProvider.put("federation_registration_endpoint", oidcIssuer + "/federation/register");
        openidProvider.put("token_endpoint_auth_methods_supported", attestationMetadata.tokenEndpointAuthMethodsSupported());
        openidProvider.put("client_attestation_signing_alg_values_supported", attestationMetadata.clientAttestationSigningAlgValuesSupported());
        openidProvider.put("client_attestation_pop_signing_alg_values_supported", attestationMetadata.clientAttestationPopSigningAlgValuesSupported());
        openidProvider.put("dpop_signing_alg_values_supported", attestationMetadata.dpopSigningAlgValuesSupported());
        List<String> popMethods = attestationMetadata.clientAttestationPopMethodsSupported();
        if (!popMethods.isEmpty()) {
            // draft-10 §8: the array MUST NOT be empty when the parameter is present
            openidProvider.put("client_attestation_pop_methods_supported", popMethods);
        }
        if (attestationMetadata.challengeEndpointEnabled()) {
            openidProvider.put("challenge_endpoint", oidcIssuer + "/federation/attestation-challenge");
        }
        metadata.put("openid_provider", openidProvider);
        metadata.put("oauth_authorization_server", Map.of("issuer", oidcIssuer, "authorization_endpoint", oidcIssuer + "/as/authorization.oauth2", "token_endpoint", oidcIssuer + "/as/token.oauth2", "pushed_authorization_request_endpoint", oidcIssuer + "/as/par.oauth2"));
        claims.setClaim("metadata", metadata);
        List<String> authorityHints = this.configuration.authorityHints();
        if (!authorityHints.isEmpty() && !this.configuration.isTrustAnchor(oidcIssuer)) {
            claims.setClaim("authority_hints", authorityHints);
        }
        return this.signClaims(claims);
    }

    String createEntityStatement(String subject, String requestedIssuer, String oidcIssuer) throws JoseException {
        String actualIssuer = requestedIssuer == null || requestedIssuer.isBlank() ? oidcIssuer : requestedIssuer;
        Map<String, Map<String, Object>> metadata = Map.of("openid_provider", Map.of("issuer", oidcIssuer, "jwks_uri", oidcIssuer + "/pf/JWKS", "authorization_endpoint", oidcIssuer + "/as/authorization.oauth2", "token_endpoint", oidcIssuer + "/as/token.oauth2", "pushed_authorization_request_endpoint", oidcIssuer + "/as/par.oauth2"));
        JwtClaims claims = baseClaims(actualIssuer, subject);
        claims.setClaim("jwks", this.buildInlineJwks());
        claims.setClaim("metadata", metadata);
        claims.setClaim("authority_hints", this.configuration.authorityHints());
        return this.signClaims(claims);
    }

    String fetchEntityStatement(String issuer, String subject, String oidcIssuer) throws JoseException {
        boolean knownIssuer;
        boolean bl = knownIssuer = issuer.equals(oidcIssuer) || this.configuration.isTrustAnchor(issuer);
        if (!knownIssuer) {
            throw new IllegalArgumentException("Unknown issuer: " + issuer);
        }
        return this.createEntityStatement(subject, issuer, oidcIssuer);
    }

    List<String> listSubordinates(String entityType) {
        return this.configuration.subordinates();
    }

    Map<String, Object> resolveTrustChain(String subject, String trustAnchorIssuer, String oidcIssuer) throws JoseException {
        String anchorIssuer = this.configuration.findTrustAnchor(trustAnchorIssuer != null ? trustAnchorIssuer : this.configuration.defaultTrustAnchorIssuer());
        String trustAnchorStatement = this.createConfiguredTrustAnchorStatement(anchorIssuer, oidcIssuer);
        String leafStatement = this.createEntityStatement(subject, trustAnchorIssuer, oidcIssuer);
        return Map.of("subject", subject, "trust_anchor", anchorIssuer, "resolved_chain", List.of(trustAnchorStatement, leafStatement), "metadata", Map.of("openid_provider", Map.of("issuer", oidcIssuer, "jwks_uri", oidcIssuer + "/pf/JWKS")));
    }

    private String createConfiguredTrustAnchorStatement(String anchorIssuer, String subject) throws JoseException {
        JwtClaims claims = baseClaims(anchorIssuer, subject);
        claims.setClaim("metadata", Map.of("openid_provider", Map.of("issuer", anchorIssuer, "jwks_uri", anchorIssuer + "/pf/JWKS", "authorization_endpoint", anchorIssuer + "/as/authorization.oauth2", "token_endpoint", anchorIssuer + "/as/token.oauth2", "pushed_authorization_request_endpoint", anchorIssuer + "/as/par.oauth2")));
        return this.signClaims(claims);
    }

    private static JwtClaims baseClaims(String issuer, String subject) {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(60.0f);
        return claims;
    }

    private SigningKeyProvider resolveSigningKeyProvider() {
        return this.signingKeyProvider;
    }

    private String signClaims(JwtClaims claims) throws JoseException {
        String algorithm = this.configuration.signingAlgorithm();
        SigningKeyProvider signingKeys = this.resolveSigningKeyProvider();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKeys.privateKey());
        jws.setAlgorithmHeaderValue(algorithm);
        jws.setHeader("typ", ENTITY_STATEMENT_TYP);
        jws.setKeyIdHeaderValue(signingKeys.keyId());
        return jws.getCompactSerialization();
    }

    private Map<String, Object> buildInlineJwks() throws JoseException {
        String algorithm = this.configuration.signingAlgorithm();
        SigningKeyProvider signingKeys = this.resolveSigningKeyProvider();
        RSAPublicKey pub = signingKeys.publicKey();
        Objects.requireNonNull(pub, "signingKeys.publicKey()");
        RsaJsonWebKey jwk = new RsaJsonWebKey(pub);
        jwk.setUse("sig");
        jwk.setAlgorithm(algorithm);
        jwk.setKeyId(signingKeys.keyId());
        String jwksJson = new JsonWebKeySet(new JsonWebKey[]{jwk}).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        return JsonUtil.parseJson(jwksJson);
    }
}

