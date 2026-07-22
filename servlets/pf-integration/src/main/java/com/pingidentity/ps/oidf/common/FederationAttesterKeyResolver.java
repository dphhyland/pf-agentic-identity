/*
 * Federation-backed resolution of Client Attester signing keys.
 */
package com.pingidentity.ps.oidf.common;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.JwtClaims;

/**
 * Establishes trust in a Client Attester by treating it as an OpenID Federation entity and validating a
 * trust chain from the attester up to the configured Trust Anchor, reusing {@link TrustChainValidator}.
 *
 * <p>The attestation's verified leaf Entity Statement supplies the keys: a dedicated
 * {@code metadata.oauth_client_attester.jwks} block is preferred if present (letting a deployment use
 * separate attestation-signing keys), otherwise the entity's chain-validated federation {@code jwks} is
 * used. Any validation failure surfaces as an exception, which the caller maps to {@code invalid_client}.
 */
public final class FederationAttesterKeyResolver implements AttesterKeyResolver {
    private final TrustChainValidator trustChainValidator;
    private final String opIssuer;
    private final long trustChainEntryMaxAgeSeconds;

    public FederationAttesterKeyResolver(TrustChainValidator trustChainValidator, String opIssuer) {
        this(trustChainValidator, opIssuer, -1L);
    }

    public FederationAttesterKeyResolver(TrustChainValidator trustChainValidator, String opIssuer, long trustChainEntryMaxAgeSeconds) {
        this.trustChainValidator = Objects.requireNonNull(trustChainValidator, "trustChainValidator");
        this.opIssuer = Claims.requireNonBlank(opIssuer, "opIssuer");
        this.trustChainEntryMaxAgeSeconds = trustChainEntryMaxAgeSeconds;
    }

    @Override
    public List<JsonWebKey> resolve(String attesterIssuer, List<String> trustChainHeader) throws Exception {
        Claims.requireNonBlank(attesterIssuer, "attesterIssuer (client attestation 'iss')");
        List<String> seed = trustChainHeader != null ? trustChainHeader : List.of();
        TrustChainValidationResult result = this.trustChainValidator.validate(seed, attesterIssuer, this.opIssuer, -1L, -1L, this.trustChainEntryMaxAgeSeconds);
        JwtClaims leaf = result.leafEntityStatement();
        if (leaf == null) {
            throw new IllegalStateException("Trust chain validation produced no attester entity statement for " + attesterIssuer);
        }
        Map<String, Object> jwks = FederationAttesterKeyResolver.selectAttesterJwks(leaf);
        List<JsonWebKey> keys = new JsonWebKeySet(JsonUtil.toJson(jwks)).getJsonWebKeys();
        if (keys.isEmpty()) {
            throw new IllegalStateException("Attester " + attesterIssuer + " published no usable signing keys");
        }
        return keys;
    }

    private static Map<String, Object> selectAttesterJwks(JwtClaims leaf) {
        Map<String, Object> metadata = Claims.optionalMap(leaf, "metadata");
        Map<String, Object> attesterJwks = Claims.optionalNestedMap(Claims.optionalNestedMap(metadata, "oauth_client_attester"), "jwks");
        if (!attesterJwks.isEmpty()) {
            return attesterJwks;
        }
        return Claims.requiredMap(leaf, "jwks");
    }
}
