/*
 * Federation-backed resolution of a Wallet Provider's WIA-signing keys.
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
 * Establishes trust in a digital-wallet <em>Wallet Provider</em> by treating it as an OpenID Federation
 * entity and validating a trust chain from the provider up to the configured Trust Anchor, reusing
 * {@link TrustChainValidator} — the wallet analogue of {@link FederationAttesterKeyResolver}. It is an
 * {@link AttesterKeyResolver}, so it plugs straight into {@code WalletInstanceAttestationValidator} to
 * resolve the keys a presented Wallet Instance Attestation must verify under.
 *
 * <p>The verified leaf Entity Statement supplies the keys: the wallet-provider metadata block
 * ({@code metadata.openid_wallet_provider.jwks}) is preferred, then a dedicated
 * {@code oauth_client_attester.jwks} block, otherwise the entity's chain-validated federation {@code jwks}.
 * {@code opIssuer} is the hosted attester's own entity id — the relying party consuming the WIA. Any
 * validation failure surfaces as an exception, which {@code WalletInstanceAttestationValidator} maps to
 * {@code invalid_instance_attestation}.
 */
public final class FederationWalletProviderKeyResolver implements AttesterKeyResolver {
    private final TrustChainValidator trustChainValidator;
    private final String opIssuer;
    private final long trustChainEntryMaxAgeSeconds;

    public FederationWalletProviderKeyResolver(TrustChainValidator trustChainValidator, String opIssuer) {
        this(trustChainValidator, opIssuer, -1L);
    }

    public FederationWalletProviderKeyResolver(TrustChainValidator trustChainValidator, String opIssuer,
                                               long trustChainEntryMaxAgeSeconds) {
        this.trustChainValidator = Objects.requireNonNull(trustChainValidator, "trustChainValidator");
        this.opIssuer = Claims.requireNonBlank(opIssuer, "opIssuer");
        this.trustChainEntryMaxAgeSeconds = trustChainEntryMaxAgeSeconds;
    }

    @Override
    public List<JsonWebKey> resolve(String walletProviderIssuer, List<String> trustChainHeader) throws Exception {
        Claims.requireNonBlank(walletProviderIssuer, "walletProviderIssuer (WIA 'iss')");
        List<String> seed = trustChainHeader != null ? trustChainHeader : List.of();
        TrustChainValidationResult result = this.trustChainValidator.validate(
                seed, walletProviderIssuer, this.opIssuer, -1L, -1L, this.trustChainEntryMaxAgeSeconds);
        JwtClaims leaf = result.leafEntityStatement();
        if (leaf == null) {
            throw new IllegalStateException(
                    "Trust chain validation produced no wallet-provider entity statement for " + walletProviderIssuer);
        }
        Map<String, Object> jwks = FederationWalletProviderKeyResolver.selectWalletProviderJwks(leaf);
        List<JsonWebKey> keys = new JsonWebKeySet(JsonUtil.toJson(jwks)).getJsonWebKeys();
        if (keys.isEmpty()) {
            throw new IllegalStateException(
                    "Wallet provider " + walletProviderIssuer + " published no usable signing keys");
        }
        return keys;
    }

    private static Map<String, Object> selectWalletProviderJwks(JwtClaims leaf) {
        Map<String, Object> metadata = Claims.optionalMap(leaf, "metadata");
        Map<String, Object> walletProvider =
                Claims.optionalNestedMap(Claims.optionalNestedMap(metadata, "openid_wallet_provider"), "jwks");
        if (!walletProvider.isEmpty()) {
            return walletProvider;
        }
        Map<String, Object> attester =
                Claims.optionalNestedMap(Claims.optionalNestedMap(metadata, "oauth_client_attester"), "jwks");
        if (!attester.isEmpty()) {
            return attester;
        }
        return Claims.requiredMap(leaf, "jwks");
    }
}
