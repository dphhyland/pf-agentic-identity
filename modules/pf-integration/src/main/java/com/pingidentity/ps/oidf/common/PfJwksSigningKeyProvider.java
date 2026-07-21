package com.pingidentity.ps.oidf.common;

import com.pingidentity.access.JwksEndpointKeyAccessor;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * {@link SigningKeyProvider} backed by PingFederate's JWKS endpoint key store.
 * Resolves the current RSA signing key for a given algorithm via
 * {@link JwksEndpointKeyAccessor} and exposes its key id and RSA key pair.
 */
public final class PfJwksSigningKeyProvider
implements SigningKeyProvider {
    private final String keyId;
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public PfJwksSigningKeyProvider(String algorithm) {
        JwksEndpointKeyAccessor.JsonWebKeyWrapper wrapper = JwksEndpointKeyAccessor.newInstance().getCurrentRsaKey(algorithm);
        this.keyId = wrapper.getKeyId();
        this.privateKey = (RSAPrivateKey)wrapper.getPrivateKey();
        this.publicKey = (RSAPublicKey)wrapper.getJWK().getPublicKey();
    }

    public PfJwksSigningKeyProvider() {
        this("RS256");
    }

    @Override
    public String keyId() {
        return this.keyId;
    }

    @Override
    public RSAPrivateKey privateKey() {
        return this.privateKey;
    }

    @Override
    public RSAPublicKey publicKey() {
        return this.publicKey;
    }
}

