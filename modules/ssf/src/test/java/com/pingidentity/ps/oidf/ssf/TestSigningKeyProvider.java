/*
 * Test-only SigningKeyProvider backed by a freshly generated RSA key.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.common.SigningKeyProvider;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;

/** A {@link SigningKeyProvider} with an in-process RSA key so SET minting can be unit-tested without PF. */
final class TestSigningKeyProvider implements SigningKeyProvider {

    private final RsaJsonWebKey jwk;

    TestSigningKeyProvider(String keyId) {
        try {
            this.jwk = RsaJwkGenerator.generateJwk(2048);
            this.jwk.setKeyId(keyId);
        } catch (Exception e) {
            throw new IllegalStateException("failed to generate test RSA key", e);
        }
    }

    @Override
    public String keyId() {
        return this.jwk.getKeyId();
    }

    @Override
    public RSAPrivateKey privateKey() {
        return (RSAPrivateKey) this.jwk.getRsaPrivateKey();
    }

    @Override
    public RSAPublicKey publicKey() {
        return this.jwk.getRsaPublicKey();
    }
}
