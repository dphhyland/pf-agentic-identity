/*
 * PingFederate's active JWKS signing key, resolved on first use, for the SETs this transmitter signs.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.pf.PfJwksSigningKeyProvider;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.function.Supplier;

/**
 * The {@link SigningKeyProvider} shared-signals' {@code SetMinter} signs with inside PingFederate: the same
 * mechanism as the federation servlet, {@link PfJwksSigningKeyProvider}, backed by PingFederate's active JWKS
 * signing key, so a receiver validates SETs against the transmitter's advertised {@code jwks_uri}
 * ({@code <issuer>/pf/JWKS}). The key is resolved on first use and kept, not when the servlets initialise, because
 * PingFederate's key accessor may not be ready then - which is what the minter did itself before 0.5.0.
 */
final class PfSetSigningKeys implements SigningKeyProvider {

    private final Supplier<SigningKeyProvider> resolver;
    private volatile SigningKeyProvider resolved;

    PfSetSigningKeys(String algorithm) {
        this(() -> new PfJwksSigningKeyProvider(algorithm));
    }

    PfSetSigningKeys(Supplier<SigningKeyProvider> resolver) {
        this.resolver = resolver;
    }

    private SigningKeyProvider keys() {
        SigningKeyProvider local = this.resolved;
        if (local == null) {
            synchronized (this) {
                if (this.resolved == null) {
                    this.resolved = this.resolver.get();
                }
                local = this.resolved;
            }
        }
        return local;
    }

    @Override
    public String keyId() {
        return keys().keyId();
    }

    @Override
    public RSAPrivateKey privateKey() {
        return keys().privateKey();
    }

    @Override
    public RSAPublicKey publicKey() {
        return keys().publicKey();
    }
}
