package com.pingidentity.ps.oidf.jose;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Supplies the RSA key pair (and its key id) used to sign federation
 * statements. Implementations bind to whatever key store the host provides.
 */
public interface SigningKeyProvider {

    String keyId();

    RSAPrivateKey privateKey();

    RSAPublicKey publicKey();
}
