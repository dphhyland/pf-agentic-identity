/*
 * Signs Security Event Tokens with a PingFederate-managed signing key (RFC 8417, typ=secevent+jwt).
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.common.PfJwksSigningKeyProvider;
import com.pingidentity.ps.oidf.common.SigningKeyProvider;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

/**
 * Turns a {@link SecurityEventToken} into a signed compact JWS. Reuses the same signing mechanism as the
 * federation servlet — {@link PfJwksSigningKeyProvider}, backed by PingFederate's active JWKS signing key —
 * so a receiver validates SETs against the transmitter's advertised {@code jwks_uri} ({@code <issuer>/pf/JWKS}).
 * The signing key provider is injectable for unit tests; in the runtime it resolves lazily against PF.
 *
 * <p>Header: {@code alg} = the configured RS256/PS256, {@code kid} = the active key id, {@code typ} =
 * {@code secevent+jwt} per RFC 8417 §2.3.
 */
public final class SetMinter {

    private static final String SET_TYP = "secevent+jwt";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String algorithm;
    private volatile SigningKeyProvider signingKeyProvider;

    /** Runtime constructor: resolves the PF JWKS signing key lazily on first use. */
    public SetMinter(String algorithm) {
        this(algorithm, null);
    }

    /** Test/seam constructor: use the supplied signing key provider instead of PF's. */
    public SetMinter(String algorithm, SigningKeyProvider signingKeyProvider) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.signingKeyProvider = signingKeyProvider;
    }

    /** Sign {@code set} and return its compact serialization. */
    public String sign(SecurityEventToken set) throws JoseException {
        SigningKeyProvider keys = resolveSigningKeyProvider();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(JsonUtil.toJson(set.toClaims()));
        jws.setKey((Key) keys.privateKey());
        jws.setAlgorithmHeaderValue(this.algorithm);
        jws.setKeyIdHeaderValue(keys.keyId());
        jws.setHeader("typ", SET_TYP);
        return jws.getCompactSerialization();
    }

    private SigningKeyProvider resolveSigningKeyProvider() {
        SigningKeyProvider local = this.signingKeyProvider;
        if (local == null) {
            synchronized (this) {
                if (this.signingKeyProvider == null) {
                    this.signingKeyProvider = new PfJwksSigningKeyProvider(this.algorithm);
                }
                local = this.signingKeyProvider;
            }
        }
        return local;
    }

    /** A fresh 128-bit base64url {@code jti}. */
    public static String newJti() {
        byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** Current time as epoch seconds, for {@code iat}/{@code event_timestamp}. */
    public static long nowSeconds() {
        return System.currentTimeMillis() / 1000L;
    }
}
