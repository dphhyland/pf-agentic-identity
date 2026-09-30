/*
 * Signs Security Event Tokens (RFC 8417, typ=secevent+jwt) behind oidf-jose's signer abstractions.
 */
package com.pingidentity.ps.oidf.signals;

import com.pingidentity.ps.oidf.jose.CompactJws;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

/**
 * Turns a {@link SecurityEventToken} into a signed compact JWS. The key is whoever supplies it: a
 * {@link SigningKeyProvider} (an RSA key pair and its id - in PingFederate, servlets/ssf hands over PingFederate's
 * active JWKS signing key, so a receiver validates SETs against the transmitter's advertised {@code jwks_uri}), or
 * a {@link JwsSigner} (a key in a vault or in process, any algorithm it signs with).
 *
 * <p>Header: {@code alg} (the configured one, or the signer's), {@code kid} (the key's id) and {@code typ} =
 * {@code secevent+jwt}. RFC 8417 §2.3 says the type "MUST be included if the SET could be used in an application
 * context in which it could be confused with other kinds of JWTs", and SSF 1.0 §4.1.1 that "SSF events MUST use
 * explicit typing".
 */
public final class SetMinter {

    /** The {@code typ} every SET carries (RFC 8417 §2.3: "the "typ" value used SHOULD be "secevent+jwt""). */
    public static final String SET_TYP = "secevent+jwt";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String algorithm;
    private final SigningKeyProvider signingKeyProvider;
    private final JwsSigner signer;

    /** Sign with an RSA key pair under {@code algorithm} (RS256 or PS256, say). */
    public SetMinter(String algorithm, SigningKeyProvider signingKeyProvider) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.signingKeyProvider = Objects.requireNonNull(signingKeyProvider, "signingKeyProvider");
        this.signer = null;
    }

    /** Sign with {@code signer}, whose algorithm and key id the header carries. */
    public SetMinter(JwsSigner signer) {
        this.signer = Objects.requireNonNull(signer, "signer");
        this.algorithm = signer.algorithm();
        this.signingKeyProvider = null;
    }

    /** The {@code alg} this minter's SETs carry. */
    public String algorithm() {
        return this.algorithm;
    }

    /** Sign {@code set} and return its compact serialization. */
    public String sign(SecurityEventToken set) throws JoseException {
        String payload = JsonUtil.toJson(set.toClaims());
        if (this.signer != null) {
            return CompactJws.sign(SET_TYP, payload, this.signer);
        }
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey((Key) this.signingKeyProvider.privateKey());
        jws.setAlgorithmHeaderValue(this.algorithm);
        jws.setKeyIdHeaderValue(this.signingKeyProvider.keyId());
        jws.setHeader("typ", SET_TYP);
        return jws.getCompactSerialization();
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
