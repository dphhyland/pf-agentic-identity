/*
 * A parsed, signature-verified DPoP proof JWT (RFC 9449).
 */
package com.pingidentity.ps.oidf.jose.dpop;

import org.jose4j.jwk.JsonWebKey;

/**
 * Immutable view of a signature-verified DPoP proof, as {@link DpopProofValidator} returns it. In attestation combined
 * mode (PoP method {@code dpop_combined}) the proof's {@code jwk} header must equal the attestation {@code cnf} key,
 * and a server-issued challenge (if any) is carried in the {@code nonce} claim; at a resource server the key's
 * thumbprint must be the access token's {@code cnf.jkt} and {@code ath} its hash.
 */
public final class DpopProof {
    private final JsonWebKey jwk;
    private final String htm;
    private final String htu;
    private final long iatEpochSeconds;
    private final String jti;
    private final String nonce;
    private final String ath;
    private final String raw;

    public DpopProof(JsonWebKey jwk, String htm, String htu, long iatEpochSeconds, String jti, String nonce, String ath, String raw) {
        this.jwk = jwk;
        this.htm = htm;
        this.htu = htu;
        this.iatEpochSeconds = iatEpochSeconds;
        this.jti = jti;
        this.nonce = nonce;
        this.ath = ath;
        this.raw = raw;
    }

    public JsonWebKey jwk() {
        return this.jwk;
    }

    public String htm() {
        return this.htm;
    }

    public String htu() {
        return this.htu;
    }

    public long iatEpochSeconds() {
        return this.iatEpochSeconds;
    }

    public String jti() {
        return this.jti;
    }

    public String nonce() {
        return this.nonce;
    }

    public String ath() {
        return this.ath;
    }

    public String raw() {
        return this.raw;
    }
}
