/*
 * Parsed DPoP proof JWT (RFC 9449) as used for attestation "combined mode".
 */
package com.pingidentity.ps.oidf.common;

import org.jose4j.jwk.JsonWebKey;

/**
 * Immutable view of a signature-verified DPoP proof. In attestation combined mode
 * (PoP method {@code dpop_combined}) the proof's {@code jwk} header MUST equal the attestation
 * {@code cnf} key, and a server-issued challenge (if any) is carried in the {@code nonce} claim.
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
