/*
 * Validates the workload's proof of possession of its instance (cnf) key at issuance time.
 */
package com.pingidentity.ps.oidf.issuer;

import java.security.Key;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jws.JsonWebSignature;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.jose.Jwks;

/**
 * Verifies that an attestation-issuance request truly comes from the holder of the instance key it asks
 * to have bound as {@code cnf}. The workload signs a small proof-of-possession JWS
 * (header {@code typ=oauth-attestation-instance-proof+jwt}) with its instance private key; this validator
 * verifies that signature against the <em>presented</em> instance public JWK — so a caller cannot ask for
 * a key it does not control — and checks the proof's {@code aud} (the attester issuer), {@code jti}
 * (returned for replay detection), its validity window ({@code iat} and {@code exp}), and optional server
 * {@code challenge}.
 *
 * <p><b>The window</b> (plan item S4c, finding F-0036). CAS §4.3 lists the proof's claims as "{@code aud} (the CAS
 * issuer identifier, REQUIRED), {@code iat} (REQUIRED), {@code exp} (REQUIRED, SHOULD be ≤ 5 minutes after
 * {@code iat}), {@code jti} (REQUIRED, unique)" and says "The CAS MUST [...] enforce {@code exp} with small clock
 * skew, and reject replayed {@code jti} values within the proof validity window". CAS §5.3.1 contradicts it:
 * "{@code iat} is not listed as required but, when present, MUST be validated for freshness (Section 4.3);
 * {@code exp}, when present, MUST be honoured." This validator follows §4.3 and makes its SHOULD a limit: both
 * claims are required, {@code exp} must be after {@code iat} and at most {@link #MAX_WINDOW_SECONDS} after it, and
 * the proof is refused before {@code iat - skew} and after {@code exp + skew}. It still meets every MUST of §5.3.1
 * ({@code aud} and {@code jti} required, {@code iat} validated, {@code exp} honoured). Without the rule a proof
 * with no {@code iat} had no end, and was accepted again once the replay store forgot its {@code jti}.
 *
 * <p>Replay state (challenge consumption, {@code jti}) is enforced by the caller through its
 * {@code AttestationReplayCache}, retained until {@link Result#retainUntilEpochSeconds()}: the last second the
 * proof could be accepted. This validator is pure (signature + claim shape + the clock) and unit-testable.
 */
public final class InstanceKeyProofValidator {

    public static final String TYP = "oauth-attestation-instance-proof+jwt";
    /** The longest {@code exp - iat} accepted: CAS §4.3's "SHOULD be ≤ 5 minutes after {@code iat}", as a limit. */
    public static final long MAX_WINDOW_SECONDS = 300L;
    /**
     * The one description every window refusal carries. CAS §4.6 gives {@code invalid_instance_proof} as "The
     * Instance Key Proof failed (signature, {@code aud}, expiry, replay, challenge)"; the description says what a
     * client has to send and never echoes the values it sent.
     */
    public static final String WINDOW_REFUSED = "the instance key proof is outside its validity window: 'iat' and "
            + "'exp' are required, with 'exp' after 'iat' by at most " + MAX_WINDOW_SECONDS + " s";
    private static final Set<String> PERMITTED_ALGORITHMS = ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS;

    private final long maxWindowSeconds;
    private final long allowedClockSkewSeconds;
    private final Clock clock;

    public InstanceKeyProofValidator() {
        this(MAX_WINDOW_SECONDS, ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS);
    }

    /**
     * @param maxWindowSeconds        the longest {@code exp - iat} accepted, at most {@link #MAX_WINDOW_SECONDS}
     * @param allowedClockSkewSeconds the skew allowed at each end of the window
     */
    public InstanceKeyProofValidator(long maxWindowSeconds, long allowedClockSkewSeconds) {
        this(maxWindowSeconds, allowedClockSkewSeconds, Clock.systemUTC());
    }

    /**
     * As {@link #InstanceKeyProofValidator(long, long)}, judging the window by {@code clock}.
     *
     * @throws IllegalArgumentException if the window is not between 1 and {@link #MAX_WINDOW_SECONDS}, or the skew
     *                                  is negative
     */
    public InstanceKeyProofValidator(long maxWindowSeconds, long allowedClockSkewSeconds, Clock clock) {
        if (maxWindowSeconds <= 0L || maxWindowSeconds > MAX_WINDOW_SECONDS) {
            throw new IllegalArgumentException("the proof window must be 1 to " + MAX_WINDOW_SECONDS + " s, got "
                    + maxWindowSeconds);
        }
        if (allowedClockSkewSeconds < 0L) {
            throw new IllegalArgumentException("the clock skew must not be negative, got " + allowedClockSkewSeconds);
        }
        this.maxWindowSeconds = maxWindowSeconds;
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * The validated proof's replay-relevant fields, plus the full claim map so the caller can apply
     * deployment-specific claim requirements (custom claims ride in the proof, signed by the instance key).
     *
     * @param retainUntilEpochSeconds {@code exp + skew}: the last second the proof can be accepted, and so how long
     *                                its {@code jti} has to be remembered
     */
    public record Result(String jti, String challenge, Map<String, Object> claims, long retainUntilEpochSeconds) {
    }

    /** The clock this validator judges windows by, for a caller that must agree with it. */
    public Clock clock() {
        return this.clock;
    }

    /**
     * @param proof             the compact proof JWS
     * @param instancePublicJwk the instance public JWK the request asks to bind (verifies the proof)
     * @param expectedAudience  the attester issuer the proof must be addressed to ({@code aud})
     * @throws IssuanceException {@code invalid_instance_proof} on any failure
     */
    public Result validate(String proof, java.util.Map<String, Object> instancePublicJwk, String expectedAudience)
            throws IssuanceException {
        if (proof == null || proof.isBlank()) {
            throw IssuanceException.invalidInstanceProof("no instance-key proof presented");
        }
        try {
            Jwks.assertPublicOnly(instancePublicJwk);
        } catch (RuntimeException e) {
            throw IssuanceException.invalidRequest("instance_key must be a public JWK: " + e.getMessage());
        }

        JsonWebSignature jws = new JsonWebSignature();
        String typ;
        String alg;
        try {
            jws.setCompactSerialization(proof);
            typ = jws.getHeader("typ");
            alg = jws.getAlgorithmHeaderValue();
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceProof("proof is not a well-formed compact JWS");
        }
        if (!TYP.equals(typ)) {
            throw IssuanceException.invalidInstanceProof("proof has wrong 'typ' (expected " + TYP + ")");
        }
        if (alg == null || !PERMITTED_ALGORITHMS.contains(alg)) {
            throw IssuanceException.invalidInstanceProof("proof uses an unsupported signing algorithm: " + alg);
        }

        Key key;
        try {
            key = Jwks.publicKey(instancePublicJwk);
        } catch (Exception e) {
            throw IssuanceException.invalidRequest("instance_key is not a usable public JWK");
        }
        jws.setKey(key);
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, alg));
        try {
            if (!jws.verifySignature()) {
                throw IssuanceException.invalidInstanceProof("proof signature does not match the presented instance_key");
            }
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceProof("proof signature verification failed");
        }

        JwtClaims claims;
        try {
            claims = JwtClaims.parse(jws.getPayload());
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceProof("proof payload is not valid JWT claims");
        }

        List<String> aud;
        try {
            aud = claims.getAudience();
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceProof("proof 'aud' is malformed");
        }
        if (aud == null || !aud.contains(expectedAudience)) {
            throw IssuanceException.invalidInstanceProof("proof audience does not include the attester issuer");
        }

        String jti;
        try {
            jti = claims.getJwtId();
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceProof("proof 'jti' is malformed");
        }
        if (jti == null || jti.isBlank()) {
            throw IssuanceException.invalidInstanceProof("proof has no 'jti'");
        }

        long retainUntil = this.checkWindow(claims);

        String challenge = claims.getClaimValueAsString("challenge");
        return new Result(jti, challenge, claims.getClaimsMap(), retainUntil);
    }

    /**
     * Holds the proof to its window and returns the last second it can be accepted, {@code exp + skew}.
     *
     * @throws IssuanceException {@code invalid_instance_proof} with {@link #WINDOW_REFUSED} when {@code iat} or
     *                           {@code exp} is missing or not a number, {@code exp} is not after {@code iat} or is
     *                           more than the window after it, or now is before {@code iat - skew} or after
     *                           {@code exp + skew}
     */
    private long checkWindow(JwtClaims claims) throws IssuanceException {
        long iat;
        long exp;
        try {
            if (claims.getIssuedAt() == null || claims.getExpirationTime() == null) {
                throw IssuanceException.invalidInstanceProof(WINDOW_REFUSED);
            }
            iat = claims.getIssuedAt().getValue();
            exp = claims.getExpirationTime().getValue();
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceProof(WINDOW_REFUSED);
        }
        long now = this.clock.millis() / 1000L;
        // Compared by differences, and the one difference that two absurd claims could overflow is checked, so an
        // iat far in the past and an exp far in the future are refused rather than wrapped into a short window.
        long window;
        try {
            window = Math.subtractExact(exp, iat);
        } catch (ArithmeticException e) {
            throw IssuanceException.invalidInstanceProof(WINDOW_REFUSED);
        }
        boolean windowShape = window > 0L && window <= this.maxWindowSeconds;
        boolean started = iat <= now || iat - now <= this.allowedClockSkewSeconds;
        boolean ended = exp < now && now - exp > this.allowedClockSkewSeconds;
        if (!windowShape || !started || ended) {
            throw IssuanceException.invalidInstanceProof(WINDOW_REFUSED);
        }
        return exp + this.allowedClockSkewSeconds;
    }
}
