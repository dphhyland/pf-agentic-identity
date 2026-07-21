/*
 * Validates the workload's proof of possession of its instance (cnf) key at issuance time.
 */
package com.pingidentity.ps.oidf.common;

import java.security.Key;
import java.util.List;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jws.JsonWebSignature;

/**
 * Verifies that an attestation-issuance request truly comes from the holder of the instance key it asks
 * to have bound as {@code cnf}. The workload signs a small proof-of-possession JWS
 * (header {@code typ=oauth-attestation-instance-proof+jwt}) with its instance private key; this validator
 * verifies that signature against the <em>presented</em> instance public JWK — so a caller cannot ask for
 * a key it does not control — and checks the proof's {@code aud} (the attester issuer), {@code jti}
 * (returned for replay detection), freshness ({@code iat}), and optional server {@code challenge}.
 *
 * <p>Freshness/replay state (challenge consumption, {@code jti}) is enforced by the caller via
 * {@link AttestationSupport}; this validator is pure (signature + claim shape) and unit-testable.
 */
public final class InstanceKeyProofValidator {

    public static final String TYP = "oauth-attestation-instance-proof+jwt";
    private static final Set<String> PERMITTED_ALGORITHMS = ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS;

    private final long maxAgeSeconds;
    private final long allowedClockSkewSeconds;

    public InstanceKeyProofValidator() {
        this(ClientAttestationConfig.DEFAULT_POP_MAX_AGE_SECONDS, ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS);
    }

    public InstanceKeyProofValidator(long maxAgeSeconds, long allowedClockSkewSeconds) {
        this.maxAgeSeconds = maxAgeSeconds;
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    /** The validated proof's replay-relevant fields. */
    public record Result(String jti, String challenge) {
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

        long now = NumericDate.now().getValue();
        try {
            if (claims.hasClaim("iat")) {
                long iat = claims.getIssuedAt().getValue();
                if (iat - this.allowedClockSkewSeconds > now) {
                    throw IssuanceException.invalidInstanceProof("proof 'iat' is in the future");
                }
                if (iat + this.maxAgeSeconds + this.allowedClockSkewSeconds < now) {
                    throw IssuanceException.invalidInstanceProof("proof is stale");
                }
            }
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceProof("proof 'iat' is malformed");
        }

        String challenge = claims.getClaimValueAsString("challenge");
        return new Result(jti, challenge);
    }
}
