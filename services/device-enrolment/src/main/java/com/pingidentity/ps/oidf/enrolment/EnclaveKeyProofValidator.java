/*
 * Verifies that the caller holds the Secure Enclave key bound to an instance.
 */
package com.pingidentity.ps.oidf.enrolment;

import com.pingidentity.ps.oidf.jose.Jwks;
import java.security.Key;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * Validates a proof that the caller controls the Secure Enclave key an instance was enrolled with.
 *
 * <p>The proof is a compact JWS carrying the public key in its {@code jwk} header — the DPoP shape —
 * signed by the matching private key. The registry stores only the RFC 7638 thumbprint, so the
 * presented key is thumbprint-matched against it. That is what binds the proof to <em>this</em>
 * instance rather than to any key the caller happens to own.
 *
 * <p><strong>What this proof does not establish, and it matters:</strong> it does not show that the
 * user was recently verified. The enclave key is biometry-gated, so a signature implies user
 * verification happened at <em>some</em> point — but the app may be holding a pre-authenticated
 * {@code LAContext}, which Apple documents no expiry for, so "at some point" could be hours ago. Only
 * {@code uv_last_verified_at} in the registry, refreshed by a verifiable IdP authentication, bounds
 * that. See {@link EnrolmentService#reissue}.
 */
public final class EnclaveKeyProofValidator {

    /** The proof media type. Mirrors the workload attester's issuance-side proof. */
    public static final String TYP = "oauth-attestation-instance-proof+jwt";

    /** ES256 only: a Secure Enclave does P-256 and nothing else, so anything else is not that key. */
    private static final Set<String> PERMITTED_ALGORITHMS = Set.of("ES256");

    private final long maxAgeSeconds;
    private final long allowedClockSkewSeconds;

    public EnclaveKeyProofValidator() {
        this(300L, 60L);
    }

    public EnclaveKeyProofValidator(long maxAgeSeconds, long allowedClockSkewSeconds) {
        this.maxAgeSeconds = maxAgeSeconds;
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    /**
     * Verifies a proof against the thumbprint recorded at enrolment.
     *
     * @param proof            the compact JWS
     * @param expectedJkt      the instance's {@code cnf_jkt}
     * @param expectedAudience this service's identifier
     * @return the proof's {@code jti} and {@code challenge}, for replay and challenge consumption
     */
    public Result validate(String proof, String expectedJkt, String expectedAudience)
            throws EnrolmentException {
        if (proof == null || proof.isBlank()) {
            throw EnrolmentException.invalidKeyProof("no key proof presented");
        }

        JsonWebSignature jws = new JsonWebSignature();
        String algorithm;
        Map<String, Object> presentedJwk;
        try {
            jws.setCompactSerialization(proof);
            algorithm = jws.getAlgorithmHeaderValue();
            String typ = jws.getHeader("typ");
            if (typ != null && !TYP.equals(typ)) {
                throw EnrolmentException.invalidKeyProof("key proof has an unexpected 'typ': " + typ);
            }
            Object jwkHeader = jws.getHeaders().getObjectHeaderValue("jwk");
            if (!(jwkHeader instanceof Map)) {
                throw EnrolmentException.invalidKeyProof("key proof carries no 'jwk' header");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> asMap = (Map<String, Object>) jwkHeader;
            presentedJwk = asMap;
        } catch (EnrolmentException e) {
            throw e;
        } catch (Exception e) {
            throw EnrolmentException.invalidKeyProof("key proof is not a well-formed compact JWS");
        }

        if (algorithm == null || !PERMITTED_ALGORITHMS.contains(algorithm)) {
            throw EnrolmentException.invalidKeyProof(
                    "key proof algorithm " + algorithm + " is not ES256");
        }
        // A private key in the header would mean the client just published its enclave key — which a
        // real enclave key cannot be, so this is either a bug or an impostor.
        try {
            Jwks.assertPublicOnly(presentedJwk);
        } catch (RuntimeException e) {
            throw EnrolmentException.invalidKeyProof("key proof 'jwk' must be a public key");
        }

        String presentedJkt;
        try {
            presentedJkt = Jwks.thumbprint(presentedJwk);
        } catch (Exception e) {
            throw EnrolmentException.invalidKeyProof("key proof 'jwk' is not a well-formed JWK");
        }
        if (!presentedJkt.equals(expectedJkt)) {
            throw EnrolmentException.invalidKeyProof(
                    "key proof is signed by a key that is not the one bound to this instance");
        }

        try {
            Key key = Jwks.publicKey(presentedJwk);
            jws.setKey(key);
            jws.setAlgorithmConstraints(
                    new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, algorithm));
            if (!jws.verifySignature()) {
                throw EnrolmentException.invalidKeyProof("key proof signature did not verify");
            }
        } catch (EnrolmentException e) {
            throw e;
        } catch (Exception e) {
            throw EnrolmentException.invalidKeyProof("key proof signature could not be verified");
        }

        JwtClaims claims;
        try {
            claims = JwtClaims.parse(jws.getUnverifiedPayload());
        } catch (Exception e) {
            throw EnrolmentException.invalidKeyProof("key proof payload is not valid JWT claims");
        }

        try {
            if (!claims.getAudience().contains(expectedAudience)) {
                throw EnrolmentException.invalidKeyProof("key proof audience is not this service");
            }
        } catch (EnrolmentException e) {
            throw e;
        } catch (Exception e) {
            throw EnrolmentException.invalidKeyProof("key proof has no usable 'aud'");
        }

        String jti = claims.getClaimValueAsString("jti");
        if (jti == null || jti.isBlank()) {
            throw EnrolmentException.invalidKeyProof("key proof has no 'jti'");
        }

        try {
            if (claims.hasClaim("iat")) {
                long iat = claims.getIssuedAt().getValue();
                long now = NumericDate.now().getValue();
                if (iat > now + this.allowedClockSkewSeconds) {
                    throw EnrolmentException.invalidKeyProof("key proof is issued in the future");
                }
                if (iat < now - this.maxAgeSeconds - this.allowedClockSkewSeconds) {
                    throw EnrolmentException.invalidKeyProof("key proof is too old");
                }
            }
        } catch (EnrolmentException e) {
            throw e;
        } catch (Exception e) {
            throw EnrolmentException.invalidKeyProof("key proof 'iat' is malformed");
        }

        return new Result(jti, claims.getClaimValueAsString("challenge"), presentedJwk);
    }

    /** What the caller needs from a verified proof. */
    public record Result(String jti, String challenge, Map<String, Object> publicJwk) {

        /** The presented key as a jose4j JWK, for minting the {@code cnf}. */
        public JsonWebKey asJsonWebKey() throws Exception {
            return Jwks.fromMap(this.publicJwk);
        }
    }
}
