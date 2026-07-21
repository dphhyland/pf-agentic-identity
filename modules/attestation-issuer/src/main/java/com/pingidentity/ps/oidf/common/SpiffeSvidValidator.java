/*
 * Validates a SPIFFE JWT-SVID against a trust-bundle JWKS.
 */
package com.pingidentity.ps.oidf.common;

import java.security.Key;
import java.util.List;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jws.JsonWebSignature;

/**
 * Verifies a SPIFFE JWT-SVID against a SPIFFE trust bundle (a JWKS of the trust domain's JWT authorities),
 * per the SPIFFE JWT-SVID and Trust Domain &amp; Bundle specifications. The SVID is deliberately minimal:
 * the SPIFFE ID is the {@code sub} ({@code spiffe://<trust-domain>/<path>}), {@code aud} is the array of
 * intended recipients, plus {@code exp} (and usually {@code iat}); it is signed (typically {@code ES256})
 * with a {@code kid} header selecting the bundle key.
 *
 * <p>Checks, in order: select the bundle key by header {@code kid}; verify the signature under an
 * asymmetric-only algorithm constraint; require {@code sub} and {@code exp}; reject if {@code exp} is past
 * (allowing a small skew); require the expected audience to appear in {@code aud}; and, when an expected
 * trust domain is supplied, require the {@code sub}'s trust domain to match. Any failure throws
 * {@link IssuanceException} {@code invalid_svid}.
 */
public final class SpiffeSvidValidator {

    /** Asymmetric JWS algorithms permitted for an SVID signature ({@code none} and symmetric are refused). */
    private static final Set<String> PERMITTED_ALGORITHMS = ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS;

    private final long allowedClockSkewSeconds;

    public SpiffeSvidValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS);
    }

    public SpiffeSvidValidator(long allowedClockSkewSeconds) {
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    /**
     * @param compactSvid       the compact JWT-SVID
     * @param bundleKeys        the trust domain's JWT-authority JWKS (public keys)
     * @param expectedAudience  the identifier this endpoint requires to appear in the SVID {@code aud}
     * @param expectedTrustDomain if non-null, the {@code sub}'s trust domain must equal this
     * @return the validated SVID
     * @throws IssuanceException {@code invalid_svid} on any failure
     */
    public SpiffeSvid validate(String compactSvid, List<JsonWebKey> bundleKeys, String expectedAudience,
                               String expectedTrustDomain) throws IssuanceException {
        if (compactSvid == null || compactSvid.isBlank()) {
            throw IssuanceException.invalidSvid("no SVID presented");
        }
        if (bundleKeys == null || bundleKeys.isEmpty()) {
            throw IssuanceException.invalidSvid("no trust bundle configured for this client");
        }
        if (expectedAudience == null || expectedAudience.isBlank()) {
            throw IssuanceException.invalidSvid("no expected audience configured");
        }

        JsonWebSignature jws = new JsonWebSignature();
        String kid;
        String alg;
        try {
            jws.setCompactSerialization(compactSvid);
            kid = jws.getKeyIdHeaderValue();
            alg = jws.getAlgorithmHeaderValue();
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("SVID is not a well-formed compact JWS");
        }
        if (alg == null || !PERMITTED_ALGORITHMS.contains(alg)) {
            throw IssuanceException.invalidSvid("SVID uses an unsupported signing algorithm: " + alg);
        }

        Key verificationKey = selectKey(bundleKeys, kid);
        jws.setKey(verificationKey);
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, alg));
        try {
            if (!jws.verifySignature()) {
                throw IssuanceException.invalidSvid("SVID signature did not verify against the trust bundle");
            }
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("SVID signature verification failed");
        }

        JwtClaims claims;
        try {
            claims = JwtClaims.parse(jws.getPayload());
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("SVID payload is not valid JWT claims");
        }

        String subject = claims.getClaimValueAsString("sub");
        if (subject == null || subject.isBlank()) {
            throw IssuanceException.invalidSvid("SVID has no 'sub' (SPIFFE ID)");
        }
        long now = NumericDate.now().getValue();
        long exp;
        try {
            if (!claims.hasClaim("exp")) {
                throw IssuanceException.invalidSvid("SVID has no 'exp'");
            }
            exp = claims.getExpirationTime().getValue();
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("SVID 'exp' is malformed");
        }
        if (exp + this.allowedClockSkewSeconds < now) {
            throw IssuanceException.invalidSvid("SVID has expired");
        }
        long iat = 0L;
        try {
            if (claims.hasClaim("iat")) {
                iat = claims.getIssuedAt().getValue();
            }
        } catch (Exception ignored) {
            iat = 0L;
        }

        List<String> audiences;
        try {
            audiences = claims.getAudience();
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("SVID 'aud' is malformed");
        }
        if (audiences == null || !audiences.contains(expectedAudience)) {
            throw IssuanceException.invalidSvid("SVID audience does not include this issuer: " + expectedAudience);
        }

        String[] parts = SpiffeSvid.parseId(subject);
        String trustDomain = parts[0];
        String path = parts[1];
        if (expectedTrustDomain != null && !expectedTrustDomain.isBlank() && !expectedTrustDomain.equals(trustDomain)) {
            throw IssuanceException.invalidSvid(
                    "SVID trust domain '" + trustDomain + "' does not match expected '" + expectedTrustDomain + "'");
        }

        return new SpiffeSvid(subject, trustDomain, path, audiences, exp, iat, compactSvid);
    }

    private static Key selectKey(List<JsonWebKey> bundleKeys, String kid) throws IssuanceException {
        JsonWebKey chosen = null;
        if (kid != null && !kid.isBlank()) {
            for (JsonWebKey k : bundleKeys) {
                if (kid.equals(k.getKeyId())) {
                    chosen = k;
                    break;
                }
            }
            if (chosen == null) {
                throw IssuanceException.invalidSvid("no trust-bundle key matches SVID kid: " + kid);
            }
        } else if (bundleKeys.size() == 1) {
            chosen = bundleKeys.get(0);
        } else {
            throw IssuanceException.invalidSvid("SVID has no kid and the trust bundle holds multiple keys");
        }
        if (!(chosen instanceof PublicJsonWebKey)) {
            throw IssuanceException.invalidSvid("trust-bundle key is not an asymmetric public key");
        }
        return ((PublicJsonWebKey) chosen).getPublicKey();
    }
}
