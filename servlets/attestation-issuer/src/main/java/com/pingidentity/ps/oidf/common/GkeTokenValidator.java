/*
 * EvidenceValidator for GKE-projected Kubernetes service-account tokens (Google-native identity).
 */
package com.pingidentity.ps.oidf.common;

import java.security.Key;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * The {@code gke-sa-token} evidence type: a Kubernetes service-account token projected by GKE with a
 * custom audience (a pod {@code serviceAccountToken} volume), validated against the cluster's public OIDC
 * JWKS. The token's {@code sub} is Kubernetes-shaped ({@code system:serviceaccount:<ns>:<sa>}), not a
 * SPIFFE ID, so after verification it is mapped onto Google's canonical SPIFFE identifier for GKE
 * workloads — {@code spiffe://PROJECT_ID.svc.id.goog/ns/<ns>/sa/<sa>} — using the client's pinned
 * {@code attestation_trust_domain} as the trust domain. Everything downstream (bindings, minting) then
 * works on the same identifiers Google documents for the workload.
 *
 * <p>Checks mirror {@link SpiffeSvidValidator}: signature under an asymmetric-only constraint with the
 * bundle key selected by {@code kid}; {@code exp} required and unexpired; {@code aud} must include the
 * attester issuer (the audience the pod volume projects); optionally {@code iss} must equal the client's
 * pinned {@code attestation_evidence_issuer} (the GKE cluster issuer URL). The trust domain is required in
 * this mode — enforced at config parse — because it names the identifier namespace the mapping mints into.
 * Failures throw {@code invalid_svid}, matching the SPIFFE path.
 */
public final class GkeTokenValidator implements EvidenceValidator {

    /** Kubernetes service-account subject shape: {@code system:serviceaccount:<namespace>:<name>}. */
    private static final Pattern KSA_SUBJECT = Pattern.compile("system:serviceaccount:([^:]+):([^:]+)");

    private static final Set<String> PERMITTED_ALGORITHMS = ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS;

    private final long allowedClockSkewSeconds;

    public GkeTokenValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS);
    }

    public GkeTokenValidator(long allowedClockSkewSeconds) {
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    @Override
    public SpiffeSvid validate(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException {
        if (evidence == null || evidence.isBlank()) {
            throw IssuanceException.invalidSvid("no service-account token presented");
        }
        if (bundleKeys == null || bundleKeys.isEmpty()) {
            throw IssuanceException.invalidSvid("no trust bundle configured for this client");
        }
        String trustDomain = config.expectedTrustDomain();
        if (trustDomain == null || trustDomain.isBlank()) {
            throw IssuanceException.invalidClient(
                    AttestationIssuanceConfig.P_TRUST_DOMAIN + " is required for gke-sa-token evidence");
        }

        JsonWebSignature jws = new JsonWebSignature();
        String kid;
        String alg;
        try {
            jws.setCompactSerialization(evidence);
            kid = jws.getKeyIdHeaderValue();
            alg = jws.getAlgorithmHeaderValue();
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("token is not a well-formed compact JWS");
        }
        if (alg == null || !PERMITTED_ALGORITHMS.contains(alg)) {
            throw IssuanceException.invalidSvid("token uses an unsupported signing algorithm: " + alg);
        }

        Key verificationKey = SpiffeSvidValidator.selectKey(bundleKeys, kid);
        jws.setKey(verificationKey);
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, alg));
        try {
            if (!jws.verifySignature()) {
                throw IssuanceException.invalidSvid("token signature did not verify against the trust bundle");
            }
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("token signature verification failed");
        }

        JwtClaims claims;
        try {
            claims = JwtClaims.parse(jws.getPayload());
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("token payload is not valid JWT claims");
        }

        String expectedIssuer = config.evidenceIssuer();
        String issuer = claims.getClaimValueAsString("iss");
        if (expectedIssuer != null && !expectedIssuer.equals(issuer)) {
            throw IssuanceException.invalidSvid(
                    "token issuer '" + issuer + "' does not match expected '" + expectedIssuer + "'");
        }

        String subject = claims.getClaimValueAsString("sub");
        if (subject == null || subject.isBlank()) {
            throw IssuanceException.invalidSvid("token has no 'sub'");
        }
        Matcher matcher = KSA_SUBJECT.matcher(subject);
        if (!matcher.matches()) {
            throw IssuanceException.invalidSvid("token 'sub' is not a Kubernetes service account: " + subject);
        }

        long now = NumericDate.now().getValue();
        long exp;
        try {
            if (!claims.hasClaim("exp")) {
                throw IssuanceException.invalidSvid("token has no 'exp'");
            }
            exp = claims.getExpirationTime().getValue();
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidSvid("token 'exp' is malformed");
        }
        if (exp + this.allowedClockSkewSeconds < now) {
            throw IssuanceException.invalidSvid("token has expired");
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
            throw IssuanceException.invalidSvid("token 'aud' is malformed");
        }
        if (audiences == null || !audiences.contains(config.issuer())) {
            throw IssuanceException.invalidSvid("token audience does not include this issuer: " + config.issuer());
        }

        // Google's canonical SPIFFE identifier for a GKE workload identity.
        String path = "/ns/" + matcher.group(1) + "/sa/" + matcher.group(2);
        String spiffeId = "spiffe://" + trustDomain + path;
        return new SpiffeSvid(spiffeId, trustDomain, path, audiences, exp, iat, evidence);
    }
}
