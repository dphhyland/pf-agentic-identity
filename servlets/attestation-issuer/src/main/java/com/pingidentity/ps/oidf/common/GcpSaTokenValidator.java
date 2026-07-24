/*
 * EvidenceValidator for Google-signed service-account ID tokens (Agent Engine / Cloud Run / GCE).
 */
package com.pingidentity.ps.oidf.common;

import java.security.Key;
import java.util.List;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * The {@code gcp-id-token} evidence type: a Google-signed OIDC ID token for a GCP service account,
 * obtained by the workload with a custom audience (the metadata server's {@code identity} endpoint, or
 * IAM Credentials {@code generateIdToken}). This is the evidence available to workloads whose platform
 * identity is a service account rather than a Kubernetes one — <em>Gemini Enterprise Agent Platform /
 * Agent Engine agents</em>, Cloud Run services, and GCE instances all qualify — so it extends attestation
 * to Google-hosted agents without any SPIFFE infrastructure of their own.
 *
 * <p>The token's {@code sub} is the service account's opaque numeric id; the stable human-meaningful
 * identifier is the {@code email} claim, so the mapped SPIFFE ID is
 * {@code spiffe://<attestation_trust_domain>/sa/<email>} (the trust domain is required in this mode and
 * names the identifier namespace — e.g. {@code <project>.gcp.example} by deployment convention; Google
 * defines no canonical SPIFFE mapping for bare service accounts). Bindings then list exactly the service
 * accounts permitted to act as instances of the client.
 *
 * <p>Checks mirror the other validators: signature under an asymmetric-only constraint with the bundle
 * key selected by {@code kid} (the bundle is Google's rotating JWKS — configure it by URL);
 * {@code iss} must equal the client's pinned {@code attestation_evidence_issuer}
 * ({@code https://accounts.google.com}) when set; {@code aud} must include the attester issuer;
 * {@code exp} required and unexpired; {@code email} required. Failures throw {@code invalid_svid}.
 */
public final class GcpSaTokenValidator implements EvidenceValidator {

    private static final Set<String> PERMITTED_ALGORITHMS = ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS;

    private final long allowedClockSkewSeconds;

    public GcpSaTokenValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS);
    }

    public GcpSaTokenValidator(long allowedClockSkewSeconds) {
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    @Override
    public SpiffeSvid validate(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException {
        if (evidence == null || evidence.isBlank()) {
            throw IssuanceException.invalidSvid("no ID token presented");
        }
        if (bundleKeys == null || bundleKeys.isEmpty()) {
            throw IssuanceException.invalidSvid("no trust bundle configured for this client");
        }
        String trustDomain = config.expectedTrustDomain();
        if (trustDomain == null || trustDomain.isBlank()) {
            throw IssuanceException.invalidClient(
                    AttestationIssuanceConfig.P_TRUST_DOMAIN + " is required for gcp-id-token evidence");
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

        String email = claims.getClaimValueAsString("email");
        if (email == null || email.isBlank()) {
            throw IssuanceException.invalidSvid("token has no 'email' (service-account identity) claim");
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

        String path = "/sa/" + email;
        String spiffeId = "spiffe://" + trustDomain + path;
        return new SpiffeSvid(spiffeId, trustDomain, path, audiences, exp, iat, evidence);
    }
}
