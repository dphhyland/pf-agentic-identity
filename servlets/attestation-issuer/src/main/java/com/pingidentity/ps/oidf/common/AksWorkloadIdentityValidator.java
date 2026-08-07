/*
 * EvidenceValidator for AKS-projected Kubernetes service-account tokens (Azure Workload Identity Federation).
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
 * The {@code aks-sa-token} evidence type: a Kubernetes service-account token projected by AKS (Azure
 * Workload Identity Federation) with a custom audience (a pod {@code serviceAccountToken} volume),
 * validated against the cluster's public OIDC JWKS. This is the Azure analogue of {@link GkeTokenValidator}
 * and {@link EksTokenValidator}: the token's {@code sub} is Kubernetes-shaped
 * ({@code system:serviceaccount:<ns>:<sa>}), so after verification it is mapped onto
 * {@code spiffe://<attestation_trust_domain>/ns/<ns>/sa/<sa>} — the identical path shape GKE/EKS use, so a
 * resource-side policy written against that shape already works across all three clouds; only the trust
 * domain distinguishes them.
 *
 * <p>The AKS cluster's OIDC issuer is discovered via {@code az aks show --query oidcIssuerProfile.issuerUrl}
 * (shape {@code https://<region>.oic.prod-aks.azure.com/<tenant-id>/<uuid>/}); configure
 * {@code attestation_bundle_url} to its JWKS at {@code <issuer>openid/v1/jwks}. Set the pod's federated
 * credential / projected-volume {@code audience} to this attester (do not rely on AKS's default audience).
 *
 * <p>Checks mirror {@link EksTokenValidator}: signature under an asymmetric-only constraint with the bundle
 * key selected by {@code kid}; {@code exp} required and unexpired; {@code aud} must include the attester
 * issuer; optionally {@code iss} must equal the client's pinned {@code attestation_evidence_issuer} (the AKS
 * cluster issuer URL). The trust domain is required in this mode. Failures throw {@code invalid_svid}.
 */
public final class AksWorkloadIdentityValidator implements InstanceAttestationValidator {

    /** Kubernetes service-account subject shape: {@code system:serviceaccount:<namespace>:<name>}. */
    private static final Pattern KSA_SUBJECT = Pattern.compile("system:serviceaccount:([^:]+):([^:]+)");

    private static final Set<String> PERMITTED_ALGORITHMS = ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS;

    private final long allowedClockSkewSeconds;

    public AksWorkloadIdentityValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS);
    }

    public AksWorkloadIdentityValidator(long allowedClockSkewSeconds) {
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    @Override
    public String id() {
        return AttestationIssuanceConfig.EVIDENCE_AKS_SA_TOKEN;
    }

    @Override
    public String format() {
        return SpiffeInstanceAttestationValidator.FORMAT;
    }

    /** The SPIFFE ID is built from the token's namespace/service-account, namespaced by the trust domain. */
    @Override
    public boolean requiresTrustDomain() {
        return true;
    }

    @Override
    public String title() {
        return "AKS projected service-account token (Workload Identity Federation)";
    }

    @Override
    public String description() {
        return "An AKS-projected Kubernetes service-account token (Azure Workload Identity Federation), "
                + "verified against the cluster's OIDC JWKS and mapped onto a SPIFFE ID under the configured "
                + "trust domain.";
    }

    @Override
    public InstanceIdentity validate(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
            throws IssuanceException {
        return InstanceIdentity.ofSpiffe(validateSvid(evidence, bundleKeys, config));
    }

    /**
     * The SPIFFE-typed validation, kept public so the mapping detail (trust domain, path, raw token) stays
     * independently assertable; {@link #validate} adapts the result to an {@link InstanceIdentity}.
     */
    public SpiffeSvid validateSvid(String evidence, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config)
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
                    AttestationIssuanceConfig.P_TRUST_DOMAIN + " is required for aks-sa-token evidence");
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

        String path = "/ns/" + matcher.group(1) + "/sa/" + matcher.group(2);
        String spiffeId = "spiffe://" + trustDomain + path;
        return new SpiffeSvid(spiffeId, trustDomain, path, audiences, exp, iat, evidence);
    }
}
