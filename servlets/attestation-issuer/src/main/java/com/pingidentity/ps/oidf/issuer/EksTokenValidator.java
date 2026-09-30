/*
 * EvidenceValidator for EKS-projected Kubernetes service-account tokens (IRSA).
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;

/**
 * The {@code eks-sa-token} evidence type: a Kubernetes service-account token projected by EKS (IRSA) with a custom
 * audience, verified against the cluster's JWKS (at {@code <issuer>/keys}) and mapped onto
 * {@code spiffe://<attestation_trust_domain>/ns/<ns>/sa/<sa>}. The cluster is its issuer,
 * {@code https://oidc.eks.<region>.amazonaws.com/id/<id>}, pinned in {@code OIDF_ATTESTER_EKS_SA_TOKEN_ISSUERS}: a
 * cluster's token carries no account, so the pin is the cluster and account check. Set the projected volume's
 * {@code audience} to this attester rather than IRSA's default {@code sts.amazonaws.com}.
 */
public final class EksTokenValidator extends CloudTokenValidator {

    /** An EKS cluster's issuer: development's default when no issuer is pinned. */
    static final Pattern CLUSTER_ISSUER = Pattern.compile("https://oidc\\.eks\\.[a-z0-9-]+\\.amazonaws\\.com/id/[A-Za-z0-9]+");

    public EksTokenValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, Policy::process);
    }

    public EksTokenValidator(Policy policy) {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, () -> policy);
    }

    EksTokenValidator(long allowedClockSkewSeconds, Supplier<Policy> policy) {
        super(allowedClockSkewSeconds, policy);
    }

    @Override
    public String id() {
        return AttestationIssuanceConfig.EVIDENCE_EKS_SA_TOKEN;
    }

    @Override
    public String title() {
        return "EKS projected service-account token (IRSA)";
    }

    @Override
    public String description() {
        return "An EKS-projected Kubernetes service-account token, verified against the cluster's OIDC "
                + "JWKS and mapped onto a SPIFFE ID under the configured trust domain.";
    }

    @Override
    public List<String> selectorNames() {
        return KUBERNETES_SELECTORS;
    }

    @Override
    protected Pattern developmentIssuer() {
        return CLUSTER_ISSUER;
    }

    @Override
    protected Mapped map(JwtClaims claims, Policy policy, AttestationIssuanceConfig config) throws IssuanceException {
        return this.kubernetes(claims);
    }
}
