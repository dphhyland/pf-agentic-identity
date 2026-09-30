/*
 * EvidenceValidator for AKS-projected Kubernetes service-account tokens (Azure Workload Identity Federation).
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;

/**
 * The {@code aks-sa-token} evidence type: a Kubernetes service-account token projected by AKS (Azure Workload
 * Identity Federation) with a custom audience, verified against the cluster's JWKS (at {@code <issuer>openid/v1/jwks})
 * and mapped onto {@code spiffe://<attestation_trust_domain>/ns/<ns>/sa/<sa>}, the path GKE and EKS use too.
 *
 * <p>A Kubernetes token carries no {@code tid}: the cluster's pinned issuer ({@code az aks show --query
 * oidcIssuerProfile.issuerUrl}, on {@code https://<region>.oic.prod-aks.azure.com}) is what holds it to a tenant.
 * When a token does carry {@code tid} and {@code OIDF_ATTESTER_AZURE_TENANTS} is set, it must be one of them.
 */
public final class AksWorkloadIdentityValidator extends CloudTokenValidator {

    /** An AKS cluster's issuer on Microsoft's default base URL: development's default when no issuer is pinned. */
    static final Pattern CLUSTER_ISSUER = Pattern.compile(
            "https://[a-z0-9]+\\.oic\\.prod-aks\\.azure\\.com/[0-9a-f-]{36}/[0-9a-f-]{36}/");

    public AksWorkloadIdentityValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, Policy::process);
    }

    public AksWorkloadIdentityValidator(Policy policy) {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, () -> policy);
    }

    AksWorkloadIdentityValidator(long allowedClockSkewSeconds, Supplier<Policy> policy) {
        super(allowedClockSkewSeconds, policy);
    }

    @Override
    public String id() {
        return AttestationIssuanceConfig.EVIDENCE_AKS_SA_TOKEN;
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
    public List<String> selectorNames() {
        return KUBERNETES_SELECTORS;
    }

    @Override
    protected Pattern developmentIssuer() {
        return CLUSTER_ISSUER;
    }

    @Override
    protected Mapped map(JwtClaims claims, Policy policy, AttestationIssuanceConfig config) throws IssuanceException {
        Set<String> tenants = policy.azureTenants();
        Object tid = claims.getClaimValue("tid");
        if (tid != null && tenants != null
                && !(tid instanceof String && tenants.contains(((String) tid).toLowerCase(Locale.ROOT)))) {
            throw refused("tenant", "token's tid is not a tenant " + Policy.AZURE_TENANTS + " lists");
        }
        return this.kubernetes(claims);
    }
}
