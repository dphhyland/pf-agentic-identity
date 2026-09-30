/*
 * EvidenceValidator for GKE-projected Kubernetes service-account tokens (Google-native identity).
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;

/**
 * The {@code gke-sa-token} evidence type: a Kubernetes service-account token projected by GKE with a custom audience
 * (a pod {@code serviceAccountToken} volume), verified against the cluster's JWKS. Its {@code sub},
 * {@code system:serviceaccount:<ns>:<sa>}, maps onto Google's identifier for the workload,
 * {@code spiffe://<attestation_trust_domain>/ns/<ns>/sa/<sa>} (the trust domain {@code PROJECT_ID.svc.id.goog}).
 *
 * <p>Beyond {@link CloudTokenValidator}'s checks: when {@code OIDF_ATTESTER_GCP_PROJECTS} is set, the project in the
 * cluster's issuer ({@code https://container.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/clusters/CLUSTER},
 * Google's identifier for "all Pods in a specific cluster") is one of them, and so is the project of a trust domain
 * of the form {@code PROJECT_ID.svc.id.goog}; and the client's bindings follow {@link GcpSaTokenValidator#checkWorkloadBindings}.
 */
public final class GkeTokenValidator extends CloudTokenValidator {

    /** A GKE cluster's issuer; group 1 is the project. Development's default when no issuer is pinned. */
    static final Pattern CLUSTER_ISSUER = Pattern.compile(
            "https://container\\.googleapis\\.com/v1/projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/locations/[a-z0-9-]+/clusters/[a-z0-9-]+");

    public GkeTokenValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, Policy::process);
    }

    public GkeTokenValidator(Policy policy) {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, () -> policy);
    }

    GkeTokenValidator(long allowedClockSkewSeconds, Supplier<Policy> policy) {
        super(allowedClockSkewSeconds, policy);
    }

    @Override
    public String id() {
        return AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN;
    }

    @Override
    public String title() {
        return "GKE projected service-account token";
    }

    @Override
    public String description() {
        return "A GKE-projected Kubernetes service-account token, verified against the cluster's OIDC "
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
    protected void checkBindings(AttestationIssuanceConfig config, Policy policy) throws IssuanceException {
        String problem = GcpSaTokenValidator.checkWorkloadBindings(config, policy.gcpProjects());
        if (problem != null) {
            throw misconfigured("binding_pattern", problem);
        }
    }

    @Override
    protected Mapped map(JwtClaims claims, Policy policy, AttestationIssuanceConfig config) throws IssuanceException {
        Set<String> projects = policy.gcpProjects();
        if (projects != null) {
            Matcher cluster = CLUSTER_ISSUER.matcher(claims.getClaimValueAsString("iss"));
            if (!cluster.matches() || !projects.contains(cluster.group(1))) {
                throw refused("project", "token's cluster is not in a project " + Policy.GCP_PROJECTS + " lists");
            }
        }
        return this.kubernetes(claims);
    }
}
