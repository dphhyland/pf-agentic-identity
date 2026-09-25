/*
 * The decisions this deployment makes by itself.
 */
package com.pingidentity.ps.oidf.federation.policy;

import java.util.Set;

/**
 * The policy this deployment applies without asking anyone: every request is permitted, narrowed to the scopes the
 * operator allows federation clients ({@code OIDF_REGISTRATION_ALLOWED_SCOPES}) when there is such a list.
 */
public final class LocalFederationPolicyDecisionPoint implements FederationPolicyDecisionPoint {
    private final NarrowingObligations obligations;

    /** @param allowedScopes the scopes a federation client may keep; null for no limit */
    public LocalFederationPolicyDecisionPoint(Set<String> allowedScopes) {
        this.obligations = allowedScopes == null ? NarrowingObligations.NONE : new NarrowingObligations(allowedScopes, null, null, null, Set.of());
    }

    @Override
    public PolicyDecision decide(PolicyDecisionRequest request) {
        return PolicyDecision.permit(this.obligations);
    }
}
