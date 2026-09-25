/*
 * This deployment's policy, then an external one.
 */
package com.pingidentity.ps.oidf.federation.policy;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * The local policy first - a local denial is final, and the external decision point is not asked - then the external
 * one. A permit from both carries the obligations of both.
 */
public final class CompositePolicyDecisionPoint implements FederationPolicyDecisionPoint {
    private final FederationPolicyDecisionPoint local;
    private final FederationPolicyDecisionPoint external;

    public CompositePolicyDecisionPoint(FederationPolicyDecisionPoint local, FederationPolicyDecisionPoint external) {
        this.local = Objects.requireNonNull(local, "local");
        this.external = Objects.requireNonNull(external, "external");
    }

    @Override
    public PolicyDecision decide(PolicyDecisionRequest request) throws PolicyDecisionException {
        PolicyDecision first = this.local.decide(request);
        if (!first.permitted()) {
            return first;
        }
        PolicyDecision second = this.external.decide(request);
        if (!second.permitted()) {
            return second;
        }
        Set<String> ignored = new LinkedHashSet<>(first.ignoredContextKeys());
        ignored.addAll(second.ignoredContextKeys());
        return new PolicyDecision(true, first.obligations().and(second.obligations()), second.reasonAdmin(), second.reasonUser(),
                second.pdpRequestId(), first.latencyMs() + second.latencyMs(), ignored);
    }
}
