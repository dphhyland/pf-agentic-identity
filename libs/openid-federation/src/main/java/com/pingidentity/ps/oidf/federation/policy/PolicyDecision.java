/*
 * A policy decision point's answer.
 */
package com.pingidentity.ps.oidf.federation.policy;

import java.util.Objects;
import java.util.Set;

/**
 * A decision: permitted or not, what a permit is obliged to narrow, the reasons given - one for an administrator's log,
 * one that may be shown to the caller - and what the exchange cost.
 *
 * @param permitted          whether the request may go ahead
 * @param obligations        what a permit narrows; {@link NarrowingObligations#NONE} for a denial
 * @param reasonAdmin        why, for the server log only; may be null
 * @param reasonUser         why, fit to show the caller when the deployment allows it; may be null
 * @param pdpRequestId       the request id the decision point answered, when it gave one
 * @param latencyMs          how long it took
 * @param ignoredContextKeys members of the decision's context this deployment does not understand
 */
public record PolicyDecision(boolean permitted, NarrowingObligations obligations, String reasonAdmin, String reasonUser, String pdpRequestId,
                             long latencyMs, Set<String> ignoredContextKeys) {

    public PolicyDecision {
        obligations = permitted ? Objects.requireNonNull(obligations, "obligations") : NarrowingObligations.NONE;
        ignoredContextKeys = ignoredContextKeys == null ? Set.of() : Set.copyOf(ignoredContextKeys);
    }

    public static PolicyDecision permit(NarrowingObligations obligations) {
        return new PolicyDecision(true, obligations, null, null, null, 0L, Set.of());
    }

    public static PolicyDecision deny(String reasonAdmin, String reasonUser) {
        return new PolicyDecision(false, NarrowingObligations.NONE, reasonAdmin, reasonUser, null, 0L, Set.of());
    }
}
