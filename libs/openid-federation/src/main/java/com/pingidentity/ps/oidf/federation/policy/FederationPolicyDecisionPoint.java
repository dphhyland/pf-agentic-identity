/*
 * Where federation decisions can be handed off.
 */
package com.pingidentity.ps.oidf.federation.policy;

/**
 * Decides whether a federation request - a registration, an enrolment - may go ahead, and what it must be narrowed to.
 * The federation's own checks come first and always apply; a decision point can only refuse what they would allow, or
 * narrow it.
 */
public interface FederationPolicyDecisionPoint {

    /**
     * @throws PolicyDecisionException when no decision could be had
     */
    PolicyDecision decide(PolicyDecisionRequest request) throws PolicyDecisionException;
}
