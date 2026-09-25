/*
 * No decision could be had.
 */
package com.pingidentity.ps.oidf.federation.policy;

/**
 * The policy decision point gave no decision: it could not be reached, answered with an HTTP error, or answered
 * something that is not a decision. Never a denial - AuthZEN §10.1.2: an HTTP error is "unrelated to the outcome of an
 * authorization decision" - so the caller decides what no decision means: refuse (the default), or go on.
 */
public class PolicyDecisionException extends Exception {
    private static final long serialVersionUID = 1L;

    public PolicyDecisionException(String message) {
        super(message);
    }

    public PolicyDecisionException(String message, Throwable cause) {
        super(message, cause);
    }
}
