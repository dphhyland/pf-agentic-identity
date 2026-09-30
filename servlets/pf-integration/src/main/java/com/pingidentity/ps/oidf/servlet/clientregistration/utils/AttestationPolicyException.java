/*
 * A client's attestation property the server refuses.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

/**
 * A client's {@code attestation_*} extended property that does not parse or would loosen the server's policy. It names
 * the client and the property, never the value: the message is for the log and the health detail, and the client is
 * told only {@link #CLIENT_DESCRIPTION}.
 */
public final class AttestationPolicyException extends Exception {
    private static final long serialVersionUID = 1L;

    /** What the refused client is told: generic, as the plan's H-FED-4 rule has client errors. */
    public static final String CLIENT_DESCRIPTION = "the client's attestation policy is not valid";

    private final String clientId;
    private final String property;
    private final String problem;

    AttestationPolicyException(String clientId, String property, String problem, String why) {
        super(property + " on client " + clientId + " " + why);
        this.clientId = clientId;
        this.property = property;
        this.problem = problem;
    }

    public String clientId() {
        return this.clientId;
    }

    public String property() {
        return this.property;
    }

    /** One of {@code unparsable}, {@code loosens}, {@code empty_intersection}, {@code foreign_htu}. */
    public String problem() {
        return this.problem;
    }
}
