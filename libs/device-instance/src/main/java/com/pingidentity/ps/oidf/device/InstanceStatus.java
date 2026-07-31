/*
 * Lifecycle state of a registered agent instance.
 */
package com.pingidentity.ps.oidf.device;

/**
 * Whether an instance may still obtain tokens.
 *
 * <p>Revocation is the point of holding a durable instance record at all: setting an instance to
 * {@link #REVOKED} makes the next token request fail, with no need to reach the device, wait for an
 * attestation to expire, or revoke anything downstream.
 */
public enum InstanceStatus {

    /** May obtain tokens, subject to the other checks (device compliance, UV recency, entitlement). */
    ACTIVE,

    /** Temporarily barred — e.g. the device fell out of compliance. Reversible. */
    SUSPENDED,

    /** Permanently barred. Re-enrolment creates a new instance; a revoked identifier is never reused. */
    REVOKED;

    /** Only an active instance is a candidate for issuance; everything else fails closed. */
    public boolean canObtainTokens() {
        return this == ACTIVE;
    }
}
