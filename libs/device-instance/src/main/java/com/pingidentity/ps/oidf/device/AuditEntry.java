/*
 * One append-only audit record.
 */
package com.pingidentity.ps.oidf.device;

import java.time.Instant;

/**
 * An audit entry. The log is append-only and is the record a dispute is settled from, so entries are
 * never updated or deleted.
 *
 * <p>{@code eventCode} is a stable machine code, not prose. Every distinct refusal reason gets its own:
 * an "access denied" with no reason makes a production incident undiagnosable, which is the failure
 * this field exists to prevent.
 *
 * @param instanceId the instance concerned, or null for a device- or owner-level event
 * @param eventCode  a stable code, e.g. {@code instance_registered}, {@code instance_revoked}
 * @param detail     human-readable context
 * @param at         when it happened
 */
public record AuditEntry(String instanceId, String eventCode, String detail, Instant at) {

    /** Enrolment completed and an instance became active. */
    public static final String INSTANCE_REGISTERED = "instance_registered";
    /** An instance was permanently barred. */
    public static final String INSTANCE_REVOKED = "instance_revoked";
    /** An instance's status changed without being revoked. */
    public static final String INSTANCE_STATUS_CHANGED = "instance_status_changed";
    /** The owner completed user verification. */
    public static final String USER_VERIFIED = "user_verified";
    /** An attestation was minted. */
    public static final String ATTESTATION_ISSUED = "attestation_issued";
    /** A device's compliance posture changed. */
    public static final String COMPLIANCE_CHANGED = "compliance_changed";
}
