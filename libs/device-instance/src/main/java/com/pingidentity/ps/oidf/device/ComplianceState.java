/*
 * Device compliance as most recently reported by the authoritative source.
 */
package com.pingidentity.ps.oidf.device;

/**
 * The device's compliance posture, carrying the two values CAEP's {@code device-compliance-change}
 * event defines plus an explicit unknown.
 *
 * <p>{@link #UNKNOWN} is deliberate rather than an oversight: a device that has never been assessed is
 * not the same as one assessed and found compliant, and treating the two alike would let an unassessed
 * device inherit a compliant posture it never earned. Policy decides whether unknown is acceptable;
 * the registry only records what it was told.
 */
public enum ComplianceState {

    /** CAEP {@code current_status: compliant}. */
    COMPLIANT,

    /** CAEP {@code current_status: not-compliant}. */
    NOT_COMPLIANT,

    /** No assessment has been received for this device yet. */
    UNKNOWN;

    /** The CAEP claim value, or null for {@link #UNKNOWN} which CAEP has no encoding for. */
    public String caepValue() {
        return switch (this) {
            case COMPLIANT -> "compliant";
            case NOT_COMPLIANT -> "not-compliant";
            case UNKNOWN -> null;
        };
    }

    /** Maps a CAEP {@code previous_status}/{@code current_status} value; unrecognised input is UNKNOWN. */
    public static ComplianceState fromCaepValue(String value) {
        if ("compliant".equals(value)) {
            return COMPLIANT;
        }
        if ("not-compliant".equals(value)) {
            return NOT_COMPLIANT;
        }
        return UNKNOWN;
    }
}
