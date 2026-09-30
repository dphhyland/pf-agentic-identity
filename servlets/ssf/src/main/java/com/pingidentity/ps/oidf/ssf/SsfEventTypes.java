/*
 * The event types this transmitter advertises and emits: CAEP 1.0 and RISC 1.0 URIs from libs/shared-signals.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.signals.EventTypes;
import java.util.List;
import java.util.Set;

/**
 * The Shared Signals event types this transmitter emits: CAEP (Continuous Access Evaluation Profile 1.0) and RISC
 * (Risk Incident Sharing and Coordination 1.0). The URIs are shared-signals' {@link EventTypes}; the lists below -
 * what is advertised in the transmitter configuration ({@code /.well-known/ssf-configuration}) and what the CAEP
 * Interop Profile asks for - are this module's.
 */
public final class SsfEventTypes {

    // CAEP 1.0
    public static final String CAEP_SESSION_REVOKED = EventTypes.CAEP_SESSION_REVOKED;
    public static final String CAEP_CREDENTIAL_CHANGE = EventTypes.CAEP_CREDENTIAL_CHANGE;
    public static final String CAEP_ASSURANCE_LEVEL_CHANGE = EventTypes.CAEP_ASSURANCE_LEVEL_CHANGE;
    public static final String CAEP_TOKEN_CLAIMS_CHANGE = EventTypes.CAEP_TOKEN_CLAIMS_CHANGE;
    public static final String CAEP_DEVICE_COMPLIANCE_CHANGE = EventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE;
    public static final String CAEP_SESSION_ESTABLISHED = EventTypes.CAEP_SESSION_ESTABLISHED;

    // RISC 1.0
    public static final String RISC_ACCOUNT_DISABLED = EventTypes.RISC_ACCOUNT_DISABLED;
    public static final String RISC_ACCOUNT_ENABLED = EventTypes.RISC_ACCOUNT_ENABLED;
    public static final String RISC_ACCOUNT_PURGED = EventTypes.RISC_ACCOUNT_PURGED;
    public static final String RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED = EventTypes.RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED;
    public static final String RISC_IDENTIFIER_CHANGED = EventTypes.RISC_IDENTIFIER_CHANGED;
    public static final String RISC_IDENTIFIER_RECYCLED = EventTypes.RISC_IDENTIFIER_RECYCLED;

    /** The SSF verification event (SSF 1.0 §Verification). */
    public static final String VERIFICATION = EventTypes.VERIFICATION;

    /** Every event type this transmitter is capable of emitting, in advertisement order. */
    public static final List<String> ALL = List.of(
            CAEP_SESSION_REVOKED,
            CAEP_CREDENTIAL_CHANGE,
            CAEP_ASSURANCE_LEVEL_CHANGE,
            CAEP_TOKEN_CLAIMS_CHANGE,
            CAEP_DEVICE_COMPLIANCE_CHANGE,
            CAEP_SESSION_ESTABLISHED,
            RISC_ACCOUNT_DISABLED,
            RISC_ACCOUNT_ENABLED,
            RISC_ACCOUNT_PURGED,
            RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED,
            RISC_IDENTIFIER_CHANGED,
            RISC_IDENTIFIER_RECYCLED,
            VERIFICATION);

    /**
     * The three events the CAEP Interop Profile 1.0 profiles (§3): what a receiver certifying against it
     * asks for, and what a transmitter certifying against it has to be able to send.
     */
    public static final List<String> CAEP_INTEROP = List.of(
            CAEP_SESSION_REVOKED,
            CAEP_CREDENTIAL_CHANGE,
            CAEP_DEVICE_COMPLIANCE_CHANGE);

    private static final Set<String> KNOWN = Set.copyOf(ALL);

    /** True if {@code uri} is an event type this transmitter recognises. */
    public static boolean isKnown(String uri) {
        return uri != null && KNOWN.contains(uri);
    }

    /** True if {@code uri} is one of the CAEP Interop Profile's three events. */
    public static boolean isCaepInterop(String uri) {
        return uri != null && CAEP_INTEROP.contains(uri);
    }

    private SsfEventTypes() {
    }
}
