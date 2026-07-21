/*
 * CAEP 1.0 and RISC 1.0 Security Event Token event-type URIs, plus the module's default advertised set.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.List;
import java.util.Set;

/**
 * Canonical event-type URIs for the two Shared Signals event families this transmitter emits:
 * CAEP (Continuous Access Evaluation Profile 1.0) and RISC (Risk Incident Sharing and Coordination 1.0).
 *
 * <p>These strings are the keys of the {@code events} object in an RFC 8417 Security Event Token and are
 * advertised in the transmitter configuration ({@code /.well-known/ssf-configuration}). They are stable
 * per the final CAEP/RISC specifications; do not abbreviate them on the wire.
 */
public final class SsfEventTypes {

    private static final String CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
    private static final String RISC = "https://schemas.openid.net/secevent/risc/event-type/";

    // CAEP 1.0
    public static final String CAEP_SESSION_REVOKED = CAEP + "session-revoked";
    public static final String CAEP_CREDENTIAL_CHANGE = CAEP + "credential-change";
    public static final String CAEP_ASSURANCE_LEVEL_CHANGE = CAEP + "assurance-level-change";
    public static final String CAEP_TOKEN_CLAIMS_CHANGE = CAEP + "token-claims-change";
    public static final String CAEP_DEVICE_COMPLIANCE_CHANGE = CAEP + "device-compliance-change";
    public static final String CAEP_SESSION_ESTABLISHED = CAEP + "session-established";

    // RISC 1.0
    public static final String RISC_ACCOUNT_DISABLED = RISC + "account-disabled";
    public static final String RISC_ACCOUNT_ENABLED = RISC + "account-enabled";
    public static final String RISC_ACCOUNT_PURGED = RISC + "account-purged";
    public static final String RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED = RISC + "account-credential-change-required";
    public static final String RISC_IDENTIFIER_CHANGED = RISC + "identifier-changed";
    public static final String RISC_IDENTIFIER_RECYCLED = RISC + "identifier-recycled";

    /**
     * The SSF "meta" verification event (SSF 1.0 §Verification). Emitted on demand so a receiver can confirm
     * an end-to-end delivery path before it depends on real events.
     */
    public static final String VERIFICATION = "https://schemas.openid.net/secevent/ssf/event-type/verification";

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

    private static final Set<String> KNOWN = Set.copyOf(ALL);

    /** True if {@code uri} is an event type this transmitter recognises. */
    public static boolean isKnown(String uri) {
        return uri != null && KNOWN.contains(uri);
    }

    private SsfEventTypes() {
    }
}
