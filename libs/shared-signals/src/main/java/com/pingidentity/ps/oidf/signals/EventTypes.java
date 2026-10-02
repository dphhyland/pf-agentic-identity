/*
 * CAEP 1.0, RISC 1.0 and SSF 1.0 Security Event Token event-type URIs.
 */
package com.pingidentity.ps.oidf.signals;

/**
 * Event-type URIs for the Shared Signals event families: CAEP (Continuous Access Evaluation Profile 1.0), RISC
 * (Risk Incident Sharing and Coordination 1.0) and SSF 1.0's own verification event.
 *
 * <p>These strings are the keys of the {@code events} object in an RFC 8417 Security Event Token. They are stable
 * per the final CAEP/RISC specifications; do not abbreviate them on the wire. Which of them a transmitter
 * advertises is the transmitter's business (servlets/ssf's {@code SsfEventTypes}).
 */
public final class EventTypes {

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

    private EventTypes() {
    }
}
