/*
 * Maps verified inbound SETs to PF-side actions (the receiver's reason to exist).
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.Map;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The {@link SsfReceiverService.ReceivedSetHandler} that acts on inbound signals: a CAEP
 * {@code session-revoked} or RISC {@code account-disabled} / {@code account-credential-change-required}
 * about a subject revokes that subject's OAuth grants in PingFederate (killing refresh ability and
 * reference-token validation immediately). The PF call is behind {@link ReceiverActions} so this mapping is
 * unit-testable; the runtime implementation is {@code PfReceiverActions} (PF SDK
 * {@code AccessGrantManagerAccessor}). Best-effort: action failures are logged, never thrown.
 */
public final class ReceiverActionHandler implements SsfReceiverService.ReceivedSetHandler {

    /** The PF-side action surface (implemented against the PF SDK in the servlet layer). */
    public interface ReceiverActions {
        /** Revoke every OAuth grant belonging to {@code userKey}; returns the number revoked. */
        int revokeGrantsFor(String userKey);
    }

    private static final Log LOGGER = LogFactory.getLog(ReceiverActionHandler.class);

    private final ReceiverActions actions;

    public ReceiverActionHandler(ReceiverActions actions) {
        this.actions = Objects.requireNonNull(actions, "actions");
    }

    @Override
    public void onSet(ReceivedSet set) {
        if (!set.hasEvent(SsfEventTypes.CAEP_SESSION_REVOKED)
                && !set.hasEvent(SsfEventTypes.RISC_ACCOUNT_DISABLED)
                && !set.hasEvent(SsfEventTypes.RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED)) {
            return; // not a revocation-worthy signal (e.g. verification)
        }
        String userKey = userKeyOf(set.subjectId());
        if (userKey == null) {
            LOGGER.warn((Object) ("SSF receiver: revocation signal " + set.jti() + " has no usable subject"));
            return;
        }
        try {
            int revoked = this.actions.revokeGrantsFor(userKey);
            LOGGER.info((Object) ("SSF receiver: revoked " + revoked + " grant(s) for '" + userKey
                    + "' on signal " + set.events().keySet() + " (jti " + set.jti() + ")"));
        } catch (RuntimeException e) {
            LOGGER.warn((Object) ("SSF receiver: grant revocation failed for '" + userKey + "': " + e.getMessage()));
        }
    }

    /**
     * The PF user key a subject maps to: {@code iss_sub}→{@code sub}, {@code email}→the address,
     * {@code opaque}→{@code id}, {@code phone_number}/{@code account}→their value. Null if no subject.
     */
    static String userKeyOf(SubjectId subject) {
        if (subject == null) {
            return null;
        }
        Map<String, Object> m = subject.toMap();
        Object v;
        switch (subject.format()) {
            case SubjectId.FORMAT_ISS_SUB:
                v = m.get("sub");
                break;
            case SubjectId.FORMAT_EMAIL:
                v = m.get("email");
                break;
            case SubjectId.FORMAT_OPAQUE:
                v = m.get("id");
                break;
            case SubjectId.FORMAT_PHONE_NUMBER:
                v = m.get("phone_number");
                break;
            case SubjectId.FORMAT_ACCOUNT:
                v = m.get("uri");
                break;
            default:
                v = null;
        }
        return v instanceof String && !((String) v).isBlank() ? (String) v : null;
    }
}
