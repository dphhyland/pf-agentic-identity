/*
 * Integration point PingFederate event hooks call to source CAEP/RISC SETs — best-effort, never breaks PF.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The seam between PingFederate's runtime events and SSF emission. Whatever observes a PF event — a
 * Notification Publisher plugin, an OGNL issuance criterion, a logout/provisioning hook — calls one of these
 * static methods, which fan the event out to subscribed streams via {@link SsfSupport#eventEmitter()}.
 *
 * <p>Every method is <strong>best-effort</strong>: it catches everything and returns the number of SETs emitted
 * (0 on any failure, including "SSF not configured"). Signalling must never break PF's primary authentication or
 * provisioning flow. String-argument overloads exist so an OGNL expression can call in without constructing a
 * {@link SubjectId}.
 */
public final class SsfEventBridge {

    private static final Log LOGGER = LogFactory.getLog(SsfEventBridge.class);

    private SsfEventBridge() {
    }

    /** CAEP session-revoked (logout / admin revoke). */
    public static int onSessionRevoked(SubjectId subject, String reasonAdmin) {
        return emit(subject, e -> e.sessionRevoked(subject, reasonAdmin), "session-revoked");
    }

    /** CAEP session-revoked, subject given as an {@code iss}/{@code sub} pair (OGNL-friendly). */
    public static int onSessionRevoked(String iss, String sub, String reasonAdmin) {
        return onSessionRevoked(SubjectId.issSub(iss, sub), reasonAdmin);
    }

    /** CAEP credential-change. */
    public static int onCredentialChange(SubjectId subject, String credentialType, String changeType) {
        return emit(subject, e -> e.credentialChange(subject, credentialType, changeType), "credential-change");
    }

    /** RISC account-disabled (e.g. from a deprovisioning flow). */
    public static int onAccountDisabled(SubjectId subject, String reason) {
        return emit(subject, e -> e.accountDisabled(subject, reason), "account-disabled");
    }

    /** RISC account-disabled, subject given as an email (OGNL/SCIM-friendly). */
    public static int onAccountDisabledEmail(String email, String reason) {
        return onAccountDisabled(SubjectId.email(email), reason);
    }

    /** RISC account-enabled. */
    public static int onAccountEnabled(SubjectId subject) {
        return emit(subject, e -> e.accountEnabled(subject), "account-enabled");
    }

    @FunctionalInterface
    private interface EmitCall {
        List<SsfEventEmitter.Emitted> apply(SsfEventEmitter emitter) throws Exception;
    }

    private static int emit(SubjectId subject, EmitCall call, String label) {
        if (subject == null) {
            return 0;
        }
        try {
            int n = call.apply(SsfSupport.eventEmitter()).size();
            if (n > 0 && LOGGER.isDebugEnabled()) {
                LOGGER.debug((Object) ("SSF " + label + ": emitted " + n + " SET(s) for " + subject.canonicalKey()));
            }
            return n;
        } catch (Exception e) {
            LOGGER.warn((Object) ("SSF " + label + " emission skipped: " + e.getMessage()));
            return 0;
        }
    }
}
