/*
 * Integration point PingFederate event hooks call to source CAEP/RISC SETs — best-effort, never breaks PF.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
 *
 * <p><strong>Duplicate suppression:</strong> more than one observer can see the same PF event — a logout hits
 * both {@code LogoutEventFilter} and the audit log's {@code SLO} entry. The bridge suppresses a repeat emission
 * of the same (event type, subject) within a short window, so overlapping sources are safe to enable together.
 */
public final class SsfEventBridge {

    private static final Log LOGGER = LogFactory.getLog(SsfEventBridge.class);

    /** Same (type, subject) within this window = the same PF event seen by two observers. */
    static final long SUPPRESSION_WINDOW_MILLIS = 5_000L;
    private static final int SUPPRESSION_MAX_ENTRIES = 512;
    private static final Map<String, Long> RECENT = new ConcurrentHashMap<>();

    private SsfEventBridge() {
    }

    /** Test hook: forget recent emissions so suppression doesn't leak across tests. */
    static void resetRecentForTests() {
        RECENT.clear();
    }

    /** Records a successful emission so overlapping observers of the same PF event stay silent. */
    static void recordEmission(String label, SubjectId subject) {
        RECENT.put(label + '|' + subject.canonicalKey(), System.currentTimeMillis());
    }

    static boolean suppressed(String label, SubjectId subject) {
        long now = System.currentTimeMillis();
        String key = label + '|' + subject.canonicalKey();
        Long last = RECENT.get(key);
        if (last != null && now - last < SUPPRESSION_WINDOW_MILLIS) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug((Object) ("SSF " + label + ": duplicate within " + SUPPRESSION_WINDOW_MILLIS
                        + "ms for " + subject.canonicalKey() + " suppressed"));
            }
            return true;
        }
        if (RECENT.size() >= SUPPRESSION_MAX_ENTRIES) {
            Iterator<Map.Entry<String, Long>> it = RECENT.entrySet().iterator();
            while (it.hasNext()) {
                if (now - it.next().getValue() >= SUPPRESSION_WINDOW_MILLIS) {
                    it.remove();
                }
            }
        }
        return false;
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
            if (suppressed(label, subject)) {
                return 0;
            }
            int n = call.apply(SsfSupport.eventEmitter()).size();
            if (n > 0) {
                recordEmission(label, subject);
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug((Object) ("SSF " + label + ": emitted " + n + " SET(s) for "
                            + subject.canonicalKey()));
                }
            }
            return n;
        } catch (Exception e) {
            LOGGER.warn((Object) ("SSF " + label + " emission skipped: " + e.getMessage()));
            return 0;
        }
    }
}
