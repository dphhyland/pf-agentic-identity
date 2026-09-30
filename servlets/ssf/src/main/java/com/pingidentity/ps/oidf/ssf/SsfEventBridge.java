/*
 * Integration point PingFederate event hooks call to source CAEP/RISC SETs — best-effort, never breaks PF.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.signals.CaepRiscEvents;
import com.pingidentity.ps.oidf.signals.SubjectId;
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
 * {@link SubjectId}. An event that raises no SET is counted as {@code ssf.set.dropped} with its reason
 * ({@link SsfEvents}).
 *
 * <p>The overloads that take a {@code txn} carry PingFederate's transaction id into every SET the event raises (SSF
 * 1.0 §4.1.9, plan item H-SSF-5); the others let the emitter mint one per event.
 *
 * <p><strong>Duplicate suppression:</strong> more than one observer can see the same PF event — a SAML logout hits
 * both a hook and the audit log's {@code SLO} entry. The bridge suppresses a repeat emission of the same (event type,
 * subject) within a short window, so overlapping sources are safe to enable together.
 */
public final class SsfEventBridge {

    private static final Log LOGGER = LogFactory.getLog(SsfEventBridge.class);

    /** Same (type, subject) within this window = the same PF event seen by two observers. */
    static final long SUPPRESSION_WINDOW_MILLIS = 5_000L;
    private static final int SUPPRESSION_MAX_ENTRIES = 512;
    private static final Map<String, Long> RECENT = new ConcurrentHashMap<>();

    /** The {@code source} of an event a hook or an OGNL expression raised. */
    public static final String BRIDGE = "bridge";

    private SsfEventBridge() {
    }

    /** The emitter to use in place of the published transmitter's; tests only. */
    private static volatile SsfEventEmitter testEmitter;

    /** Test hook: emit through {@code emitter} (null: the published transmitter's again). */
    static void useEmitterForTests(SsfEventEmitter emitter) {
        testEmitter = emitter;
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
        return onSessionRevoked(subject, reasonAdmin, null, BRIDGE);
    }

    /** CAEP session-revoked, from {@code source}, the SETs carrying {@code txn} (null: a new one). */
    public static int onSessionRevoked(SubjectId subject, String reasonAdmin, String txn, String source) {
        return emit(subject, e -> e.sessionRevoked(subject, reasonAdmin, txn), SsfEventTypes.CAEP_SESSION_REVOKED, source);
    }

    /** CAEP session-revoked, subject given as an {@code iss}/{@code sub} pair (OGNL-friendly). */
    public static int onSessionRevoked(String iss, String sub, String reasonAdmin) {
        return onSessionRevoked(SubjectId.issSub(iss, sub), reasonAdmin);
    }

    /** CAEP 1.0 §3.6 session-established, from {@code source}, the SETs carrying {@code txn} (null: a new one). */
    public static int onSessionEstablished(SubjectId subject, String txn, String source) {
        return emit(subject, e -> e.sessionEstablished(subject, txn), SsfEventTypes.CAEP_SESSION_ESTABLISHED, source);
    }

    /** CAEP credential-change. */
    public static int onCredentialChange(SubjectId subject, String credentialType, String changeType) {
        return onCredentialChange(subject, credentialType, changeType, null, BRIDGE);
    }

    /**
     * CAEP credential-change, from {@code source}, the SETs carrying {@code txn} (null: a new one). A
     * {@code credentialType} that is not one of CAEP 1.0's registered types (null included) raises nothing and is
     * counted as {@code ssf.set.dropped} {@code credential_type}: it is not sent as a guess.
     */
    public static int onCredentialChange(SubjectId subject, String credentialType, String changeType, String txn,
            String source) {
        if (subject != null && !SsfEventEmitter.validCredentialType(credentialType)) {
            LOGGER.warn((Object) ("SSF credential-change not sent: the credential type is not one of CAEP 1.0's "
                    + CaepRiscEvents.CREDENTIAL_TYPES));
            SsfEvents.setDropped(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, source, SsfEvents.CREDENTIAL_TYPE);
            return 0;
        }
        return emit(subject, e -> e.credentialChange(subject, credentialType, changeType, txn),
                SsfEventTypes.CAEP_CREDENTIAL_CHANGE, source);
    }

    /**
     * CAEP 1.0 §3.4 assurance-level-change, for a hook or an OGNL expression that knows the levels (PingFederate's
     * audit records carry no level, so the audit source never raises it; {@code POST /ssf/events:emit} is the other way
     * in). {@code namespace} and {@code currentLevel} are required; {@code changeDirection} is increase, decrease or null.
     */
    public static int onAssuranceLevelChange(SubjectId subject, String namespace, String previousLevel,
            String currentLevel, String changeDirection) {
        return emit(subject, e -> e.assuranceLevelChange(subject, namespace, previousLevel, currentLevel, changeDirection,
                null), SsfEventTypes.CAEP_ASSURANCE_LEVEL_CHANGE, BRIDGE);
    }

    /** CAEP device-compliance-change; the reason is a sentence, tagged as English on the wire. */
    public static int onDeviceComplianceChange(SubjectId subject, String previousStatus, String currentStatus,
                                               String reasonAdmin) {
        return emit(subject, e -> e.deviceComplianceChange(subject, previousStatus, currentStatus,
                CaepRiscEvents.reasonAdmin(reasonAdmin)), SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE, BRIDGE);
    }

    /** RISC account-disabled (e.g. from a deprovisioning flow). */
    public static int onAccountDisabled(SubjectId subject, String reason) {
        return onAccountDisabled(subject, reason, null, BRIDGE);
    }

    /** RISC account-disabled, from {@code source}, the SETs carrying {@code txn} (null: a new one). */
    public static int onAccountDisabled(SubjectId subject, String reason, String txn, String source) {
        return emit(subject, e -> e.accountDisabled(subject, reason, txn), SsfEventTypes.RISC_ACCOUNT_DISABLED, source);
    }

    /** RISC account-disabled, subject given as an email (OGNL/SCIM-friendly). */
    public static int onAccountDisabledEmail(String email, String reason) {
        return onAccountDisabled(SubjectId.email(email), reason);
    }

    /** RISC account-enabled. */
    public static int onAccountEnabled(SubjectId subject) {
        return onAccountEnabled(subject, null, BRIDGE);
    }

    /** RISC account-enabled, from {@code source}, the SETs carrying {@code txn} (null: a new one). */
    public static int onAccountEnabled(SubjectId subject, String txn, String source) {
        return emit(subject, e -> e.accountEnabled(subject, txn), SsfEventTypes.RISC_ACCOUNT_ENABLED, source);
    }

    /** RISC 1.0 §2.2 account-purged, from {@code source}, the SETs carrying {@code txn} (null: a new one). */
    public static int onAccountPurged(SubjectId subject, String txn, String source) {
        return emit(subject, e -> e.accountPurged(subject, txn), SsfEventTypes.RISC_ACCOUNT_PURGED, source);
    }

    @FunctionalInterface
    private interface EmitCall {
        List<SsfEventEmitter.Emitted> apply(SsfEventEmitter emitter) throws Exception;
    }

    private static int emit(SubjectId subject, EmitCall call, String eventType, String source) {
        if (subject == null) {
            return 0;
        }
        String label = SsfEvents.shortName(eventType);
        try {
            if (suppressed(label, subject)) {
                SsfEvents.setDropped(eventType, source, SsfEvents.DUPLICATE);
                return 0;
            }
            SsfEventEmitter emitter = testEmitter;
            if (emitter == null && !SsfSupport.isConfigured()) {
                SsfEvents.setDropped(eventType, source, SsfEvents.NOT_STARTED);
                return 0;
            }
            int n = call.apply(emitter != null ? emitter : SsfSupport.eventEmitter()).size();
            if (n > 0) {
                recordEmission(label, subject);
            }
            return n;
        } catch (Exception | LinkageError | java.util.ServiceConfigurationError e) {
            // PingFederate's signing keys not linking included: signalling never breaks the flow that raised it
            LOGGER.warn((Object) ("SSF " + label + " emission skipped: " + e.getMessage()));
            SsfEvents.setDropped(eventType, source, SsfEvents.FAILED);
            return 0;
        }
    }
}
