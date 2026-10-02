/*
 * Fans a single observed event out to every subscribed stream as a signed SET.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.signals.CaepRiscEvents;
import com.pingidentity.ps.oidf.signals.SecurityEventToken;
import com.pingidentity.ps.oidf.signals.SetMinter;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.lang.JoseException;

/**
 * Turns one observed event (an event-type URI + subject + payload) into a signed SET per matching stream, and
 * enqueues each. A stream matches when it {@link #subscribes}: it is {@link StreamStatus#ENABLED}, its
 * {@code events_delivered} contains the event type, and it hears about the subject - because the subject was
 * added to it, or because the transmitter's {@code default_subjects} is {@code ALL}. Poll streams then drain
 * via the poll endpoint; push streams via {@link PushDeliveryService}. This is the bridge PF's event hooks
 * call (see the notification-publisher adapter) — kept transport-free so it unit-tests without PF.
 */
public final class SsfEventEmitter {

    /** One SET enqueued for one stream. */
    public static final class Emitted {
        private final String streamId;
        private final String jti;
        private final DeliveryMethod deliveryMethod;

        Emitted(String streamId, String jti, DeliveryMethod deliveryMethod) {
            this.streamId = streamId;
            this.jti = jti;
            this.deliveryMethod = deliveryMethod;
        }

        public String streamId() {
            return this.streamId;
        }

        public String jti() {
            return this.jti;
        }

        public DeliveryMethod deliveryMethod() {
            return this.deliveryMethod;
        }
    }

    private final SsfStore store;
    private final SetMinter minter;
    private final SsfConfiguration config;
    private final SetPublisher publisher;

    public SsfEventEmitter(SsfStore store, SetMinter minter, SsfConfiguration config) {
        this(store, minter, config, SetPublisher.NOOP);
    }

    public SsfEventEmitter(SsfStore store, SetMinter minter, SsfConfiguration config, SetPublisher publisher) {
        this.store = store;
        this.minter = minter;
        this.config = config;
        this.publisher = publisher != null ? publisher : SetPublisher.NOOP;
    }

    /**
     * Emit {@code eventType} about {@code subject} to every matching stream. Returns one {@link Emitted} per
     * stream a SET was enqueued for (empty if no stream subscribes this subject to this event).
     */
    public List<Emitted> emit(String eventType, SubjectId subject, Map<String, Object> payload) throws JoseException {
        return emit(eventType, subject, payload, null, null);
    }

    /**
     * The same, considering only the stream {@code onlyStreamId} when it is non-null. The stream must still
     * subscribe; naming it narrows the fan-out and admits nothing.
     */
    public List<Emitted> emit(String eventType, SubjectId subject, Map<String, Object> payload, String onlyStreamId)
            throws JoseException {
        return emit(eventType, subject, payload, onlyStreamId, null);
    }

    /**
     * The same, with the SETs' {@code txn} (plan item H-SSF-5). SSF 1.0 §4.1.9: "Transmitters SHOULD set the "txn" claim
     * value in Security Event Tokens (SETs). If the value is present, it MUST be unique to the underlying event that
     * caused the Transmitter to generate the Security Event Token (SET)." Every SET this call mints - one per stream
     * that hears the event - is from the one underlying event, so every one carries the same {@code txn}: the caller's
     * (PingFederate's {@code transactionid} for an audit record), or a new random value when the caller has none. Never
     * PingFederate's {@code trackingid}, which PingFederate's own log4j2.xml describes as "unique for a user session":
     * one browser's login and its later logout share it, and they are two underlying events.
     */
    public List<Emitted> emit(String eventType, SubjectId subject, Map<String, Object> payload, String onlyStreamId,
            String txn) throws JoseException {
        List<Emitted> out = new ArrayList<>();
        long now = SetMinter.nowSeconds();
        long expiresAt = this.config.setTtlSeconds() > 0 ? now + this.config.setTtlSeconds() : 0;
        String transaction = txn == null || txn.isBlank() ? SetMinter.newJti() : txn;
        for (Stream s : this.store.listStreams()) {
            if ((onlyStreamId != null && !onlyStreamId.equals(s.id())) || !subscribes(s, eventType, subject)) {
                continue;
            }
            String jti = SetMinter.newJti();
            SecurityEventToken set = SecurityEventToken.builder()
                    .issuer(this.config.issuer())
                    .audience(s.audience())
                    .jti(jti)
                    .issuedAt(now)
                    .txn(transaction)
                    .subjectId(subject)
                    .event(eventType, payload)
                    .build();
            String jws = this.minter.sign(set);
            this.store.enqueue(PendingSet.fresh(jti, s.id(), subject.canonicalKey(), eventType, jws, now, expiresAt));
            this.publisher.publish(eventType, subject.canonicalKey(), jws, now);
            SsfEvents.setEmitted(eventType);
            out.add(new Emitted(s.id(), jti, s.deliveryMethod()));
        }
        return out;
    }

    /**
     * Whether {@code s} hears {@code eventType} about {@code subject}: it is enabled, it delivers the type,
     * and either the subject was added to it or the transmitter's {@code default_subjects} is {@code ALL}
     * (SSF 1.0 §7.1.1; CAEP Interop Profile §2.4.4). The one rule every emission path applies - there is no
     * way to raise an event past it.
     */
    boolean subscribes(Stream s, String eventType, SubjectId subject) {
        return s.status() == StreamStatus.ENABLED && s.deliversEvent(eventType)
                && (this.config.defaultSubjectsAll() || this.store.hasSubject(s.id(), subject));
    }

    // ─────────────────────────── convenience emitters ───────────────────────────

    public List<Emitted> sessionRevoked(SubjectId subject, String reasonAdmin) throws JoseException {
        return sessionRevoked(subject, reasonAdmin, null);
    }

    /** CAEP 1.0 §3.1 session-revoked, the SETs carrying {@code txn} (null: a new one). */
    public List<Emitted> sessionRevoked(SubjectId subject, String reasonAdmin, String txn) throws JoseException {
        return emit(SsfEventTypes.CAEP_SESSION_REVOKED, subject,
                CaepRiscEvents.sessionRevoked(SetMinter.nowSeconds(), reasonAdmin), null, txn);
    }

    /**
     * CAEP 1.0 §3.6 session-established: "the Transmitter has established a new session for the subject". Its claims
     * ({@code fp_ua}, {@code acr}, {@code amr}, {@code ext_id}) are all optional and PingFederate's audit record carries
     * none of them, so the event is {@code event_timestamp} alone.
     */
    public List<Emitted> sessionEstablished(SubjectId subject, String txn) throws JoseException {
        return emit(SsfEventTypes.CAEP_SESSION_ESTABLISHED, subject, timestampOnly(), null, txn);
    }

    public List<Emitted> credentialChange(SubjectId subject, String credentialType, String changeType) throws JoseException {
        return credentialChange(subject, credentialType, changeType, null);
    }

    /**
     * CAEP 1.0 §3.3.1 credential-change. {@code credential_type} "MUST be one of the following strings, or any other
     * credential type supported mutually by the Transmitter and the Receiver" - this transmitter has agreed no other with
     * anyone, so only the ten CAEP registers are sent ({@link CaepRiscEvents#CREDENTIAL_TYPES}); {@code change_type} "MUST
     * be one of" create, revoke, update, delete. Anything else is refused here rather than sent as a guess.
     *
     * @throws IllegalArgumentException for a credential or change type CAEP does not register
     */
    public List<Emitted> credentialChange(SubjectId subject, String credentialType, String changeType, String txn)
            throws JoseException {
        if (!validCredentialType(credentialType)) {
            throw new IllegalArgumentException("credential_type '" + credentialType + "' is not one of CAEP 1.0's "
                    + CaepRiscEvents.CREDENTIAL_TYPES + "; not sent");
        }
        if (changeType == null || !CaepRiscEvents.CHANGE_TYPES.contains(changeType)) {
            throw new IllegalArgumentException("change_type '" + changeType + "' is not one of CAEP 1.0's "
                    + CaepRiscEvents.CHANGE_TYPES + "; not sent");
        }
        return emit(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, subject,
                CaepRiscEvents.credentialChange(SetMinter.nowSeconds(), credentialType, changeType), null, txn);
    }

    /** Whether {@code credentialType} is one of CAEP 1.0 §3.3.1's registered credential types. */
    public static boolean validCredentialType(String credentialType) {
        return credentialType != null && CaepRiscEvents.CREDENTIAL_TYPES.contains(credentialType);
    }

    /**
     * CAEP 1.0 §3.4 assurance-level-change. §3.4.1: {@code namespace} is "REQUIRED" (RFC8176, RFC6711, ISO-IEC-29115,
     * NIST-IAL, NIST-AAL, NIST-FAL, or an alias agreed with the receiver), {@code current_level} "REQUIRED",
     * {@code previous_level} "OPTIONAL", and {@code change_direction}, if present, "MUST be one of" increase or
     * decrease - so it is sent only as the caller gives it, never worked out by comparing two level names (shared-signals'
     * {@code CaepRiscEvents.assuranceLevelChange}, which does that, omits {@code namespace} and can write {@code unknown};
     * finding F-0400).
     *
     * @throws IllegalArgumentException for a blank namespace or current level, or a direction CAEP does not allow
     */
    public List<Emitted> assuranceLevelChange(SubjectId subject, String namespace, String previousLevel, String currentLevel,
            String changeDirection, String txn) throws JoseException {
        return emit(SsfEventTypes.CAEP_ASSURANCE_LEVEL_CHANGE, subject,
                assuranceLevelPayload(SetMinter.nowSeconds(), namespace, previousLevel, currentLevel, changeDirection), null, txn);
    }

    /** The CAEP 1.0 §3.4.1 payload, checked; see {@link #assuranceLevelChange}. */
    static Map<String, Object> assuranceLevelPayload(long eventTimestamp, String namespace, String previousLevel,
            String currentLevel, String changeDirection) {
        if (namespace == null || namespace.isBlank()) {
            throw new IllegalArgumentException("assurance-level-change needs a namespace (CAEP 1.0 §3.4.1)");
        }
        if (currentLevel == null || currentLevel.isBlank()) {
            throw new IllegalArgumentException("assurance-level-change needs a current_level (CAEP 1.0 §3.4.1)");
        }
        if (changeDirection != null && !"increase".equals(changeDirection) && !"decrease".equals(changeDirection)) {
            throw new IllegalArgumentException("change_direction must be increase or decrease (CAEP 1.0 §3.4.1), not '"
                    + changeDirection + "'");
        }
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("event_timestamp", eventTimestamp);
        p.put("namespace", namespace);
        p.put("current_level", currentLevel);
        if (previousLevel != null && !previousLevel.isBlank()) {
            p.put("previous_level", previousLevel);
        }
        if (changeDirection != null) {
            p.put("change_direction", changeDirection);
        }
        return p;
    }

    public List<Emitted> deviceComplianceChange(SubjectId subject, String previousStatus, String currentStatus,
                                                Map<String, Object> reasonAdmin) throws JoseException {
        return emit(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE, subject,
                CaepRiscEvents.deviceComplianceChange(SetMinter.nowSeconds(), previousStatus, currentStatus, reasonAdmin));
    }

    public List<Emitted> accountDisabled(SubjectId subject, String reason) throws JoseException {
        return accountDisabled(subject, reason, null);
    }

    /** RISC account-disabled, the SETs carrying {@code txn} (null: a new one). */
    public List<Emitted> accountDisabled(SubjectId subject, String reason, String txn) throws JoseException {
        return emit(SsfEventTypes.RISC_ACCOUNT_DISABLED, subject,
                CaepRiscEvents.accountDisabled(SetMinter.nowSeconds(), reason), null, txn);
    }

    public List<Emitted> accountEnabled(SubjectId subject) throws JoseException {
        return accountEnabled(subject, null);
    }

    /** RISC account-enabled, the SETs carrying {@code txn} (null: a new one). */
    public List<Emitted> accountEnabled(SubjectId subject, String txn) throws JoseException {
        return emit(SsfEventTypes.RISC_ACCOUNT_ENABLED, subject,
                CaepRiscEvents.accountEnabled(SetMinter.nowSeconds()), null, txn);
    }

    /**
     * RISC 1.0 §2.2 account-purged: "the account identified by the subject has been permanently deleted". "Attributes:
     * none", so the event is {@code event_timestamp} alone.
     */
    public List<Emitted> accountPurged(SubjectId subject, String txn) throws JoseException {
        return emit(SsfEventTypes.RISC_ACCOUNT_PURGED, subject, timestampOnly(), null, txn);
    }

    private static Map<String, Object> timestampOnly() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("event_timestamp", SetMinter.nowSeconds());
        return p;
    }
}
