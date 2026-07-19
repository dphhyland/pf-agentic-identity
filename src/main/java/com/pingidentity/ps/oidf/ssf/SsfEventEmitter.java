/*
 * Fans a single observed event out to every subscribed stream as a signed SET.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jose4j.lang.JoseException;

/**
 * Turns one observed event (an event-type URI + subject + payload) into a signed SET per matching stream, and
 * enqueues each. A stream matches when it is {@link StreamStatus#ENABLED}, its {@code events_delivered} contains
 * the event type, and it has the subject registered. Poll streams then drain via the poll endpoint; push streams
 * via {@link PushDeliveryService}. This is the bridge PF's event hooks call (see the notification-publisher
 * adapter) — kept transport-free so it unit-tests without PF.
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

    public SsfEventEmitter(SsfStore store, SetMinter minter, SsfConfiguration config) {
        this.store = store;
        this.minter = minter;
        this.config = config;
    }

    /**
     * Emit {@code eventType} about {@code subject} to every matching stream. Returns one {@link Emitted} per
     * stream a SET was enqueued for (empty if no stream subscribes this subject to this event).
     */
    public List<Emitted> emit(String eventType, SubjectId subject, Map<String, Object> payload) throws JoseException {
        List<Emitted> out = new ArrayList<>();
        long now = SetMinter.nowSeconds();
        long expiresAt = this.config.setTtlSeconds() > 0 ? now + this.config.setTtlSeconds() : 0;
        for (Stream s : this.store.listStreams()) {
            if (s.status() != StreamStatus.ENABLED || !s.deliversEvent(eventType)
                    || !this.store.hasSubject(s.id(), subject)) {
                continue;
            }
            String jti = SetMinter.newJti();
            SecurityEventToken set = SecurityEventToken.builder()
                    .issuer(this.config.issuer())
                    .audience(s.audience())
                    .jti(jti)
                    .issuedAt(now)
                    .subjectId(subject)
                    .event(eventType, payload)
                    .build();
            String jws = this.minter.sign(set);
            this.store.enqueue(PendingSet.fresh(jti, s.id(), subject.canonicalKey(), eventType, jws, now, expiresAt));
            out.add(new Emitted(s.id(), jti, s.deliveryMethod()));
        }
        return out;
    }

    // ─────────────────────────── convenience emitters ───────────────────────────

    public List<Emitted> sessionRevoked(SubjectId subject, String reasonAdmin) throws JoseException {
        return emit(SsfEventTypes.CAEP_SESSION_REVOKED, subject,
                CaepRiscEvents.sessionRevoked(SetMinter.nowSeconds(), reasonAdmin));
    }

    public List<Emitted> credentialChange(SubjectId subject, String credentialType, String changeType) throws JoseException {
        return emit(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, subject,
                CaepRiscEvents.credentialChange(SetMinter.nowSeconds(), credentialType, changeType));
    }

    public List<Emitted> accountDisabled(SubjectId subject, String reason) throws JoseException {
        return emit(SsfEventTypes.RISC_ACCOUNT_DISABLED, subject,
                CaepRiscEvents.accountDisabled(SetMinter.nowSeconds(), reason));
    }

    public List<Emitted> accountEnabled(SubjectId subject) throws JoseException {
        return emit(SsfEventTypes.RISC_ACCOUNT_ENABLED, subject,
                CaepRiscEvents.accountEnabled(SetMinter.nowSeconds()));
    }
}
