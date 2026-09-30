/*
 * Maps verified inbound SETs to PF-side actions (the receiver's reason to exist).
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.signals.ReceivedSet;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The {@link SsfReceiverService.ReceivedSetHandler} that acts on inbound signals: a CAEP
 * {@code session-revoked} or RISC {@code account-disabled} / {@code account-credential-change-required}
 * about a subject revokes that subject's OAuth grants in PingFederate (killing refresh ability and
 * reference-token validation immediately). The PF call is behind {@link ReceiverActions} so this mapping is
 * unit-testable; the runtime implementation is {@code PfReceiverActions} (PF SDK
 * {@code AccessGrantManagerAccessor}). Best-effort: action failures are logged, never thrown.
 *
 * <p>The subject is mapped to a user key by {@link SsfSubjects#userKey}, honouring an {@code iss_sub}'s issuer: the
 * SET's own issuer and {@code localIssuers} (this PingFederate's SSF issuer and {@code OIDF_SSF_RECEIVER_SUBJECT_ISSUERS})
 * are honoured, any other is refused. A subject that maps to no
 * one is logged with the reason and counted ({@value #SUBJECT_UNMAPPED}); nothing is revoked.
 */
public final class ReceiverActionHandler implements SsfReceiverService.ReceivedSetHandler {

    /** The PF-side action surface (implemented against the PF SDK in the servlet layer). */
    public interface ReceiverActions {
        /** Revoke every OAuth grant belonging to {@code userKey}; returns the number revoked. */
        int revokeGrantsFor(String userKey);
    }

    private static final Log LOGGER = LogFactory.getLog(ReceiverActionHandler.class);

    static final String EVENTS = "ssf-receiver";
    static final String SUBJECT_UNMAPPED = "ssf.receiver.subject_unmapped";

    private final ReceiverActions actions;
    private final Set<String> localIssuers;

    /** A handler that honours only the SET's own issuer in an {@code iss_sub} subject. */
    public ReceiverActionHandler(ReceiverActions actions) {
        this(actions, Set.of());
    }

    /**
     * @param localIssuers the issuers, besides the SET's own, whose {@code iss_sub} subjects name a user here
     *                     ({@link SsfConfiguration#receiverLocalIssuers()})
     */
    public ReceiverActionHandler(ReceiverActions actions, Set<String> localIssuers) {
        this.actions = Objects.requireNonNull(actions, "actions");
        this.localIssuers = Set.copyOf(localIssuers);
    }

    @Override
    public void onSet(ReceivedSet set) {
        if (!set.hasEvent(SsfEventTypes.CAEP_SESSION_REVOKED)
                && !set.hasEvent(SsfEventTypes.RISC_ACCOUNT_DISABLED)
                && !set.hasEvent(SsfEventTypes.RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED)) {
            return; // not a revocation-worthy signal (e.g. verification)
        }
        SsfSubjects.Mapping mapping = SsfSubjects.userKey(set.subjectId(), issuers(set, this.localIssuers));
        if (!mapping.mapped()) {
            LOGGER.warn((Object) ("SSF receiver: revocation signal " + set.jti() + " names no user here: "
                    + mapping.refusal()));
            Events.event(EVENTS, SUBJECT_UNMAPPED).failure("unmapped").field("handler", "grants")
                    .field("format", formatOf(set.subjectId())).emit();
            return;
        }
        String userKey = mapping.value();
        try {
            int revoked = this.actions.revokeGrantsFor(userKey);
            LOGGER.info((Object) ("SSF receiver: revoked " + revoked + " grant(s) for '" + userKey
                    + "' on signal " + set.events().keySet() + " (jti " + set.jti() + ")"));
        } catch (RuntimeException e) {
            LOGGER.warn((Object) ("SSF receiver: grant revocation failed for '" + userKey + "': " + e.getMessage()));
        }
    }

    /** The issuers whose {@code iss_sub} subjects name someone here: the SET's own and {@code localIssuers}. */
    static Set<String> issuers(ReceivedSet set, Set<String> localIssuers) {
        Set<String> out = new HashSet<>(localIssuers);
        out.add(set.issuer());
        return out;
    }

    /** The subject's format for an event field, or {@code none}. */
    static String formatOf(SubjectId subject) {
        return subject == null ? "none" : subject.format();
    }
}
