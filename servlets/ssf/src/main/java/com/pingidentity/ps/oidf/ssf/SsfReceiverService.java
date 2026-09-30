/*
 * Receiver core: verify an inbound SET, dedupe by jti, dispatch to handlers (transport-free).
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.signals.ReceivedSet;
import com.pingidentity.ps.oidf.signals.SetVerifier;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;

/**
 * The receiver pipeline behind the push endpoint (and, later, the poll client): verify via
 * {@link SetVerifier}, drop duplicate {@code jti}s (a transmitter may redeliver — RFC 8935 requires
 * idempotent acceptance), record the SET in a bounded recent-events buffer (demo/inspection), and dispatch
 * to every registered {@link ReceivedSetHandler}. Handler failures are logged, never propagated — a broken
 * action must not cause redelivery loops.
 *
 * <p>The jti dedup window and recent buffer are per-node in-memory (bounded); like the attestation caches,
 * they are not cluster-safe — acceptable because redelivery of an already-processed SET is idempotent at
 * the action layer.
 *
 * <p>Two refusals go beyond {@link SetVerifier} (finding F-0246), made here rather than in shared-signals so that
 * other users of the verifier are not changed: a SET carrying {@code exp} or {@code sub} is refused as
 * {@code invalid_request} with a description naming the claim. SSF 1.0 (29 August 2025) §4.1.7: "The "exp" claim
 * MUST NOT be used in SETs"; §4.1.2: "The JWT "sub" claim MUST NOT be present in any SET containing an SSF event";
 * §4.1.3 lists both among the restrictions that keep SETs from being "confused for other kinds of JWTs". Both are
 * written to the transmitter; a SET that breaks them is one a conforming transmitter would not have sent, and this
 * receiver refuses it rather than guess at what else it might be.
 *
 * <p>And an event whose complex subject carries a member the transmitter declared critical
 * ({@code critical_subject_members}, learnt when the receiver sets up its stream) that the handlers do not act on is
 * discarded - accepted, not acted on: SSF 1.0 §3.6, "An SSF Receiver MUST discard any event that contains a Subject
 * with a Critical member that it is unable to process". The handlers act on {@code user} and {@code device}
 * ({@link SsfSubjects#ACTED_ON_MEMBERS}).
 *
 * <p>Every refusal and discard is logged and counted as an {@code ssf-receiver} event.
 */
public final class SsfReceiverService {

    private static final Log LOGGER = LogFactory.getLog(SsfReceiverService.class);
    private static final int DEDUP_MAX = 10_000;
    private static final int RECENT_MAX = 100;

    /** Acts on a verified, deduplicated inbound SET (e.g. revoke sessions, disable accounts). */
    public interface ReceivedSetHandler {
        void onSet(ReceivedSet set);
    }

    /**
     * Outcome of {@link #receive}: accepted (dispatched), duplicate (acked, not re-dispatched), discarded (acked, not
     * dispatched: a critical subject member the handlers do not act on).
     */
    public enum Outcome { ACCEPTED, DUPLICATE, DISCARDED }

    static final String EVENTS = "ssf-receiver";
    static final String SET_REFUSED = "ssf.receiver.set_refused";
    static final String SET_DISCARDED = "ssf.receiver.set_discarded";

    private final SetVerifier verifier;
    private final List<ReceivedSetHandler> handlers = new CopyOnWriteArrayList<>();
    private final LinkedHashSet<String> seenJtis = new LinkedHashSet<>();
    private final Deque<ReceivedSet> recent = new ArrayDeque<>();
    private volatile Set<String> criticalSubjectMembers = Set.of();

    public SsfReceiverService(SetVerifier verifier) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
    }

    public void addHandler(ReceivedSetHandler handler) {
        if (handler != null) {
            this.handlers.add(handler);
        }
    }

    /**
     * The complex-subject members the transmitter declared critical (SSF 1.0 §7.1 {@code critical_subject_members}),
     * as its configuration metadata said when the receiver set up its stream; empty until then.
     */
    public void criticalSubjectMembers(Set<String> members) {
        this.criticalSubjectMembers = Set.copyOf(members);
    }

    public Set<String> criticalSubjectMembers() {
        return this.criticalSubjectMembers;
    }

    /**
     * Verify, dedupe, record, dispatch. Throws {@link SetVerifier.SetVerificationException} on a SET that
     * must be rejected (the servlet maps its error code to the RFC 8935 response).
     */
    public Outcome receive(String compactJws) throws SetVerifier.SetVerificationException {
        ReceivedSet set;
        try {
            refuseForbiddenClaims(compactJws);
            set = this.verifier.verify(compactJws);
        } catch (SetVerifier.SetVerificationException e) {
            Events.event(EVENTS, SET_REFUSED).failure(e.errorCode()).emit();
            throw e;
        }
        Set<String> unprocessed = unprocessedCriticalMembers(set.subjectId(), this.criticalSubjectMembers);
        if (!unprocessed.isEmpty()) {
            LOGGER.warn((Object) ("SSF receiver: SET " + set.jti() + " discarded: its subject carries the critical member(s) "
                    + unprocessed + ", which this receiver does not act on (SSF 1.0 §3.6)"));
            Events.event(EVENTS, SET_DISCARDED).failure("critical_subject_member").emit();
            return Outcome.DISCARDED;
        }
        synchronized (this) {
            if (this.seenJtis.contains(set.jti())) {
                return Outcome.DUPLICATE;
            }
            this.seenJtis.add(set.jti());
            while (this.seenJtis.size() > DEDUP_MAX) {
                this.seenJtis.remove(this.seenJtis.iterator().next());
            }
            this.recent.addFirst(set);
            while (this.recent.size() > RECENT_MAX) {
                this.recent.removeLast();
            }
        }
        for (ReceivedSetHandler handler : this.handlers) {
            try {
                handler.onSet(set);
            } catch (RuntimeException e) {
                LOGGER.warn((Object) ("SSF receiver handler failed for jti " + set.jti() + ": " + e.getMessage()));
            }
        }
        return Outcome.ACCEPTED;
    }

    /**
     * Refuses a SET whose payload carries {@code exp} or {@code sub} (SSF 1.0 §4.1.7, §4.1.2). Read before the
     * signature is checked, so the refusal names the claim whatever else is wrong; a payload that cannot be read is
     * left to the verifier, which refuses it for what it is.
     */
    static void refuseForbiddenClaims(String compactJws) throws SetVerifier.SetVerificationException {
        Map<String, Object> claims;
        try {
            String[] parts = compactJws.split("\\.", -1);
            claims = JsonUtil.parseJson(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
        } catch (Exception e) {
            return;
        }
        if (claims.containsKey("exp")) {
            throw new SetVerifier.SetVerificationException("invalid_request",
                    "the SET carries the \"exp\" claim, which SSF 1.0 §4.1.7 forbids in SETs");
        }
        if (claims.containsKey("sub")) {
            throw new SetVerifier.SetVerificationException("invalid_request",
                    "the SET carries the JWT \"sub\" claim, which SSF 1.0 §4.1.2 forbids in SETs (the subject is sub_id)");
        }
    }

    /** The critical members of a complex subject that the handlers do not act on; empty for any other subject. */
    static Set<String> unprocessedCriticalMembers(SubjectId subject, Set<String> critical) {
        Set<String> out = new TreeSet<>();
        if (subject == null || !subject.isComplex()) {
            return out;
        }
        for (String member : critical) {
            if (subject.member(member) != null && !SsfSubjects.ACTED_ON_MEMBERS.contains(member)) {
                out.add(member);
            }
        }
        return out;
    }

    /** The most recent received SETs (newest first) as JSON-shaped summaries, for the inspection endpoint. */
    public List<Map<String, Object>> recentEvents() {
        List<ReceivedSet> snapshot;
        synchronized (this) {
            snapshot = new ArrayList<>(this.recent);
        }
        List<Map<String, Object>> out = new ArrayList<>(snapshot.size());
        for (ReceivedSet s : snapshot) {
            LinkedHashMap<String, Object> m = new LinkedHashMap<>();
            m.put("jti", s.jti());
            m.put("iss", s.issuer());
            m.put("iat", s.issuedAt());
            if (s.subjectId() != null) {
                m.put("sub_id", s.subjectId().toMap());
            }
            m.put("event_types", new ArrayList<>(s.events().keySet()));
            out.add(m);
        }
        return Collections.unmodifiableList(out);
    }
}
