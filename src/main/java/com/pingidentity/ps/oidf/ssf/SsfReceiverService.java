/*
 * Receiver core: verify an inbound SET, dedupe by jti, dispatch to handlers (transport-free).
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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
 */
public final class SsfReceiverService {

    private static final Log LOGGER = LogFactory.getLog(SsfReceiverService.class);
    private static final int DEDUP_MAX = 10_000;
    private static final int RECENT_MAX = 100;

    /** Acts on a verified, deduplicated inbound SET (e.g. revoke sessions, disable accounts). */
    public interface ReceivedSetHandler {
        void onSet(ReceivedSet set);
    }

    /** Outcome of {@link #receive}: accepted (dispatched), duplicate (acked, not re-dispatched). */
    public enum Outcome { ACCEPTED, DUPLICATE }

    private final SetVerifier verifier;
    private final List<ReceivedSetHandler> handlers = new CopyOnWriteArrayList<>();
    private final LinkedHashSet<String> seenJtis = new LinkedHashSet<>();
    private final Deque<ReceivedSet> recent = new ArrayDeque<>();

    public SsfReceiverService(SetVerifier verifier) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
    }

    public void addHandler(ReceivedSetHandler handler) {
        if (handler != null) {
            this.handlers.add(handler);
        }
    }

    /**
     * Verify, dedupe, record, dispatch. Throws {@link SetVerifier.SetVerificationException} on a SET that
     * must be rejected (the servlet maps its error code to the RFC 8935 response).
     */
    public Outcome receive(String compactJws) throws SetVerifier.SetVerificationException {
        ReceivedSet set = this.verifier.verify(compactJws);
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
