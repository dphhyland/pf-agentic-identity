/*
 * Persistence contract for SSF stream configs, subjects, and undelivered SETs.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * The persistence boundary for the transmitter: stream configurations, per-stream subjects, and the queue of
 * undelivered/unacked Security Event Tokens. Two implementations sit behind this interface — a per-node
 * {@link InMemorySsfStore} dev fallback and a PingFederate JDBC-backed store (cluster-safe, survives restart) —
 * selected by {@code dataStoreId}. All methods must be safe for concurrent callers (servlets + the push
 * executor).
 */
public interface SsfStore {

    // ---- streams ----

    Stream createStream(Stream stream);

    Optional<Stream> getStream(String streamId);

    List<Stream> listStreams();

    /** Replace an existing stream; returns the stored value. Throws if the stream does not exist. */
    Stream updateStream(Stream stream);

    boolean deleteStream(String streamId);

    // ---- subjects ----

    /** Add a subject to a stream. Returns true if newly added, false if already present. */
    boolean addSubject(String streamId, SubjectId subject);

    /** Remove a subject from a stream. Returns true if it was present. */
    boolean removeSubject(String streamId, SubjectId subject);

    boolean hasSubject(String streamId, SubjectId subject);

    List<SubjectId> listSubjects(String streamId);

    // ---- pending SETs ----

    void enqueue(PendingSet set);

    /** Oldest-first pending SETs for a stream, up to {@code max} (poll delivery / inspection). */
    List<PendingSet> peek(String streamId, int max);

    /** Delete acked/delivered SETs by {@code jti} for a stream (poll ack / push success). */
    int ack(String streamId, Collection<String> jtis);

    /**
     * Push candidates across all streams whose {@code nextAttemptAt} is at or before {@code now}, oldest first,
     * up to {@code max}. The push executor drives delivery from this.
     */
    List<PendingSet> dueForPush(long now, int max);

    /** Record a failed push attempt and reschedule (replaces the entry). */
    void recordAttempt(PendingSet set, long nextAttemptAt);

    /** Evict pending SETs whose {@code expiresAt} is at or before {@code now}. Returns the count removed. */
    int evictExpired(long now);
}
