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
 *
 * <p>A store answers for every stream, whoever owns it: the event emitter and the push executor work
 * across receivers and have no caller to scope to. Which receiver may see which stream is decided above
 * this interface, by {@link StreamAccess} - anything that acts for a receiver asks it about a stream read
 * from here before doing anything with it.
 */
public interface SsfStore {

    // ---- streams ----

    /**
     * Store a new stream, refusing an id that is already taken. This is the only write of
     * {@link Stream#ownerClientId()}.
     */
    Stream createStream(Stream stream);

    Optional<Stream> getStream(String streamId);

    List<Stream> listStreams();

    /**
     * Replace an existing stream. Throws if the stream does not exist. What is returned is the stream as
     * it was written, which for the two durable stores is the argument - so its owner is the caller's word
     * and not the store's. Read the stream back if the owner matters.
     *
     * <p>The owner is not part of what is replaced. Whatever {@code stream} carries, the stored owner
     * stands, so no update - a PATCH, a status change, the push executor pausing a failing stream - can
     * move a stream to another receiver or strip its owner and orphan it.
     */
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

    /**
     * Evict pending SETs whose {@code expiresAt} is at or before {@code now}, on every stream. Returns the
     * count removed. An {@code expiresAt} of 0 is no expiry and is never evicted.
     *
     * <p>{@link #peek} and {@link #dueForPush} do not look at {@code expiresAt}: their callers evict first,
     * with the same {@code now}, and that is what keeps an expired SET from being delivered.
     */
    int evictExpired(long now);
}
