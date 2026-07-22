/*
 * Per-node in-memory SsfStore. Dev fallback; NOT cluster-safe and NOT durable across restarts.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link SsfStore} used when no {@code dataStoreId} is configured. State is per-JVM, so — exactly
 * like the attestation challenge/replay caches — it is <strong>not shared across a PingFederate cluster and
 * does not survive a restart</strong>. Use the JDBC-backed store for production/multi-node. Suitable for dev,
 * tests, and single-node demos.
 */
public final class InMemorySsfStore implements SsfStore {

    private final Map<String, Stream> streams = new ConcurrentHashMap<>();
    private final Map<String, Set<SubjectId>> subjects = new ConcurrentHashMap<>();
    // streamId -> (jti -> PendingSet)
    private final Map<String, Map<String, PendingSet>> pending = new ConcurrentHashMap<>();

    @Override
    public Stream createStream(Stream stream) {
        this.streams.put(stream.id(), stream);
        this.subjects.putIfAbsent(stream.id(), ConcurrentHashMap.newKeySet());
        this.pending.putIfAbsent(stream.id(), new ConcurrentHashMap<>());
        return stream;
    }

    @Override
    public Optional<Stream> getStream(String streamId) {
        return Optional.ofNullable(this.streams.get(streamId));
    }

    @Override
    public List<Stream> listStreams() {
        return new ArrayList<>(this.streams.values());
    }

    @Override
    public Stream updateStream(Stream stream) {
        if (!this.streams.containsKey(stream.id())) {
            throw new IllegalArgumentException("no such stream: " + stream.id());
        }
        this.streams.put(stream.id(), stream);
        return stream;
    }

    @Override
    public boolean deleteStream(String streamId) {
        this.subjects.remove(streamId);
        this.pending.remove(streamId);
        return this.streams.remove(streamId) != null;
    }

    @Override
    public boolean addSubject(String streamId, SubjectId subject) {
        requireStream(streamId);
        return this.subjects.computeIfAbsent(streamId, k -> ConcurrentHashMap.newKeySet()).add(subject);
    }

    @Override
    public boolean removeSubject(String streamId, SubjectId subject) {
        Set<SubjectId> set = this.subjects.get(streamId);
        return set != null && set.remove(subject);
    }

    @Override
    public boolean hasSubject(String streamId, SubjectId subject) {
        Set<SubjectId> set = this.subjects.get(streamId);
        return set != null && set.contains(subject);
    }

    @Override
    public List<SubjectId> listSubjects(String streamId) {
        Set<SubjectId> set = this.subjects.get(streamId);
        return set == null ? List.of() : new ArrayList<>(new LinkedHashSet<>(set));
    }

    @Override
    public void enqueue(PendingSet set) {
        this.pending.computeIfAbsent(set.streamId(), k -> new ConcurrentHashMap<>()).put(set.jti(), set);
    }

    @Override
    public List<PendingSet> peek(String streamId, int max) {
        Map<String, PendingSet> q = this.pending.get(streamId);
        if (q == null || q.isEmpty()) {
            return List.of();
        }
        return q.values().stream()
                .sorted(Comparator.comparingLong(PendingSet::issuedAt))
                .limit(Math.max(0, max))
                .toList();
    }

    @Override
    public int ack(String streamId, Collection<String> jtis) {
        Map<String, PendingSet> q = this.pending.get(streamId);
        if (q == null || jtis == null) {
            return 0;
        }
        int removed = 0;
        for (String jti : jtis) {
            if (q.remove(jti) != null) {
                removed++;
            }
        }
        return removed;
    }

    @Override
    public List<PendingSet> dueForPush(long now, int max) {
        return this.pending.values().stream()
                .flatMap(q -> q.values().stream())
                .filter(p -> p.nextAttemptAt() <= now)
                .sorted(Comparator.comparingLong(PendingSet::issuedAt))
                .limit(Math.max(0, max))
                .toList();
    }

    @Override
    public void recordAttempt(PendingSet set, long nextAttemptAt) {
        Map<String, PendingSet> q = this.pending.get(set.streamId());
        if (q != null && q.containsKey(set.jti())) {
            q.put(set.jti(), set.withAttempt(nextAttemptAt));
        }
    }

    @Override
    public int evictExpired(long now) {
        int removed = 0;
        for (Map<String, PendingSet> q : this.pending.values()) {
            var it = q.values().iterator();
            while (it.hasNext()) {
                PendingSet p = it.next();
                if (p.expiresAt() > 0 && p.expiresAt() <= now) {
                    it.remove();
                    removed++;
                }
            }
        }
        return removed;
    }

    private void requireStream(String streamId) {
        if (!this.streams.containsKey(streamId)) {
            throw new IllegalArgumentException("no such stream: " + streamId);
        }
    }
}
