/*
 * SsfStore over the ID Partners Identity Object Model (Postgres JSONB entry store) — dialect "ldm".
 */
package com.pingidentity.ps.oidf.ssf;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;
import org.jose4j.json.JsonUtil;

/**
 * Persists the transmitter's state as object-class entries in the Identity Object Model's single
 * {@code idm.entry} table (LDAP-derived classes on Postgres JSONB), instead of the module's own three
 * relational tables. Selected by {@code storeDialect=ldm}. Class mapping (registered by the
 * {@code 0001-add-shared-signals-ssf} migration in the model repo):
 *
 * <ul>
 *   <li>{@code ssfStream} — one entry per stream; the stream id IS the {@code entry_uuid} (streams are
 *       minted as UUIDs), so stream lookup is by primary key.</li>
 *   <li>{@code ssfStreamSubject} — membership by containment: {@code parent_id} = the stream entry,
 *       {@code subject_id} = the RFC 9493 canonical key — the same subject key the model's grants and
 *       authorisation records use, so stream membership joins to the identity's wider state.</li>
 *   <li>{@code ssfPendingSet} — one queued SET under its stream; the hot {@code expires_at} column drives
 *       TTL eviction; retry state lives in {@code attrs}. Stream deletion cascades to both.</li>
 * </ul>
 *
 * <p>Postgres-specific SQL (JSONB operators, {@code ANY(object_classes)}). The schema is owned by the
 * model repo's migration workflow — this store never creates tables. Connections come from the supplied
 * {@link DataSource} (in PF, the managed pool for the configured JDBC data store).
 */
public final class LdmSsfStore implements SsfStore {

    private static final String STREAM_CLASS = "ssfStream";
    private static final String SUBJECT_CLASS = "ssfStreamSubject";
    private static final String PENDING_CLASS = "ssfPendingSet";

    private final DataSource dataSource;

    public LdmSsfStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    // ─────────────────────────────── streams ───────────────────────────────

    @Override
    public Stream createStream(Stream s) {
        exec("INSERT INTO idm.entry (entry_uuid, object_classes, attrs, created_at, modified_at) "
                + "VALUES (?::uuid, ?::text[], ?::jsonb, to_timestamp(?), to_timestamp(?))", ps -> {
                    ps.setString(1, s.id());
                    ps.setString(2, "{" + STREAM_CLASS + "}");
                    ps.setString(3, JsonUtil.toJson(streamAttrs(s)));
                    ps.setLong(4, s.createdAt());
                    ps.setLong(5, s.updatedAt());
                });
        return s;
    }

    @Override
    public Optional<Stream> getStream(String streamId) {
        return query("SELECT entry_uuid::text AS id, attrs::text AS attrs, "
                        + "extract(epoch FROM created_at)::bigint AS created_epoch, "
                        + "extract(epoch FROM modified_at)::bigint AS modified_epoch "
                        + "FROM idm.entry WHERE entry_uuid = ?::uuid AND ? = ANY (object_classes)",
                ps -> {
                    ps.setString(1, streamId);
                    ps.setString(2, STREAM_CLASS);
                },
                rs -> rs.next() ? Optional.of(mapStream(rs)) : Optional.<Stream>empty());
    }

    @Override
    public List<Stream> listStreams() {
        return query("SELECT entry_uuid::text AS id, attrs::text AS attrs, "
                        + "extract(epoch FROM created_at)::bigint AS created_epoch, "
                        + "extract(epoch FROM modified_at)::bigint AS modified_epoch "
                        + "FROM idm.entry WHERE ? = ANY (object_classes)",
                ps -> ps.setString(1, STREAM_CLASS),
                rs -> {
                    List<Stream> out = new ArrayList<>();
                    while (rs.next()) {
                        out.add(mapStream(rs));
                    }
                    return out;
                });
    }

    @Override
    public Stream updateStream(Stream s) {
        int n = exec("UPDATE idm.entry SET attrs = ?::jsonb, modified_at = to_timestamp(?) "
                + "WHERE entry_uuid = ?::uuid AND ? = ANY (object_classes)", ps -> {
                    ps.setString(1, JsonUtil.toJson(streamAttrs(s)));
                    ps.setLong(2, s.updatedAt());
                    ps.setString(3, s.id());
                    ps.setString(4, STREAM_CLASS);
                });
        if (n == 0) {
            throw new IllegalArgumentException("no such stream: " + s.id());
        }
        return s;
    }

    @Override
    public boolean deleteStream(String streamId) {
        // parent_id ON DELETE CASCADE removes the stream's subject + pending-set entries with it
        return exec("DELETE FROM idm.entry WHERE entry_uuid = ?::uuid AND ? = ANY (object_classes)", ps -> {
            ps.setString(1, streamId);
            ps.setString(2, STREAM_CLASS);
        }) > 0;
    }

    // ─────────────────────────────── subjects ───────────────────────────────

    @Override
    public boolean addSubject(String streamId, SubjectId subject) {
        if (getStream(streamId).isEmpty()) {
            throw new IllegalArgumentException("no such stream: " + streamId);
        }
        if (hasSubject(streamId, subject)) {
            return false;
        }
        LinkedHashMap<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("subjectFormat", subject.format());
        attrs.put("subjectJson", subject.toMap());
        exec("INSERT INTO idm.entry (object_classes, parent_id, subject_id, attrs) "
                + "VALUES (?::text[], ?::uuid, ?, ?::jsonb)", ps -> {
                    ps.setString(1, "{" + SUBJECT_CLASS + "}");
                    ps.setString(2, streamId);
                    ps.setString(3, subject.canonicalKey());
                    ps.setString(4, JsonUtil.toJson(attrs));
                });
        return true;
    }

    @Override
    public boolean removeSubject(String streamId, SubjectId subject) {
        return exec("DELETE FROM idm.entry WHERE parent_id = ?::uuid AND subject_id = ? AND ? = ANY (object_classes)",
                ps -> {
                    ps.setString(1, streamId);
                    ps.setString(2, subject.canonicalKey());
                    ps.setString(3, SUBJECT_CLASS);
                }) > 0;
    }

    @Override
    public boolean hasSubject(String streamId, SubjectId subject) {
        return query("SELECT 1 FROM idm.entry WHERE parent_id = ?::uuid AND subject_id = ? AND ? = ANY (object_classes)",
                ps -> {
                    ps.setString(1, streamId);
                    ps.setString(2, subject.canonicalKey());
                    ps.setString(3, SUBJECT_CLASS);
                }, ResultSet::next);
    }

    @Override
    public List<SubjectId> listSubjects(String streamId) {
        return query("SELECT attrs::text AS attrs FROM idm.entry "
                        + "WHERE parent_id = ?::uuid AND ? = ANY (object_classes)",
                ps -> {
                    ps.setString(1, streamId);
                    ps.setString(2, SUBJECT_CLASS);
                },
                rs -> {
                    List<SubjectId> out = new ArrayList<>();
                    while (rs.next()) {
                        out.add(parseSubject(rs.getString("attrs")));
                    }
                    return out;
                });
    }

    // ─────────────────────────────── pending SETs ───────────────────────────────

    @Override
    public void enqueue(PendingSet p) {
        LinkedHashMap<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("jti", p.jti());
        attrs.put("eventType", p.eventType());
        attrs.put("subjectKey", p.subjectKey());
        attrs.put("setJws", p.setJws());
        attrs.put("issuedAt", p.issuedAt());
        attrs.put("deliveryAttempts", p.deliveryAttempts());
        attrs.put("nextAttemptAt", p.nextAttemptAt());
        exec("INSERT INTO idm.entry (object_classes, parent_id, subject_id, expires_at, attrs) "
                + "VALUES (?::text[], ?::uuid, ?, CASE WHEN ? > 0 THEN to_timestamp(?) END, ?::jsonb)", ps -> {
                    ps.setString(1, "{" + PENDING_CLASS + "}");
                    ps.setString(2, p.streamId());
                    ps.setString(3, p.subjectKey());
                    ps.setLong(4, p.expiresAt());
                    ps.setLong(5, p.expiresAt());
                    ps.setString(6, JsonUtil.toJson(attrs));
                });
    }

    @Override
    public List<PendingSet> peek(String streamId, int max) {
        return query(pendingSelect() + " WHERE parent_id = ?::uuid AND ? = ANY (object_classes) "
                        + "ORDER BY (attrs->>'issuedAt')::bigint LIMIT ?",
                ps -> {
                    ps.setString(1, streamId);
                    ps.setString(2, PENDING_CLASS);
                    ps.setInt(3, Math.max(0, max));
                }, this::mapPending);
    }

    @Override
    public int ack(String streamId, Collection<String> jtis) {
        if (jtis == null || jtis.isEmpty()) {
            return 0;
        }
        int removed = 0;
        for (String jti : jtis) {
            removed += exec("DELETE FROM idm.entry WHERE parent_id = ?::uuid AND attrs->>'jti' = ? "
                    + "AND ? = ANY (object_classes)", ps -> {
                        ps.setString(1, streamId);
                        ps.setString(2, jti);
                        ps.setString(3, PENDING_CLASS);
                    });
        }
        return removed;
    }

    @Override
    public List<PendingSet> dueForPush(long now, int max) {
        return query(pendingSelect() + " WHERE ? = ANY (object_classes) AND (attrs->>'nextAttemptAt')::bigint <= ? "
                        + "ORDER BY (attrs->>'issuedAt')::bigint LIMIT ?",
                ps -> {
                    ps.setString(1, PENDING_CLASS);
                    ps.setLong(2, now);
                    ps.setInt(3, Math.max(0, max));
                }, this::mapPending);
    }

    @Override
    public void recordAttempt(PendingSet p, long nextAttemptAt) {
        exec("UPDATE idm.entry SET attrs = attrs || jsonb_build_object("
                + "'deliveryAttempts', (attrs->>'deliveryAttempts')::int + 1, 'nextAttemptAt', ?::bigint), "
                + "modified_at = now() WHERE attrs->>'jti' = ? AND ? = ANY (object_classes)", ps -> {
                    ps.setLong(1, nextAttemptAt);
                    ps.setString(2, p.jti());
                    ps.setString(3, PENDING_CLASS);
                });
    }

    @Override
    public int evictExpired(long now) {
        return exec("DELETE FROM idm.entry WHERE ? = ANY (object_classes) "
                + "AND expires_at IS NOT NULL AND expires_at <= to_timestamp(?)", ps -> {
                    ps.setString(1, PENDING_CLASS);
                    ps.setLong(2, now);
                });
    }

    // ─────────────────────────────── attrs mapping ───────────────────────────────

    private static Map<String, Object> streamAttrs(Stream s) {
        LinkedHashMap<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("audience", s.audience());
        attrs.put("deliveryMethod", s.deliveryMethod().urn());
        attrs.put("streamStatus", s.status().value());
        if (s.pushEndpointUrl() != null) {
            attrs.put("pushEndpointUrl", s.pushEndpointUrl());
        }
        if (s.pushAuthorizationHeader() != null) {
            attrs.put("pushAuthorizationHeader", s.pushAuthorizationHeader());
        }
        attrs.put("eventsRequested", s.eventsRequested());
        attrs.put("eventsDelivered", s.eventsDelivered());
        if (s.statusReason() != null) {
            attrs.put("statusReason", s.statusReason());
        }
        return attrs;
    }

    private Stream mapStream(ResultSet rs) throws SQLException {
        Map<String, Object> attrs = parseJson(rs.getString("attrs"));
        return Stream.builder()
                .id(rs.getString("id"))
                .audience((String) attrs.get("audience"))
                .deliveryMethod(DeliveryMethod.fromUrn((String) attrs.get("deliveryMethod")))
                .pushEndpointUrl((String) attrs.get("pushEndpointUrl"))
                .pushAuthorizationHeader((String) attrs.get("pushAuthorizationHeader"))
                .eventsRequested(stringList(attrs.get("eventsRequested")))
                .eventsDelivered(stringList(attrs.get("eventsDelivered")))
                .status(StreamStatus.fromValue((String) attrs.get("streamStatus")))
                .statusReason((String) attrs.get("statusReason"))
                .createdAt(rs.getLong("created_epoch"))
                .updatedAt(rs.getLong("modified_epoch"))
                .build();
    }

    private static String pendingSelect() {
        return "SELECT parent_id::text AS stream_id, attrs::text AS attrs, "
                + "COALESCE(extract(epoch FROM expires_at)::bigint, 0) AS expires_epoch FROM idm.entry";
    }

    private List<PendingSet> mapPending(ResultSet rs) throws SQLException {
        List<PendingSet> out = new ArrayList<>();
        while (rs.next()) {
            Map<String, Object> attrs = parseJson(rs.getString("attrs"));
            out.add(new PendingSet(
                    (String) attrs.get("jti"),
                    rs.getString("stream_id"),
                    (String) attrs.get("subjectKey"),
                    (String) attrs.get("eventType"),
                    (String) attrs.get("setJws"),
                    asLong(attrs.get("issuedAt")),
                    rs.getLong("expires_epoch"),
                    (int) asLong(attrs.get("deliveryAttempts")),
                    asLong(attrs.get("nextAttemptAt"))));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static SubjectId parseSubject(String attrsJson) {
        Object subjectJson = parseJson(attrsJson).get("subjectJson");
        if (!(subjectJson instanceof Map)) {
            throw new IllegalStateException("ssfStreamSubject entry has no subjectJson object");
        }
        return SubjectId.fromMap((Map<String, Object>) subjectJson);
    }

    private static Map<String, Object> parseJson(String json) {
        try {
            return JsonUtil.parseJson(json);
        } catch (Exception e) {
            throw new IllegalStateException("corrupt entry attrs: " + json, e);
        }
    }

    private static List<String> stringList(Object raw) {
        List<String> out = new ArrayList<>();
        if (raw instanceof Iterable) {
            for (Object o : (Iterable<?>) raw) {
                if (o != null) {
                    out.add(o.toString());
                }
            }
        }
        return out;
    }

    private static long asLong(Object o) {
        return o instanceof Number ? ((Number) o).longValue() : 0L;
    }

    // ─────────────────────────────── JDBC plumbing (as JdbcSsfStore) ───────────────────────────────

    private interface Binder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    private interface RowReader<T> {
        T read(ResultSet rs) throws SQLException;
    }

    private int exec(String sql, Binder binder) {
        try (Connection c = this.dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("SSF LDM store error: " + sql, e);
        }
    }

    private <T> T query(String sql, Binder binder, RowReader<T> reader) {
        try (Connection c = this.dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                return reader.read(rs);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("SSF LDM store query error: " + sql, e);
        }
    }
}
