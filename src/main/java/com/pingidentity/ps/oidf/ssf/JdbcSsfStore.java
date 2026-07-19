/*
 * JDBC-backed SsfStore — cluster-safe, survives restarts. Uses a PF-provided DataSource (no own pool).
 */
package com.pingidentity.ps.oidf.ssf;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;
import org.jose4j.json.JsonUtil;

/**
 * The durable, cluster-safe {@link SsfStore}: stream configs, subjects, and undelivered SETs live in three
 * tables ({@code ssf_streams}, {@code ssf_stream_subjects}, {@code ssf_pending_sets}) so they survive a PF
 * restart and are shared across nodes. Obtains connections from a {@link DataSource} — in the runtime this is a
 * PingFederate-configured JDBC data store resolved by id (installed via {@link SsfSupport#installStoreFactory});
 * this class never opens its own pool. {@link #ensureSchema()} applies the DDL on boot if the tables are absent.
 *
 * <p>Event lists are stored newline-joined (event-type URIs contain no newlines); subjects are stored as their
 * RFC 9493 JSON plus a canonical key. SQL is kept to a portable subset ({@code CREATE TABLE IF NOT EXISTS},
 * {@code LIMIT}) that HSQLDB (PF's bundled DB) and common engines accept; see docs/ssf-transmitter.md for the DDL.
 */
public final class JdbcSsfStore implements SsfStore {

    static final String DDL_STREAMS =
            "CREATE TABLE IF NOT EXISTS ssf_streams ("
                    + "stream_id VARCHAR(64) PRIMARY KEY, audience VARCHAR(1024) NOT NULL, "
                    + "delivery_method VARCHAR(64) NOT NULL, push_endpoint_url VARCHAR(2048), push_auth_header VARCHAR(4096), "
                    + "events_requested VARCHAR(8192), events_delivered VARCHAR(8192), "
                    + "status VARCHAR(16) NOT NULL, status_reason VARCHAR(1024), created_at BIGINT, updated_at BIGINT)";
    static final String DDL_SUBJECTS =
            "CREATE TABLE IF NOT EXISTS ssf_stream_subjects ("
                    + "stream_id VARCHAR(64) NOT NULL, subject_key VARCHAR(1024) NOT NULL, subject_json VARCHAR(4096) NOT NULL, "
                    + "PRIMARY KEY (stream_id, subject_key))";
    static final String DDL_PENDING =
            "CREATE TABLE IF NOT EXISTS ssf_pending_sets ("
                    + "jti VARCHAR(64) NOT NULL, stream_id VARCHAR(64) NOT NULL, subject_key VARCHAR(1024), "
                    + "event_type VARCHAR(256), set_jws VARCHAR(16384) NOT NULL, issued_at BIGINT, expires_at BIGINT, "
                    + "delivery_attempts INTEGER DEFAULT 0, next_attempt_at BIGINT, PRIMARY KEY (jti))";

    private final DataSource dataSource;

    public JdbcSsfStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    /** Create the three tables if they don't exist. Call once on boot. */
    public void ensureSchema() {
        try (Connection c = this.dataSource.getConnection(); Statement st = c.createStatement()) {
            st.execute(DDL_STREAMS);
            st.execute(DDL_SUBJECTS);
            st.execute(DDL_PENDING);
        } catch (SQLException e) {
            throw new IllegalStateException("failed to apply SSF schema", e);
        }
    }

    // ─────────────────────────────── streams ───────────────────────────────

    @Override
    public Stream createStream(Stream s) {
        exec("INSERT INTO ssf_streams (stream_id, audience, delivery_method, push_endpoint_url, push_auth_header, "
                + "events_requested, events_delivered, status, status_reason, created_at, updated_at) "
                + "VALUES (?,?,?,?,?,?,?,?,?,?,?)", ps -> {
                    ps.setString(1, s.id());
                    ps.setString(2, s.audience());
                    ps.setString(3, s.deliveryMethod().name());
                    ps.setString(4, s.pushEndpointUrl());
                    ps.setString(5, s.pushAuthorizationHeader());
                    ps.setString(6, joinEvents(s.eventsRequested()));
                    ps.setString(7, joinEvents(s.eventsDelivered()));
                    ps.setString(8, s.status().value());
                    ps.setString(9, s.statusReason());
                    ps.setLong(10, s.createdAt());
                    ps.setLong(11, s.updatedAt());
                });
        return s;
    }

    @Override
    public Optional<Stream> getStream(String streamId) {
        return query("SELECT * FROM ssf_streams WHERE stream_id = ?", ps -> ps.setString(1, streamId),
                rs -> rs.next() ? Optional.of(mapStream(rs)) : Optional.<Stream>empty());
    }

    @Override
    public List<Stream> listStreams() {
        return query("SELECT * FROM ssf_streams", ps -> { }, rs -> {
            List<Stream> out = new ArrayList<>();
            while (rs.next()) {
                out.add(mapStream(rs));
            }
            return out;
        });
    }

    @Override
    public Stream updateStream(Stream s) {
        int n = exec("UPDATE ssf_streams SET audience=?, delivery_method=?, push_endpoint_url=?, push_auth_header=?, "
                + "events_requested=?, events_delivered=?, status=?, status_reason=?, updated_at=? WHERE stream_id=?", ps -> {
                    ps.setString(1, s.audience());
                    ps.setString(2, s.deliveryMethod().name());
                    ps.setString(3, s.pushEndpointUrl());
                    ps.setString(4, s.pushAuthorizationHeader());
                    ps.setString(5, joinEvents(s.eventsRequested()));
                    ps.setString(6, joinEvents(s.eventsDelivered()));
                    ps.setString(7, s.status().value());
                    ps.setString(8, s.statusReason());
                    ps.setLong(9, s.updatedAt());
                    ps.setString(10, s.id());
                });
        if (n == 0) {
            throw new IllegalArgumentException("no such stream: " + s.id());
        }
        return s;
    }

    @Override
    public boolean deleteStream(String streamId) {
        exec("DELETE FROM ssf_pending_sets WHERE stream_id=?", ps -> ps.setString(1, streamId));
        exec("DELETE FROM ssf_stream_subjects WHERE stream_id=?", ps -> ps.setString(1, streamId));
        return exec("DELETE FROM ssf_streams WHERE stream_id=?", ps -> ps.setString(1, streamId)) > 0;
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
        exec("INSERT INTO ssf_stream_subjects (stream_id, subject_key, subject_json) VALUES (?,?,?)", ps -> {
            ps.setString(1, streamId);
            ps.setString(2, subject.canonicalKey());
            ps.setString(3, JsonUtil.toJson(subject.toMap()));
        });
        return true;
    }

    @Override
    public boolean removeSubject(String streamId, SubjectId subject) {
        return exec("DELETE FROM ssf_stream_subjects WHERE stream_id=? AND subject_key=?", ps -> {
            ps.setString(1, streamId);
            ps.setString(2, subject.canonicalKey());
        }) > 0;
    }

    @Override
    public boolean hasSubject(String streamId, SubjectId subject) {
        return query("SELECT 1 FROM ssf_stream_subjects WHERE stream_id=? AND subject_key=?", ps -> {
            ps.setString(1, streamId);
            ps.setString(2, subject.canonicalKey());
        }, ResultSet::next);
    }

    @Override
    public List<SubjectId> listSubjects(String streamId) {
        return query("SELECT subject_json FROM ssf_stream_subjects WHERE stream_id=?", ps -> ps.setString(1, streamId), rs -> {
            List<SubjectId> out = new ArrayList<>();
            while (rs.next()) {
                out.add(parseSubject(rs.getString(1)));
            }
            return out;
        });
    }

    // ─────────────────────────────── pending SETs ───────────────────────────────

    @Override
    public void enqueue(PendingSet p) {
        exec("INSERT INTO ssf_pending_sets (jti, stream_id, subject_key, event_type, set_jws, issued_at, expires_at, "
                + "delivery_attempts, next_attempt_at) VALUES (?,?,?,?,?,?,?,?,?)", ps -> {
                    ps.setString(1, p.jti());
                    ps.setString(2, p.streamId());
                    ps.setString(3, p.subjectKey());
                    ps.setString(4, p.eventType());
                    ps.setString(5, p.setJws());
                    ps.setLong(6, p.issuedAt());
                    ps.setLong(7, p.expiresAt());
                    ps.setInt(8, p.deliveryAttempts());
                    ps.setLong(9, p.nextAttemptAt());
                });
    }

    @Override
    public List<PendingSet> peek(String streamId, int max) {
        return query("SELECT * FROM ssf_pending_sets WHERE stream_id=? ORDER BY issued_at LIMIT ?", ps -> {
            ps.setString(1, streamId);
            ps.setInt(2, Math.max(0, max));
        }, this::mapPending);
    }

    @Override
    public int ack(String streamId, Collection<String> jtis) {
        if (jtis == null || jtis.isEmpty()) {
            return 0;
        }
        int removed = 0;
        for (String jti : jtis) {
            removed += exec("DELETE FROM ssf_pending_sets WHERE stream_id=? AND jti=?", ps -> {
                ps.setString(1, streamId);
                ps.setString(2, jti);
            });
        }
        return removed;
    }

    @Override
    public List<PendingSet> dueForPush(long now, int max) {
        return query("SELECT * FROM ssf_pending_sets WHERE next_attempt_at <= ? ORDER BY issued_at LIMIT ?", ps -> {
            ps.setLong(1, now);
            ps.setInt(2, Math.max(0, max));
        }, this::mapPending);
    }

    @Override
    public void recordAttempt(PendingSet p, long nextAttemptAt) {
        exec("UPDATE ssf_pending_sets SET delivery_attempts=delivery_attempts+1, next_attempt_at=? WHERE jti=?", ps -> {
            ps.setLong(1, nextAttemptAt);
            ps.setString(2, p.jti());
        });
    }

    @Override
    public int evictExpired(long now) {
        return exec("DELETE FROM ssf_pending_sets WHERE expires_at > 0 AND expires_at <= ?", ps -> ps.setLong(1, now));
    }

    // ─────────────────────────────── mapping + JDBC plumbing ───────────────────────────────

    private Stream mapStream(ResultSet rs) throws SQLException {
        return Stream.builder()
                .id(rs.getString("stream_id"))
                .audience(rs.getString("audience"))
                .deliveryMethod(DeliveryMethod.valueOf(rs.getString("delivery_method")))
                .pushEndpointUrl(rs.getString("push_endpoint_url"))
                .pushAuthorizationHeader(rs.getString("push_auth_header"))
                .eventsRequested(splitEvents(rs.getString("events_requested")))
                .eventsDelivered(splitEvents(rs.getString("events_delivered")))
                .status(StreamStatus.fromValue(rs.getString("status")))
                .statusReason(rs.getString("status_reason"))
                .createdAt(rs.getLong("created_at"))
                .updatedAt(rs.getLong("updated_at"))
                .build();
    }

    private List<PendingSet> mapPending(ResultSet rs) throws SQLException {
        List<PendingSet> out = new ArrayList<>();
        while (rs.next()) {
            out.add(new PendingSet(rs.getString("jti"), rs.getString("stream_id"), rs.getString("subject_key"),
                    rs.getString("event_type"), rs.getString("set_jws"), rs.getLong("issued_at"),
                    rs.getLong("expires_at"), rs.getInt("delivery_attempts"), rs.getLong("next_attempt_at")));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static SubjectId parseSubject(String json) {
        try {
            return SubjectId.fromMap((Map<String, Object>) (Map<?, ?>) JsonUtil.parseJson(json));
        } catch (Exception e) {
            throw new IllegalStateException("corrupt subject row: " + json, e);
        }
    }

    private static String joinEvents(List<String> events) {
        return events == null ? "" : String.join("\n", events);
    }

    private static List<String> splitEvents(String joined) {
        if (joined == null || joined.isBlank()) {
            return List.of();
        }
        return Arrays.asList(joined.split("\n"));
    }

    // functional JDBC helpers — one connection per call from the PF-provided DataSource.

    private interface Binder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    private interface RowReader<T> {
        T read(ResultSet rs) throws SQLException;
    }

    /** Bind params then execute an INSERT/UPDATE/DELETE; returns the affected-row count. */
    private int exec(String sql, Binder binder) {
        try (Connection c = this.dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("SSF JDBC store error: " + sql, e);
        }
    }

    private <T> T query(String sql, Binder binder, RowReader<T> reader) {
        try (Connection c = this.dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                return reader.read(rs);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("SSF JDBC store query error: " + sql, e);
        }
    }
}
