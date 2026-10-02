/*
 * JDBC-backed SsfStore — cluster-safe, survives restarts. Uses a PF-provided DataSource (no own pool).
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.signals.SubjectId;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
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
 * this class never opens its own pool. {@link #ensureSchema()} applies the DDL on boot if the tables are absent,
 * and adds {@code owner_client_id} to an {@code ssf_streams} created before streams had owners.
 *
 * <p>Event lists are stored newline-joined (event-type URIs contain no newlines); subjects are stored as their
 * RFC 9493 JSON plus a canonical key. The SQL is PostgreSQL's, the one database since 0.5.0: a second's SETs are ordered
 * by {@code jti COLLATE "C"}, bytewise whatever the database's collation; the DDL is the DDL_* constants below.
 */
public final class JdbcSsfStore implements SsfStore {

    static final String DDL_STREAMS =
            "CREATE TABLE IF NOT EXISTS ssf_streams ("
                    + "stream_id VARCHAR(64) PRIMARY KEY, audience VARCHAR(1024) NOT NULL, owner_client_id VARCHAR(1024), "
                    + "delivery_method VARCHAR(64) NOT NULL, push_endpoint_url VARCHAR(2048), push_auth_header VARCHAR(4096), "
                    + "events_requested VARCHAR(8192), events_delivered VARCHAR(8192), "
                    + "status VARCHAR(16) NOT NULL, status_reason VARCHAR(1024), created_at BIGINT, updated_at BIGINT, "
                    + "description VARCHAR(1024), min_verification_interval INTEGER, inactivity_timeout BIGINT)";
    static final String DDL_SUBJECTS =
            "CREATE TABLE IF NOT EXISTS ssf_stream_subjects ("
                    + "stream_id VARCHAR(64) NOT NULL, subject_key VARCHAR(1024) NOT NULL, subject_json VARCHAR(4096) NOT NULL, "
                    + "PRIMARY KEY (stream_id, subject_key))";
    static final String DDL_PENDING =
            "CREATE TABLE IF NOT EXISTS ssf_pending_sets ("
                    + "jti VARCHAR(64) NOT NULL, stream_id VARCHAR(64) NOT NULL, subject_key VARCHAR(1024), "
                    + "event_type VARCHAR(256), set_jws VARCHAR(16384) NOT NULL, issued_at BIGINT, expires_at BIGINT, "
                    + "delivery_attempts INTEGER DEFAULT 0, next_attempt_at BIGINT, PRIMARY KEY (jti))";

    /**
     * The one additive change to a table an earlier version created. Nullable on purpose: the rows already
     * there have no owner to give, and a row with none is a stream no receiver is admitted to until an
     * operator says whose it is ({@code SsfConfiguration#unownedStreamOwner}) - not a row to guess at.
     * As wide as {@code audience}, which already holds a client id whenever a receiver sends no {@code aud}.
     */
    static final String DDL_ADD_OWNER = "ALTER TABLE ssf_streams ADD COLUMN owner_client_id VARCHAR(1024)";
    /** Selects nothing. It resolves the column exactly as the store's own statements will, or fails. */
    static final String PROBE_OWNER = "SELECT owner_client_id FROM ssf_streams WHERE 1 = 0";

    /**
     * The three optional stream members of SSF 1.0 §8.1.1 (plan item H-SSF-3, 0.6.0), added to an {@code ssf_streams}
     * an earlier version created. Nullable: a stream stored before them has none. {@code ADD COLUMN IF NOT EXISTS} is
     * PostgreSQL's (the one database this store supports since 0.5.0), and makes two nodes booting together harmless.
     * DB-2's V300 baseline (Phase 4, which removes DDL at runtime) is {@link #DDL_STREAMS} as written, these included.
     */
    static final List<String> DDL_ADD_STREAM_MEMBERS = List.of(
            "ALTER TABLE ssf_streams ADD COLUMN IF NOT EXISTS description VARCHAR(1024)",
            "ALTER TABLE ssf_streams ADD COLUMN IF NOT EXISTS min_verification_interval INTEGER",
            "ALTER TABLE ssf_streams ADD COLUMN IF NOT EXISTS inactivity_timeout BIGINT");

    /**
     * What the SCIM endpoint keeps about a user (plan item H-SSF-4, 0.6.0): one row per subject it was given, keyed by
     * the subject's canonical key, which is the SCIM {@code id}. Part of DB-2's V300 baseline as written.
     */
    static final String DDL_SCIM_USERS =
            "CREATE TABLE IF NOT EXISTS ssf_scim_users ("
                    + "subject_key VARCHAR(1024) PRIMARY KEY, subject_json VARCHAR(4096) NOT NULL, user_name VARCHAR(1024), "
                    + "external_id VARCHAR(1024), active BOOLEAN NOT NULL, streams VARCHAR(8192), "
                    + "created_at BIGINT, updated_at BIGINT)";

    private final DataSource dataSource;
    private final PushHeaderCipher headers;

    /** A store that keeps a push {@code authorization_header} in clear, as every version before 0.6.0 did. */
    public JdbcSsfStore(DataSource dataSource) {
        this(dataSource, PushHeaderCipher.CLEAR);
    }

    /**
     * A store that seals a push stream's {@code authorization_header} with {@code headers} on write and opens it on read
     * (plan item H-SSF-7): {@code push_auth_header} holds the sealed value, and an earlier version's clear value is read
     * as it is and sealed on the stream's next write.
     */
    public JdbcSsfStore(DataSource dataSource, PushHeaderCipher headers) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.headers = Objects.requireNonNull(headers, "headers");
    }

    /** Create the three tables if they don't exist, and bring an older {@code ssf_streams} up to date. Call once on boot. */
    public void ensureSchema() {
        try (Connection c = this.dataSource.getConnection()) {
            try (Statement st = c.createStatement()) {
                st.execute(DDL_STREAMS);
                st.execute(DDL_SUBJECTS);
                st.execute(DDL_PENDING);
                st.execute(DDL_SCIM_USERS);
            }
            ensureOwnerColumn(c);
            try (Statement st = c.createStatement()) {
                for (String ddl : DDL_ADD_STREAM_MEMBERS) {
                    st.execute(ddl);
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("failed to apply SSF schema", e);
        }
    }

    /**
     * {@code CREATE TABLE IF NOT EXISTS} leaves an existing table as it found it, so a deployment that
     * already has {@code ssf_streams} needs the column added. Probed rather than read from
     * {@code DatabaseMetaData}, which has to guess the engine's identifier case (HSQLDB and H2 fold to upper,
     * Postgres to lower) and can be answered by a same-named table in another schema. And rather than
     * {@code ADD COLUMN IF NOT EXISTS}, which is an extension and not standard SQL: the three engines this
     * was run against - PF 13.0.3's bundled HSQLDB 2.7.1, H2 and Postgres 16 - all have it, but a probe asks
     * nothing of an engine beyond a SELECT and a plain ALTER.
     */
    private static void ensureOwnerColumn(Connection c) throws SQLException {
        if (hasOwnerColumn(c)) {
            return;
        }
        try (Statement st = c.createStatement()) {
            st.execute(DDL_ADD_OWNER);
        } catch (SQLException e) {
            // Two nodes booting together both find the column missing, and the second ALTER fails because
            // the first landed. That is the only failure forgiven here.
            if (!hasOwnerColumn(c)) {
                throw e;
            }
        }
    }

    private static boolean hasOwnerColumn(Connection c) {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery(PROBE_OWNER)) {
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    // ─────────────────────────────── streams ───────────────────────────────

    @Override
    public Stream createStream(Stream s) {
        exec("INSERT INTO ssf_streams (stream_id, audience, delivery_method, push_endpoint_url, push_auth_header, "
                + "events_requested, events_delivered, status, status_reason, created_at, updated_at, owner_client_id, "
                + "description, min_verification_interval, inactivity_timeout) "
                + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ps -> {
                    ps.setString(1, s.id());
                    ps.setString(2, s.audience());
                    ps.setString(3, s.deliveryMethod().name());
                    ps.setString(4, s.pushEndpointUrl());
                    ps.setString(5, this.headers.seal(s.id(), s.pushAuthorizationHeader()));
                    ps.setString(6, joinEvents(s.eventsRequested()));
                    ps.setString(7, joinEvents(s.eventsDelivered()));
                    ps.setString(8, s.status().value());
                    ps.setString(9, s.statusReason());
                    ps.setLong(10, s.createdAt());
                    ps.setLong(11, s.updatedAt());
                    ps.setString(12, s.ownerClientId());
                    bindMembers(ps, 13, s);
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
        // owner_client_id is absent from this statement by design, not oversight: see SsfStore#updateStream.
        int n = exec("UPDATE ssf_streams SET audience=?, delivery_method=?, push_endpoint_url=?, push_auth_header=?, "
                + "events_requested=?, events_delivered=?, status=?, status_reason=?, updated_at=?, description=?, "
                + "min_verification_interval=?, inactivity_timeout=? WHERE stream_id=?", ps -> {
                    ps.setString(1, s.audience());
                    ps.setString(2, s.deliveryMethod().name());
                    ps.setString(3, s.pushEndpointUrl());
                    ps.setString(4, this.headers.seal(s.id(), s.pushAuthorizationHeader()));
                    ps.setString(5, joinEvents(s.eventsRequested()));
                    ps.setString(6, joinEvents(s.eventsDelivered()));
                    ps.setString(7, s.status().value());
                    ps.setString(8, s.statusReason());
                    ps.setLong(9, s.updatedAt());
                    bindMembers(ps, 10, s);
                    ps.setString(13, s.id());
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

    /** SsfStore#peek's order: oldest first, then {@code jti} bytewise (C), whatever the database's collation - as {@link #SELECT_DUE_FOR_PUSH}. */
    static final String SELECT_PEEK = "SELECT * FROM ssf_pending_sets WHERE stream_id=? ORDER BY issued_at, jti COLLATE \"C\" LIMIT ?";

    @Override
    public List<PendingSet> peek(String streamId, int max) {
        return query(SELECT_PEEK, ps -> {
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

    /**
     * The stream's state is in the query (SsfStore#dueForPush): a JOIN, so the batch is only ever deliverable
     * SETs. Ordered as {@link #SELECT_PEEK} is, {@code jti} in C order breaking a second's ties, so the push executor's
     * hold and its batch agree on which SET of a stream is first.
     */
    static final String SELECT_DUE_FOR_PUSH =
            "SELECT p.* FROM ssf_pending_sets p JOIN ssf_streams s ON s.stream_id = p.stream_id "
                    + "WHERE s.delivery_method = ? AND s.status = ? AND p.next_attempt_at <= ? "
                    + "ORDER BY p.issued_at, p.jti COLLATE \"C\" LIMIT ?";

    @Override
    public List<PendingSet> dueForPush(long now, int max) {
        return query(SELECT_DUE_FOR_PUSH, ps -> {
            ps.setString(1, DeliveryMethod.PUSH.name());
            ps.setString(2, StreamStatus.ENABLED.value());
            ps.setLong(3, now);
            ps.setInt(4, Math.max(0, max));
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

    // ─────────────────────────────── SCIM users ───────────────────────────────

    @Override
    public boolean keepsOptionalStreamMembers() {
        return true;
    }

    @Override
    public boolean keepsScimUsers() {
        return true;
    }

    @Override
    public Optional<ScimUser> getScimUser(String id) {
        return query("SELECT * FROM ssf_scim_users WHERE subject_key = ?", ps -> ps.setString(1, id),
                rs -> rs.next() ? Optional.of(mapScimUser(rs)) : Optional.<ScimUser>empty());
    }

    @Override
    public List<ScimUser> listScimUsers() {
        return query("SELECT * FROM ssf_scim_users", ps -> { }, rs -> {
            List<ScimUser> out = new ArrayList<>();
            while (rs.next()) {
                out.add(mapScimUser(rs));
            }
            return out;
        });
    }

    /** One statement, so two provisioners writing the same user leave one row whichever lands second. */
    @Override
    public void putScimUser(ScimUser u) {
        exec("INSERT INTO ssf_scim_users (subject_key, subject_json, user_name, external_id, active, streams, created_at, "
                + "updated_at) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT (subject_key) DO UPDATE SET "
                + "subject_json = EXCLUDED.subject_json, user_name = EXCLUDED.user_name, external_id = EXCLUDED.external_id, "
                + "active = EXCLUDED.active, streams = EXCLUDED.streams, updated_at = EXCLUDED.updated_at", ps -> {
                    ps.setString(1, u.id());
                    ps.setString(2, JsonUtil.toJson(u.subject().toMap()));
                    ps.setString(3, u.userName());
                    ps.setString(4, u.externalId());
                    ps.setBoolean(5, u.active());
                    ps.setString(6, joinEvents(u.restoreStreams()));
                    ps.setLong(7, u.createdAt());
                    ps.setLong(8, u.updatedAt());
                });
    }

    @Override
    public boolean deleteScimUser(String id) {
        return exec("DELETE FROM ssf_scim_users WHERE subject_key = ?", ps -> ps.setString(1, id)) > 0;
    }

    private static ScimUser mapScimUser(ResultSet rs) throws SQLException {
        return new ScimUser(parseSubject(rs.getString("subject_json")), rs.getString("user_name"),
                rs.getString("external_id"), rs.getBoolean("active"), splitEvents(rs.getString("streams")),
                rs.getLong("created_at"), rs.getLong("updated_at"));
    }

    // ─────────────────────────────── mapping + JDBC plumbing ───────────────────────────────

    private Stream mapStream(ResultSet rs) throws SQLException {
        String id = rs.getString("stream_id");
        return Stream.builder()
                .id(id)
                .audience(rs.getString("audience"))
                .ownerClientId(rs.getString("owner_client_id"))
                .deliveryMethod(DeliveryMethod.valueOf(rs.getString("delivery_method")))
                .pushEndpointUrl(rs.getString("push_endpoint_url"))
                .pushAuthorizationHeader(this.headers.open(id, rs.getString("push_auth_header")))
                .eventsRequested(splitEvents(rs.getString("events_requested")))
                .eventsDelivered(splitEvents(rs.getString("events_delivered")))
                .status(StreamStatus.fromValue(rs.getString("status")))
                .statusReason(rs.getString("status_reason"))
                .createdAt(rs.getLong("created_at"))
                .updatedAt(rs.getLong("updated_at"))
                .description(rs.getString("description"))
                .minVerificationInterval(nullableInt(rs, "min_verification_interval"))
                .inactivityTimeout(nullableLong(rs, "inactivity_timeout"))
                .build();
    }

    /** The optional members at {@code first}, {@code first + 1} and {@code first + 2}; SQL NULL for each one absent. */
    private static void bindMembers(PreparedStatement ps, int first, Stream s) throws SQLException {
        ps.setString(first, s.description());
        if (s.minVerificationInterval() == null) {
            ps.setNull(first + 1, Types.INTEGER);
        } else {
            ps.setInt(first + 1, s.minVerificationInterval());
        }
        if (s.inactivityTimeout() == null) {
            ps.setNull(first + 2, Types.BIGINT);
        } else {
            ps.setLong(first + 2, s.inactivityTimeout());
        }
    }

    private static Integer nullableInt(ResultSet rs, String column) throws SQLException {
        int v = rs.getInt(column);
        return rs.wasNull() ? null : v;
    }

    private static Long nullableLong(ResultSet rs, String column) throws SQLException {
        long v = rs.getLong(column);
        return rs.wasNull() ? null : v;
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

    /** Newline-joined: event-type URIs and stream ids contain no newlines. */
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
            throw new IllegalStateException("SSF JDBC store error: " + e.getMessage(), e);
        }
    }

    private <T> T query(String sql, Binder binder, RowReader<T> reader) {
        try (Connection c = this.dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                return reader.read(rs);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("SSF JDBC store query error: " + e.getMessage(), e);
        }
    }
}
