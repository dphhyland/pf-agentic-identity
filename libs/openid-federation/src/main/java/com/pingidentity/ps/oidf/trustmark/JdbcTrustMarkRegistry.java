/*
 * The durable TrustMarkRegistry, over JDBC.
 */
package com.pingidentity.ps.oidf.trustmark;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.authority.HostedEntityConfigurationCache;
import com.pingidentity.ps.oidf.federation.EntityId;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;

/**
 * The production {@link TrustMarkRegistry}, over the schema in {@code db/migration/V102__trust_mark.sql}. Each change
 * and its audit line are written in one transaction, so the history never disagrees with the grant. A change applies
 * only to the grant it read (its status and {@code granted_at} in the {@code WHERE}, and the row count checked): of two
 * operators changing one grant at once, the second to commit gets {@code STALE_UPDATE} and writes nothing.
 */
public final class JdbcTrustMarkRegistry implements TrustMarkRegistry {
    private static final String SELECT = "SELECT trust_mark_type, subject, status, granted_at, not_after, revoked_at, reason, actor"
            + " FROM trust_mark_grant";
    /** SQLSTATE of a unique or primary key violation, on Postgres and H2 alike. */
    private static final String UNIQUE_VIOLATION = "23505";

    private final DataSource dataSource;
    private final Clock clock;

    public JdbcTrustMarkRegistry(DataSource dataSource, Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** A unit of work in one transaction. */
    private interface Work<T> {
        T run(Connection c) throws SQLException, AuthorityRegistryException;
    }

    private <T> T inTransaction(String operation, Work<T> work) throws AuthorityRegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                T result = work.run(c);
                c.commit();
                return result;
            } catch (SQLException | AuthorityRegistryException | RuntimeException e) {
                c.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "could not " + operation, e);
        }
    }

    @Override
    public TrustMarkGrant grant(String type, String subject, Instant notAfter, String actor) throws AuthorityRegistryException {
        Instant now = this.clock.instant();
        TrustMarkGrant granted = this.inTransaction("grant a Trust Mark", c -> grantIn(c, type, subject, notAfter, actor, now));
        HostedEntityConfigurationCache.changed(subject);
        return granted;
    }

    /**
     * A first grant inserts the row; granting again - reinstating a revoked grant, or restarting a standing one - updates
     * it only while it is still the grant just read: the same status and the same {@code granted_at} (plan item
     * H-FED-3). A change that committed in between, or a first grant racing another, is {@code STALE_UPDATE}.
     */
    private static TrustMarkGrant grantIn(Connection c, String type, String subject, Instant notAfter, String actor, Instant now)
            throws SQLException, AuthorityRegistryException {
        Optional<TrustMarkGrant> current = find(c, type, subject);
        if (current.isEmpty()) {
            try (PreparedStatement ps = c.prepareStatement("INSERT INTO trust_mark_grant (trust_mark_type, subject, status, granted_at,"
                    + " not_after, actor) VALUES (?, ?, 'ACTIVE', ?, ?, ?)")) {
                ps.setString(1, type);
                ps.setString(2, subject);
                ps.setTimestamp(3, Timestamp.from(now));
                ps.setTimestamp(4, timestamp(notAfter));
                ps.setString(5, actor);
                ps.executeUpdate();
            } catch (SQLException e) {
                if (UNIQUE_VIOLATION.equals(e.getSQLState())) {
                    throw stale(type, subject);
                }
                throw e;
            }
        } else {
            try (PreparedStatement ps = c.prepareStatement("UPDATE trust_mark_grant SET status = 'ACTIVE', granted_at = ?, not_after = ?,"
                    + " revoked_at = NULL, reason = NULL, actor = ? WHERE trust_mark_type = ? AND subject = ? AND status = ? AND granted_at = ?")) {
                ps.setTimestamp(1, Timestamp.from(now));
                ps.setTimestamp(2, timestamp(notAfter));
                ps.setString(3, actor);
                ps.setString(4, type);
                ps.setString(5, subject);
                ps.setString(6, current.get().status().name());
                ps.setTimestamp(7, Timestamp.from(current.get().grantedAt()));
                if (ps.executeUpdate() != 1) {
                    throw stale(type, subject);
                }
            }
        }
        appendAudit(c, type, subject, TrustMarkAuditEntry.GRANTED, notAfter == null ? null : "not_after=" + notAfter, actor, now);
        return find(c, type, subject).orElseThrow();
    }

    private static AuthorityRegistryException stale(String type, String subject) {
        return new AuthorityRegistryException(AuthorityRegistryException.STALE_UPDATE,
                "the grant of " + type + " to " + subject + " changed while this change was being made; read it again");
    }

    @Override
    public Optional<TrustMarkGrant> find(String type, String subject) throws AuthorityRegistryException {
        return this.inTransaction("read a Trust Mark grant", c -> find(c, type, subject));
    }

    @Override
    public List<TrustMarkGrant> grantsTo(String subject) throws AuthorityRegistryException {
        return this.inTransaction("read Trust Mark grants", c -> list(c, SELECT + " WHERE subject = ? ORDER BY trust_mark_type", subject));
    }

    @Override
    public List<TrustMarkGrant> grantsOf(String type) throws AuthorityRegistryException {
        return this.inTransaction("read Trust Mark grants", c -> list(c, SELECT + " WHERE trust_mark_type = ? ORDER BY subject", type));
    }

    @Override
    public List<TrustMarkGrant> standing(String type, String subject, Instant now) throws AuthorityRegistryException {
        return this.inTransaction("read Trust Mark grants", c -> standingIn(c, type, subject, now));
    }

    private static List<TrustMarkGrant> standingIn(Connection c, String type, String subject, Instant now) throws SQLException {
        String sql = SELECT + " WHERE trust_mark_type = ? AND status = 'ACTIVE' AND (not_after IS NULL OR not_after > ?)"
                + (subject == null ? "" : " AND subject IN (?, ?)") + " ORDER BY subject";
        List<TrustMarkGrant> grants = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, type);
            ps.setTimestamp(2, Timestamp.from(now));
            if (subject != null) {
                // The two spellings EntityId.same equates: with and without the trailing slash.
                String bare = EntityId.comparable(subject);
                ps.setString(3, bare);
                ps.setString(4, bare + "/");
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    grants.add(grant(rs));
                }
            }
        }
        return List.copyOf(grants);
    }

    @Override
    public TrustMarkGrant revoke(String type, String subject, String reason, String actor) throws AuthorityRegistryException {
        Instant now = this.clock.instant();
        TrustMarkGrant revoked = this.inTransaction("revoke a Trust Mark", c -> revokeIn(c, type, subject, null, reason, actor, now));
        HostedEntityConfigurationCache.changed(subject);
        return revoked;
    }

    @Override
    public TrustMarkGrant revoke(TrustMarkGrant expected, String reason, String actor) throws AuthorityRegistryException {
        Instant now = this.clock.instant();
        TrustMarkGrant revoked = this.inTransaction("revoke a Trust Mark",
                c -> revokeIn(c, expected.type(), expected.subject(), expected, reason, actor, now));
        HostedEntityConfigurationCache.changed(expected.subject());
        return revoked;
    }

    /** {@code expected} null: the grant as read; otherwise only {@code expected}, unchanged. */
    private static TrustMarkGrant revokeIn(Connection c, String type, String subject, TrustMarkGrant expected, String reason, String actor,
            Instant now) throws SQLException, AuthorityRegistryException {
        Optional<TrustMarkGrant> found = find(c, type, subject);
        if (found.isEmpty()) {
            throw new AuthorityRegistryException(AuthorityRegistryException.NOT_FOUND, "no grant of " + type + " to " + subject);
        }
        TrustMarkGrant current = found.get();
        if (expected != null && !TrustMarkGrant.sameGrant(current, expected)) {
            throw stale(type, subject);
        }
        if (current.status() == TrustMarkGrant.Status.REVOKED) {
            return current;
        }
        // Only the standing grant just read is revoked (plan item H-FED-3).
        try (PreparedStatement ps = c.prepareStatement("UPDATE trust_mark_grant SET status = 'REVOKED', revoked_at = ?, reason = ?,"
                + " actor = ? WHERE trust_mark_type = ? AND subject = ? AND status = 'ACTIVE' AND granted_at = ?")) {
            ps.setTimestamp(1, Timestamp.from(now));
            ps.setString(2, reason);
            ps.setString(3, actor);
            ps.setString(4, type);
            ps.setString(5, subject);
            ps.setTimestamp(6, Timestamp.from(current.grantedAt()));
            if (ps.executeUpdate() != 1) {
                throw stale(type, subject);
            }
        }
        appendAudit(c, type, subject, TrustMarkAuditEntry.REVOKED, reason, actor, now);
        return find(c, type, subject).orElseThrow();
    }

    @Override
    public List<TrustMarkAuditEntry> auditTrail(String type, String subject) throws AuthorityRegistryException {
        return this.inTransaction("read the Trust Mark audit trail", c -> auditTrailIn(c, type, subject));
    }

    private static List<TrustMarkAuditEntry> auditTrailIn(Connection c, String type, String subject) throws SQLException {
        List<TrustMarkAuditEntry> trail = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement("SELECT trust_mark_type, subject, event_code, detail, actor, at"
                + " FROM trust_mark_audit_log WHERE trust_mark_type = ? AND subject = ? ORDER BY seq")) {
            ps.setString(1, type);
            ps.setString(2, subject);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    trail.add(new TrustMarkAuditEntry(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                            rs.getString(5), rs.getTimestamp(6).toInstant()));
                }
            }
        }
        return List.copyOf(trail);
    }

    private static Optional<TrustMarkGrant> find(Connection c, String type, String subject) throws SQLException {
        List<TrustMarkGrant> found = list(c, SELECT + " WHERE trust_mark_type = ? AND subject = ?", type, subject);
        return found.isEmpty() ? Optional.empty() : Optional.of(found.get(0));
    }

    private static List<TrustMarkGrant> list(Connection c, String sql, String... parameters) throws SQLException {
        List<TrustMarkGrant> grants = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                ps.setString(i + 1, parameters[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    grants.add(grant(rs));
                }
            }
        }
        return List.copyOf(grants);
    }

    private static TrustMarkGrant grant(ResultSet rs) throws SQLException {
        return new TrustMarkGrant(rs.getString(1), rs.getString(2), TrustMarkGrant.Status.valueOf(rs.getString(3)),
                rs.getTimestamp(4).toInstant(), instant(rs.getTimestamp(5)), instant(rs.getTimestamp(6)), rs.getString(7), rs.getString(8));
    }

    private static void appendAudit(Connection c, String type, String subject, String eventCode, String detail, String actor, Instant at)
            throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("INSERT INTO trust_mark_audit_log (trust_mark_type, subject, event_code, detail,"
                + " actor, at) VALUES (?, ?, ?, ?, ?, ?)")) {
            ps.setString(1, type);
            ps.setString(2, subject);
            ps.setString(3, eventCode);
            ps.setString(4, detail);
            ps.setString(5, actor);
            ps.setTimestamp(6, Timestamp.from(at));
            ps.executeUpdate();
        }
    }

    private static Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
