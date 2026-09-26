/*
 * The durable TrustMarkRegistry, over JDBC.
 */
package com.pingidentity.ps.oidf.trustmark;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
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
 * and its audit line are written in one transaction, so the history never disagrees with the grant.
 */
public final class JdbcTrustMarkRegistry implements TrustMarkRegistry {
    private static final String SELECT = "SELECT trust_mark_type, subject, status, granted_at, not_after, revoked_at, reason, actor"
            + " FROM trust_mark_grant";

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
        return this.inTransaction("grant a Trust Mark", c -> grantIn(c, type, subject, notAfter, actor, now));
    }

    private static TrustMarkGrant grantIn(Connection c, String type, String subject, Instant notAfter, String actor, Instant now) throws SQLException {
        int updated;
        try (PreparedStatement ps = c.prepareStatement("UPDATE trust_mark_grant SET status = 'ACTIVE', granted_at = ?, not_after = ?,"
                + " revoked_at = NULL, reason = NULL, actor = ? WHERE trust_mark_type = ? AND subject = ?")) {
            ps.setTimestamp(1, Timestamp.from(now));
            ps.setTimestamp(2, timestamp(notAfter));
            ps.setString(3, actor);
            ps.setString(4, type);
            ps.setString(5, subject);
            updated = ps.executeUpdate();
        }
        if (updated == 0) {
            try (PreparedStatement ps = c.prepareStatement("INSERT INTO trust_mark_grant (trust_mark_type, subject, status, granted_at,"
                    + " not_after, actor) VALUES (?, ?, 'ACTIVE', ?, ?, ?)")) {
                ps.setString(1, type);
                ps.setString(2, subject);
                ps.setTimestamp(3, Timestamp.from(now));
                ps.setTimestamp(4, timestamp(notAfter));
                ps.setString(5, actor);
                ps.executeUpdate();
            }
        }
        appendAudit(c, type, subject, TrustMarkAuditEntry.GRANTED, notAfter == null ? null : "not_after=" + notAfter, actor, now);
        return find(c, type, subject).orElseThrow();
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
    public TrustMarkGrant revoke(String type, String subject, String reason, String actor) throws AuthorityRegistryException {
        Instant now = this.clock.instant();
        return this.inTransaction("revoke a Trust Mark", c -> revokeIn(c, type, subject, reason, actor, now));
    }

    private static TrustMarkGrant revokeIn(Connection c, String type, String subject, String reason, String actor, Instant now)
        throws SQLException, AuthorityRegistryException {
        Optional<TrustMarkGrant> found = find(c, type, subject);
        if (found.isEmpty()) {
        throw new AuthorityRegistryException(AuthorityRegistryException.NOT_FOUND, "no grant of " + type + " to " + subject);
        }
        TrustMarkGrant current = found.get();
        if (current.status() == TrustMarkGrant.Status.REVOKED) {
        return current;
        }
        try (PreparedStatement ps = c.prepareStatement("UPDATE trust_mark_grant SET status = 'REVOKED', revoked_at = ?, reason = ?,"
                + " actor = ? WHERE trust_mark_type = ? AND subject = ?")) {
            ps.setTimestamp(1, Timestamp.from(now));
            ps.setString(2, reason);
            ps.setString(3, actor);
            ps.setString(4, type);
            ps.setString(5, subject);
            ps.executeUpdate();
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
                    grants.add(new TrustMarkGrant(rs.getString(1), rs.getString(2), TrustMarkGrant.Status.valueOf(rs.getString(3)),
                            rs.getTimestamp(4).toInstant(), instant(rs.getTimestamp(5)), instant(rs.getTimestamp(6)), rs.getString(7),
                            rs.getString(8)));
                }
            }
        }
        return List.copyOf(grants);
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
