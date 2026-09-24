/*
 * The durable KeyHistoryStore, over JDBC.
 */
package com.pingidentity.ps.oidf.keyhistory;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

/**
 * The production {@link KeyHistoryStore}, over {@code db/migration/V103__federation_key_history.sql}. A rotation - the
 * old key retired, the new one recorded - is one transaction, so every node of a cluster that notices it agrees.
 */
public final class JdbcKeyHistoryStore implements KeyHistoryStore {
    private static final String SELECT = "SELECT kid, jwk, issued_at, expires_at, revoked_at, reason FROM federation_key_history";

    private final DataSource dataSource;

    public JdbcKeyHistoryStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
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
    public Optional<HistoricalKey> rotateTo(Map<String, Object> publicJwk, Instant now, Instant retiredUntil) throws AuthorityRegistryException {
        return this.inTransaction("record the signing key", c -> rotateIn(c, publicJwk, now, retiredUntil));
    }

    private static Optional<HistoricalKey> rotateIn(Connection c, Map<String, Object> publicJwk, Instant now, Instant retiredUntil)
            throws SQLException, AuthorityRegistryException {
        String kid = (String) publicJwk.get("kid");
        String previousKid = null;
        String previousJwk = null;
        Instant previousSince = null;
        try (PreparedStatement ps = c.prepareStatement("SELECT kid, jwk, since FROM federation_key_current WHERE slot = 'signing' FOR UPDATE");
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                previousKid = rs.getString(1);
                previousJwk = rs.getString(2);
                previousSince = rs.getTimestamp(3).toInstant();
            }
        }
        if (kid.equals(previousKid)) {
            return Optional.empty();
        }
        Optional<HistoricalKey> returning = find(c, kid);
        if (returning.isPresent() && returning.get().revokedAt() != null) {
            throw new AuthorityRegistryException(AuthorityRegistryException.STALE_UPDATE, "key " + kid + " was revoked and must not sign again");
        }
        // A retired key signing again is no longer history.
        update(c, "DELETE FROM federation_key_history WHERE kid = ?", kid);
        update(c, "DELETE FROM federation_key_current WHERE slot = 'signing'");
        try (PreparedStatement ps = c.prepareStatement("INSERT INTO federation_key_current (slot, kid, jwk, since) VALUES ('signing', ?, ?, ?)")) {
            ps.setString(1, kid);
            ps.setString(2, JsonUtil.toJson(publicJwk));
            ps.setTimestamp(3, Timestamp.from(now));
            ps.executeUpdate();
        }
        if (previousKid == null) {
            return Optional.empty();
        }
        try (PreparedStatement ps = c.prepareStatement("INSERT INTO federation_key_history (kid, jwk, issued_at, expires_at) VALUES (?, ?, ?, ?)")) {
            ps.setString(1, previousKid);
            ps.setString(2, previousJwk);
            ps.setTimestamp(3, Timestamp.from(previousSince));
            ps.setTimestamp(4, Timestamp.from(retiredUntil));
            ps.executeUpdate();
        }
        return find(c, previousKid);
    }

    @Override
    public HistoricalKey revoke(String kid, Instant revokedAt, String reason) throws AuthorityRegistryException {
        return this.inTransaction("revoke a historical key", c -> revokeIn(c, kid, revokedAt, reason));
    }

    private static HistoricalKey revokeIn(Connection c, String kid, Instant revokedAt, String reason) throws SQLException, AuthorityRegistryException {
        Optional<HistoricalKey> found = find(c, kid);
        if (found.isEmpty()) {
            throw new AuthorityRegistryException(AuthorityRegistryException.NOT_FOUND, "no retired key " + kid);
        }
        if (found.get().revokedAt() != null) {
            return found.get();
        }
        try (PreparedStatement ps = c.prepareStatement("UPDATE federation_key_history SET revoked_at = ?, reason = ? WHERE kid = ?")) {
            ps.setTimestamp(1, Timestamp.from(revokedAt));
            ps.setString(2, reason);
            ps.setString(3, kid);
            ps.executeUpdate();
        }
        return find(c, kid).orElseThrow();
    }

    @Override
    public List<HistoricalKey> retired() throws AuthorityRegistryException {
        return this.inTransaction("read the key history", c -> list(c, SELECT + " ORDER BY expires_at, kid"));
    }

    private static Optional<HistoricalKey> find(Connection c, String kid) throws SQLException {
        List<HistoricalKey> found = list(c, SELECT + " WHERE kid = ?", kid);
        return found.isEmpty() ? Optional.empty() : Optional.of(found.get(0));
    }

    private static List<HistoricalKey> list(Connection c, String sql, String... parameters) throws SQLException {
        List<HistoricalKey> keys = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                ps.setString(i + 1, parameters[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    keys.add(new HistoricalKey(rs.getString(1), jwk(rs.getString(2)), instant(rs.getTimestamp(3)), rs.getTimestamp(4).toInstant(),
                            instant(rs.getTimestamp(5)), rs.getString(6)));
                }
            }
        }
        return keys;
    }

    private static void update(Connection c, String sql, String... parameters) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                ps.setString(i + 1, parameters[i]);
            }
            ps.executeUpdate();
        }
    }

    private static Map<String, Object> jwk(String json) throws SQLException {
        try {
            return JsonUtil.parseJson(json);
        } catch (JoseException e) {
            // Only ever written by rotateIn from a parsed JWK: unreadable means the row was damaged under us.
            throw new SQLException("a stored historical key is not a JWK", e);
        }
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
