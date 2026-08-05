/*
 * The durable AgentRegistry, over JDBC.
 */
package com.pingidentity.ps.oidf.agent;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import javax.sql.DataSource;

/**
 * The production {@link AgentRegistry}, backed by the schema in
 * {@code db/migration/V200__agent_identity.sql}.
 *
 * <p>{@link #resolveOrMint} is race-safe via an {@code INSERT ... ON CONFLICT (natural key) DO NOTHING}
 * followed by a {@code SELECT} on that same natural key: the insert is atomic regardless of how many
 * callers race it, so at most one of them actually inserts a row, and every caller — including the ones
 * that lost the race — reads back the single canonical row afterward. This works identically against
 * Postgres (the deployment target) and H2 in PostgreSQL-compatibility mode (the test target).
 */
public final class JdbcAgentRegistry implements AgentRegistry {

    private final DataSource dataSource;

    public JdbcAgentRegistry(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public AgentIdentity resolveOrMint(String iss, String clientId, String instanceFormat, String instanceSubject)
            throws AgentRegistryException {
        requireNonBlank(iss, "iss");
        requireNonBlank(clientId, "clientId");
        requireNonBlank(instanceFormat, "instanceFormat");
        requireNonBlank(instanceSubject, "instanceSubject");
        try (Connection c = this.dataSource.getConnection()) {
            // Bare ON CONFLICT DO NOTHING, not ON CONFLICT (natural key) DO NOTHING: H2 (the test target,
            // even in PostgreSQL compatibility mode) only accepts the bare form, and it is just as
            // correct here — the row's only two unique constraints are agent_id's primary key (never
            // conflicts in practice; see AgentIdMinter) and the natural key, so any conflict this insert
            // can hit is the one resolveOrMint means to no-op against.
            try (PreparedStatement ps = c.prepareStatement(
                    "INSERT INTO agent_identity (agent_id, iss, client_id, instance_format, instance_subject, minted_at)"
                            + " VALUES (?,?,?,?,?,?)"
                            + " ON CONFLICT DO NOTHING")) {
                ps.setString(1, AgentIdMinter.mint());
                ps.setString(2, iss);
                ps.setString(3, clientId);
                ps.setString(4, instanceFormat);
                ps.setString(5, instanceSubject);
                ps.setTimestamp(6, Timestamp.from(Instant.now()));
                ps.executeUpdate();
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT agent_id, iss, client_id, instance_format, instance_subject, minted_at"
                            + " FROM agent_identity WHERE iss = ? AND client_id = ? AND instance_format = ?"
                            + " AND instance_subject = ?")) {
                ps.setString(1, iss);
                ps.setString(2, clientId);
                ps.setString(3, instanceFormat);
                ps.setString(4, instanceSubject);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        // The insert above either created this row or lost a race to a concurrent insert
                        // of the identical natural key — either way a row must now exist. Its absence
                        // means something else deleted it between the insert and this select, which this
                        // registry never does itself; that is a genuine fault, not "not found".
                        throw new AgentRegistryException(AgentRegistryException.MINT_COLLISION,
                                "agent_identity row vanished immediately after resolveOrMint's own upsert for "
                                        + "iss=" + iss + " client_id=" + clientId);
                    }
                    return new AgentIdentity(rs.getString(1), rs.getString(2), rs.getString(3),
                            rs.getString(4), rs.getString(5), rs.getTimestamp(6).toInstant());
                }
            }
        } catch (SQLException e) {
            throw new AgentRegistryException(AgentRegistryException.STORAGE_FAILURE,
                    "could not resolve or mint agent_id: " + e.getMessage(), e);
        }
    }

    private static void requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
