/*
 * InstanceRegistry over the ID Partners Identity Object Model (Postgres JSONB entry store).
 */
package com.pingidentity.ps.oidf.device;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.jose4j.json.JsonUtil;

/**
 * The registry as entries in the Identity Object Model's single {@code idm.entry} table, beside the
 * humans the agents act for — instead of five private tables of its own. Class mapping is registered by
 * the {@code 006-add-agent-instance-registry} migration in the model repo:
 *
 * <ul>
 *   <li>{@code agentInstance} (+{@code cryptoBinding}) — the instance id is {@code subject_id}
 *       ({@code subject_type='agent'}); its {@link InstanceStatus} IS {@code record_status}; the
 *       Secure Enclave key thumbprint is both {@code attrs.cnfJkt} and the cryptoBinding
 *       {@code keyRef}. Contained under its device.</li>
 *   <li>{@code agentDevice} (+{@code cryptoBinding}) — {@code attrs.deviceId}; {@code subject_id} is
 *       the owner's {@code entry_uuid} (a reference, never containment).</li>
 *   <li>{@code authenticatorBinding} — the passkey that bound the device, contained under it.</li>
 *   <li>{@code agentLifecycleEvent} — the append-only ledger, ordered by {@code attrs.auditSeq} from a
 *       Postgres sequence.</li>
 *   <li>the owner is the existing {@code {identity, involvedParty}} row keyed by
 *       {@code attrs.pingoneUserId} — the same row the SCIM user store writes, so a person and their
 *       agent devices are one party record.</li>
 * </ul>
 *
 * <p><b>Why this is safer than the JDBC registry it replaces.</b> That one read, decided in Java, then
 * wrote — on autocommit, with no transaction — so two concurrent callers could both pass the check.
 * Here every rule is one statement the database evaluates atomically: revocation and status changes are
 * {@code UPDATE … WHERE record_status <> 'revoked'} with the audit row written by the same CTE, so a
 * losing caller updates nothing AND logs nothing; the App Attest counter is a compare-and-set
 * ({@code WHERE (attrs->>'appAttestSignCount')::bigint < ?}) which Postgres re-evaluates against the
 * locked row under READ COMMITTED, so two assertions cannot both win; duplicates are partial unique
 * indexes. A zero row count is then classified with a follow-up read: absent means {@code NOT_FOUND},
 * present means the rule refused ({@code STALE_UPDATE}) or the call was a no-op.
 *
 * <p>Postgres-specific SQL (JSONB operators, {@code ANY(object_classes)}, CTEs). The schema is owned by
 * the model repo's migration workflow — this class never creates tables.
 */
public final class IomInstanceRegistry implements InstanceRegistry {

    static final String INSTANCE_CLASS = "agentInstance";
    static final String DEVICE_CLASS = "agentDevice";
    static final String BINDING_CLASS = "authenticatorBinding";
    static final String EVENT_CLASS = "agentLifecycleEvent";
    static final String PARTY_CLASS = "involvedParty";
    private static final String CRYPTO_AUX = "cryptoBinding";

    /** SQLSTATE 23505 — unique_violation; the partial unique indexes are the DUPLICATE guard. */
    private static final String UNIQUE_VIOLATION = "23505";

    /**
     * ISO-8601 UTC with a fixed six fractional digits: the model's convention, so a timestamp held as
     * text in {@code attrs} still sorts and compares lexicographically.
     */
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'").withZone(ZoneOffset.UTC);

    private final DataSource dataSource;

    public IomInstanceRegistry(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    // ─────────────────────────────── owner ───────────────────────────────

    @Override
    public OwnerUser upsertOwner(String pingOneSubject) throws RegistryException {
        requireText(pingOneSubject, "pingOneSubject");
        String id = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("cn", pingOneSubject);
        attrs.put("identityID", id);
        attrs.put("identityType", "person");
        attrs.put("identityDescriptor", "agent owner (PingOne subject)");
        attrs.put("internalKey", id);
        attrs.put("pingoneUserId", pingOneSubject);

        // Race-free: the partial unique index arbitrates, so a concurrent caller does not get a
        // duplicate and does not get an exception either — it falls through to the read below.
        Optional<OwnerUser> inserted = query(
                "INSERT INTO idm.entry (entry_uuid, object_classes, subject_id, subject_type, attrs, created_at, modified_at) "
                        + "VALUES (?::uuid, ?::text[], ?, 'person', ?::jsonb, to_timestamp(?), to_timestamp(?)) "
                        + "ON CONFLICT ((attrs->>'pingoneUserId')) WHERE '" + PARTY_CLASS + "' = ANY (object_classes) "
                        + "DO NOTHING "
                        + "RETURNING entry_uuid::text, extract(epoch FROM created_at)",
                ps -> {
                    ps.setString(1, id);
                    ps.setString(2, "{identity," + PARTY_CLASS + "}");
                    ps.setString(3, id);
                    ps.setString(4, JsonUtil.toJson(attrs));
                    ps.setDouble(5, epoch(now));
                    ps.setDouble(6, epoch(now));
                },
                rs -> rs.next()
                        ? Optional.of(new OwnerUser(rs.getString(1), pingOneSubject, instant(rs.getDouble(2))))
                        : Optional.<OwnerUser>empty());
        if (inserted.isPresent()) {
            return inserted.get();
        }
        return query("SELECT entry_uuid::text, extract(epoch FROM created_at) FROM idm.entry "
                        + "WHERE attrs->>'pingoneUserId' = ? AND ? = ANY (object_classes)",
                ps -> {
                    ps.setString(1, pingOneSubject);
                    ps.setString(2, PARTY_CLASS);
                },
                rs -> rs.next() ? new OwnerUser(rs.getString(1), pingOneSubject, instant(rs.getDouble(2))) : null,
                () -> new RegistryException(RegistryException.STORAGE_FAILURE,
                        "owner neither inserted nor found: " + pingOneSubject));
    }

    @Override
    public Optional<OwnerUser> findOwner(String ownerUserId) throws RegistryException {
        requireText(ownerUserId, "ownerUserId");
        if (!isUuid(ownerUserId)) {
            return Optional.empty();
        }
        return query("SELECT entry_uuid::text, attrs->>'pingoneUserId', extract(epoch FROM created_at) "
                        + "FROM idm.entry WHERE entry_uuid = ?::uuid AND ? = ANY (object_classes)",
                ps -> {
                    ps.setString(1, ownerUserId);
                    ps.setString(2, PARTY_CLASS);
                },
                rs -> rs.next()
                        ? Optional.of(new OwnerUser(rs.getString(1), rs.getString(2), instant(rs.getDouble(3))))
                        : Optional.<OwnerUser>empty());
    }

    // ─────────────────────────────── device ───────────────────────────────

    @Override
    public Device registerDevice(Device device) throws RegistryException {
        Objects.requireNonNull(device, "device");
        if (!isUuid(device.ownerUserId())) {
            throw new RegistryException(RegistryException.NOT_FOUND, "no such owner: " + device.ownerUserId());
        }
        Map<String, Object> attrs = deviceAttrs(device);
        int n = execUnique(
                "INSERT INTO idm.entry (object_classes, subject_id, subject_type, attrs) "
                        + "SELECT ?::text[], ?, 'person', ?::jsonb "
                        + "WHERE EXISTS (SELECT 1 FROM idm.entry o WHERE o.entry_uuid = ?::uuid AND ? = ANY (o.object_classes))",
                ps -> {
                    ps.setString(1, "{" + DEVICE_CLASS + "," + CRYPTO_AUX + "}");
                    ps.setString(2, device.ownerUserId());
                    ps.setString(3, JsonUtil.toJson(attrs));
                    ps.setString(4, device.ownerUserId());
                    ps.setString(5, PARTY_CLASS);
                },
                () -> "device already registered: " + device.id());
        if (n == 0) {
            throw new RegistryException(RegistryException.NOT_FOUND, "no such owner: " + device.ownerUserId());
        }
        return device;
    }

    @Override
    public Optional<Device> findDevice(String deviceId) throws RegistryException {
        requireText(deviceId, "deviceId");
        return query(deviceSelect() + " WHERE d.attrs->>'deviceId' = ? AND ? = ANY (d.object_classes)",
                ps -> {
                    ps.setString(1, deviceId);
                    ps.setString(2, DEVICE_CLASS);
                },
                rs -> rs.next() ? Optional.of(readDevice(rs)) : Optional.<Device>empty());
    }

    /** Every device owned by the party with this PingOne subject — the CAEP user-subject fan-out path. */
    @Override
    public List<Device> devicesOwnedBy(String pingOneSubject) throws RegistryException {
        requireText(pingOneSubject, "pingOneSubject");
        return query(deviceSelect()
                        + " JOIN idm.entry o ON o.entry_uuid::text = d.subject_id AND ? = ANY (o.object_classes) "
                        + "WHERE o.attrs->>'pingoneUserId' = ? AND ? = ANY (d.object_classes) "
                        + "ORDER BY d.attrs->>'deviceId'",
                ps -> {
                    ps.setString(1, PARTY_CLASS);
                    ps.setString(2, pingOneSubject);
                    ps.setString(3, DEVICE_CLASS);
                },
                rs -> {
                    List<Device> out = new ArrayList<>();
                    while (rs.next()) {
                        out.add(readDevice(rs));
                    }
                    return out;
                });
    }

    @Override
    public void updateCompliance(String deviceId, ComplianceState state, Instant checkedAt) throws RegistryException {
        requireText(deviceId, "deviceId");
        Objects.requireNonNull(state, "state");
        Instant when = checkedAt == null ? Instant.now() : checkedAt;
        int n = exec("UPDATE idm.entry SET attrs = attrs || jsonb_build_object("
                        + "'complianceState', ?::text, 'complianceCheckedAt', ?::text) "
                        + "WHERE attrs->>'deviceId' = ? AND ? = ANY (object_classes)",
                ps -> {
                    ps.setString(1, state.caepValue());
                    ps.setString(2, TS.format(when));
                    ps.setString(3, deviceId);
                    ps.setString(4, DEVICE_CLASS);
                });
        if (n == 0) {
            throw new RegistryException(RegistryException.NOT_FOUND, "no such device: " + deviceId);
        }
        auditDevice(deviceId, AuditEntry.COMPLIANCE_CHANGED, state.caepValue());
    }

    @Override
    public void recordAppAttestCounter(String deviceId, long counter) throws RegistryException {
        requireText(deviceId, "deviceId");
        // Compare-and-set: Postgres re-evaluates the predicate against the locked row version, so two
        // concurrent assertions with the same counter cannot both succeed.
        int n = exec("UPDATE idm.entry SET attrs = attrs || jsonb_build_object('appAttestSignCount', ?::bigint) "
                        + "WHERE attrs->>'deviceId' = ? AND ? = ANY (object_classes) "
                        + "AND (attrs->>'appAttestSignCount')::bigint < ?",
                ps -> {
                    ps.setLong(1, counter);
                    ps.setString(2, deviceId);
                    ps.setString(3, DEVICE_CLASS);
                    ps.setLong(4, counter);
                });
        if (n == 0) {
            if (findDevice(deviceId).isEmpty()) {
                throw new RegistryException(RegistryException.NOT_FOUND, "no such device: " + deviceId);
            }
            throw new RegistryException(RegistryException.STALE_UPDATE,
                    "App Attest counter did not advance for device " + deviceId + ": " + counter);
        }
    }

    // ─────────────────────────────── instance ───────────────────────────────

    @Override
    public AgentInstance register(AgentInstance instance) throws RegistryException {
        Objects.requireNonNull(instance, "instance");
        Map<String, Object> attrs = instanceAttrs(instance);
        // One statement: materialise the instance under its device and write its first ledger entry.
        // A missing device yields zero rows (NOT_FOUND); a repeat trips the unique index (DUPLICATE).
        int n = execUnique(
                "WITH ins AS ("
                        + "  INSERT INTO idm.entry (object_classes, subject_id, subject_type, parent_id, record_status, attrs) "
                        + "  SELECT ?::text[], ?, 'agent', d.entry_uuid, ?::idm.record_status, ?::jsonb "
                        + "    FROM idm.entry d WHERE d.attrs->>'deviceId' = ? AND ? = ANY (d.object_classes) "
                        + "  RETURNING entry_uuid, subject_id) "
                        + "INSERT INTO idm.entry (object_classes, subject_id, subject_type, parent_id, attrs) "
                        + "SELECT ?::text[], subject_id, 'agent', entry_uuid, "
                        + "  jsonb_build_object('eventCode', ?::text, 'eventTimestamp', ?::text, "
                        + "                     'auditSeq', nextval('idm.agent_lifecycle_event_seq')) "
                        + "FROM ins",
                ps -> {
                    ps.setString(1, "{" + INSTANCE_CLASS + "," + CRYPTO_AUX + "}");
                    ps.setString(2, instance.id());
                    ps.setString(3, recordStatus(instance.status()));
                    ps.setString(4, JsonUtil.toJson(attrs));
                    ps.setString(5, instance.deviceId());
                    ps.setString(6, DEVICE_CLASS);
                    ps.setString(7, "{" + EVENT_CLASS + "}");
                    ps.setString(8, AuditEntry.INSTANCE_REGISTERED);
                    ps.setString(9, TS.format(Instant.now()));
                },
                () -> "instance already registered: " + instance.id());
        if (n == 0) {
            throw new RegistryException(RegistryException.NOT_FOUND, "no such device: " + instance.deviceId());
        }
        return instance;
    }

    @Override
    public Optional<AgentInstance> findInstance(String instanceId) throws RegistryException {
        requireText(instanceId, "instanceId");
        return query(instanceSelect() + " WHERE i.subject_id = ? AND ? = ANY (i.object_classes)",
                ps -> {
                    ps.setString(1, instanceId);
                    ps.setString(2, INSTANCE_CLASS);
                },
                rs -> rs.next() ? Optional.of(readInstance(rs)) : Optional.<AgentInstance>empty());
    }

    @Override
    public List<AgentInstance> instancesOnDevice(String deviceId) throws RegistryException {
        requireText(deviceId, "deviceId");
        return query(instanceSelect()
                        + " WHERE ? = ANY (i.object_classes) AND i.parent_id = "
                        + "(SELECT entry_uuid FROM idm.entry WHERE attrs->>'deviceId' = ? AND ? = ANY (object_classes)) "
                        + "ORDER BY i.subject_id",
                ps -> {
                    ps.setString(1, INSTANCE_CLASS);
                    ps.setString(2, deviceId);
                    ps.setString(3, DEVICE_CLASS);
                },
                rs -> {
                    List<AgentInstance> out = new ArrayList<>();
                    while (rs.next()) {
                        out.add(readInstance(rs));
                    }
                    return out;
                });
    }

    @Override
    public void revoke(String instanceId, String reason) throws RegistryException {
        requireText(instanceId, "instanceId");
        // Idempotent by construction: the WHERE excludes already-revoked rows, so a retried CAEP event
        // updates nothing and — because the ledger insert is fed by the same CTE — logs nothing either.
        int n = statusChange(instanceId, InstanceStatus.REVOKED, reason,
                AuditEntry.INSTANCE_REVOKED, " AND record_status <> 'revoked'");
        if (n == 0 && findInstance(instanceId).isEmpty()) {
            throw new RegistryException(RegistryException.NOT_FOUND, "no such instance: " + instanceId);
        }
    }

    @Override
    public void setStatus(String instanceId, InstanceStatus status, String reason) throws RegistryException {
        requireText(instanceId, "instanceId");
        Objects.requireNonNull(status, "status");
        if (status == InstanceStatus.REVOKED) {
            revoke(instanceId, reason);
            return;
        }
        int n = statusChange(instanceId, status, reason, AuditEntry.INSTANCE_STATUS_CHANGED,
                " AND record_status <> 'revoked' AND record_status <> ?::idm.record_status");
        if (n == 0) {
            AgentInstance existing = findInstance(instanceId).orElseThrow(() ->
                    new RegistryException(RegistryException.NOT_FOUND, "no such instance: " + instanceId));
            if (existing.status() == InstanceStatus.REVOKED) {
                throw new RegistryException(RegistryException.STALE_UPDATE,
                        "instance is revoked; revocation is permanent: " + instanceId);
            }
            // already in the requested state — a no-op, not a failure
        }
    }

    @Override
    public void recordUserVerification(String instanceId, Instant when) throws RegistryException {
        requireText(instanceId, "instanceId");
        Instant at = when == null ? Instant.now() : when;
        touchInstance(instanceId, "uvLastVerifiedAt", TS.format(at), AuditEntry.USER_VERIFIED, TS.format(at));
    }

    @Override
    public void recordAttestationExpiry(String instanceId, Instant expiresAt) throws RegistryException {
        requireText(instanceId, "instanceId");
        Objects.requireNonNull(expiresAt, "expiresAt");
        touchInstance(instanceId, "attestationExp", TS.format(expiresAt),
                AuditEntry.ATTESTATION_ISSUED, TS.format(expiresAt));
    }

    // ─────────────────────────────── authenticator ───────────────────────────────

    @Override
    public BoundAuthenticator bindAuthenticator(BoundAuthenticator authenticator) throws RegistryException {
        Objects.requireNonNull(authenticator, "authenticator");
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("bindingId", authenticator.id());
        attrs.put("credentialId", authenticator.credentialId());
        attrs.put("authenticatorType", authenticator.authenticatorType());
        putIfPresent(attrs, "aaguid", authenticator.aaguid());
        attrs.put("deviceRef", authenticator.deviceId());
        attrs.put("eventTimestamp", TS.format(authenticator.boundAt()));
        attrs.put("outcome", "granted");

        int n = execUnique(
                "INSERT INTO idm.entry (object_classes, subject_id, subject_type, parent_id, attrs) "
                        + "SELECT ?::text[], d.subject_id, 'person', d.entry_uuid, ?::jsonb "
                        + "  FROM idm.entry d WHERE d.attrs->>'deviceId' = ? AND ? = ANY (d.object_classes)",
                ps -> {
                    ps.setString(1, "{" + BINDING_CLASS + "}");
                    ps.setString(2, JsonUtil.toJson(attrs));
                    ps.setString(3, authenticator.deviceId());
                    ps.setString(4, DEVICE_CLASS);
                },
                () -> "authenticator binding already recorded: " + authenticator.id());
        if (n == 0) {
            throw new RegistryException(RegistryException.NOT_FOUND, "no such device: " + authenticator.deviceId());
        }
        return authenticator;
    }

    // ─────────────────────────────── audit ───────────────────────────────

    @Override
    public void audit(String instanceId, String eventCode, String detail) throws RegistryException {
        requireText(eventCode, "eventCode");
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("eventCode", eventCode);
        attrs.put("eventTimestamp", TS.format(Instant.now()));
        putIfPresent(attrs, "detail", detail);
        // parent_id resolves to the instance when it exists; the old table had no FK, so an event for
        // an unknown instance is still recorded (unparented) rather than refused.
        exec("INSERT INTO idm.entry (object_classes, subject_id, subject_type, parent_id, attrs) "
                        + "VALUES (?::text[], ?, 'agent', "
                        + "(SELECT entry_uuid FROM idm.entry WHERE subject_id = ? AND ? = ANY (object_classes)), "
                        + "?::jsonb || jsonb_build_object('auditSeq', nextval('idm.agent_lifecycle_event_seq')))",
                ps -> {
                    ps.setString(1, "{" + EVENT_CLASS + "}");
                    ps.setString(2, instanceId);
                    ps.setString(3, instanceId);
                    ps.setString(4, INSTANCE_CLASS);
                    ps.setString(5, JsonUtil.toJson(attrs));
                });
    }

    @Override
    public List<AuditEntry> auditTrail(String instanceId) throws RegistryException {
        requireText(instanceId, "instanceId");
        return query("SELECT subject_id, attrs->>'eventCode', attrs->>'detail', attrs->>'eventTimestamp' "
                        + "FROM idm.entry WHERE subject_id = ? AND ? = ANY (object_classes) "
                        + "ORDER BY (attrs->>'auditSeq')::bigint",
                ps -> {
                    ps.setString(1, instanceId);
                    ps.setString(2, EVENT_CLASS);
                },
                rs -> {
                    List<AuditEntry> out = new ArrayList<>();
                    while (rs.next()) {
                        out.add(new AuditEntry(rs.getString(1), rs.getString(2), rs.getString(3),
                                parseTs(rs.getString(4))));
                    }
                    return out;
                });
    }

    // ─────────────────────────────── internals ───────────────────────────────

    /**
     * The status-change CTE: flip {@code record_status} and write the matching ledger entry in ONE
     * statement, so a caller that loses the guard writes neither. {@code guard} adds the predicates that
     * make the change conditional (never leave revoked; don't re-apply the current status); when it
     * contains a placeholder, the status is bound a second time.
     */
    private int statusChange(String instanceId, InstanceStatus status, String reason, String eventCode,
                             String guard) throws RegistryException {
        boolean boundStatus = guard.contains("?");
        String sql = "WITH upd AS ("
                + "  UPDATE idm.entry SET record_status = ?::idm.record_status"
                + "     , attrs = CASE WHEN ?::text IS NULL THEN attrs ELSE attrs || jsonb_build_object('statusReason', ?::text) END"
                + "   WHERE subject_id = ? AND ? = ANY (object_classes)" + guard
                + "  RETURNING entry_uuid, subject_id) "
                + "INSERT INTO idm.entry (object_classes, subject_id, subject_type, parent_id, attrs) "
                + "SELECT ?::text[], subject_id, 'agent', entry_uuid, "
                + "  jsonb_build_object('eventCode', ?::text, 'eventTimestamp', ?::text, "
                + "    'auditSeq', nextval('idm.agent_lifecycle_event_seq')) "
                + "  || CASE WHEN ?::text IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('detail', ?::text) END "
                + "FROM upd";
        return exec(sql, ps -> {
            int i = 1;
            ps.setString(i++, recordStatus(status));
            ps.setString(i++, reason);
            ps.setString(i++, reason);
            ps.setString(i++, instanceId);
            ps.setString(i++, INSTANCE_CLASS);
            if (boundStatus) {
                ps.setString(i++, recordStatus(status));
            }
            ps.setString(i++, "{" + EVENT_CLASS + "}");
            ps.setString(i++, eventCode);
            ps.setString(i++, TS.format(Instant.now()));
            ps.setString(i++, reason);
            ps.setString(i, reason);
        });
    }

    /** Set one instance attribute and log it, in one statement; NOT_FOUND when the instance is unknown. */
    private void touchInstance(String instanceId, String attr, String value, String eventCode, String detail)
            throws RegistryException {
        int n = exec("WITH upd AS ("
                        + "  UPDATE idm.entry SET attrs = attrs || jsonb_build_object(?::text, ?::text) "
                        + "   WHERE subject_id = ? AND ? = ANY (object_classes) "
                        + "  RETURNING entry_uuid, subject_id) "
                        + "INSERT INTO idm.entry (object_classes, subject_id, subject_type, parent_id, attrs) "
                        + "SELECT ?::text[], subject_id, 'agent', entry_uuid, "
                        + "  jsonb_build_object('eventCode', ?::text, 'eventTimestamp', ?::text, 'detail', ?::text, "
                        + "    'auditSeq', nextval('idm.agent_lifecycle_event_seq')) "
                        + "FROM upd",
                ps -> {
                    ps.setString(1, attr);
                    ps.setString(2, value);
                    ps.setString(3, instanceId);
                    ps.setString(4, INSTANCE_CLASS);
                    ps.setString(5, "{" + EVENT_CLASS + "}");
                    ps.setString(6, eventCode);
                    ps.setString(7, TS.format(Instant.now()));
                    ps.setString(8, detail);
                });
        if (n == 0) {
            throw new RegistryException(RegistryException.NOT_FOUND, "no such instance: " + instanceId);
        }
    }

    /** A device-level ledger entry: no instance subject, parented on the device. */
    private void auditDevice(String deviceId, String eventCode, String detail) throws RegistryException {
        exec("INSERT INTO idm.entry (object_classes, subject_id, subject_type, parent_id, attrs) "
                        + "SELECT ?::text[], NULL, NULL, d.entry_uuid, "
                        + "  jsonb_build_object('eventCode', ?::text, 'eventTimestamp', ?::text, 'detail', ?::text, "
                        + "    'deviceRef', ?::text, 'auditSeq', nextval('idm.agent_lifecycle_event_seq')) "
                        + "FROM idm.entry d WHERE d.attrs->>'deviceId' = ? AND ? = ANY (d.object_classes)",
                ps -> {
                    ps.setString(1, "{" + EVENT_CLASS + "}");
                    ps.setString(2, eventCode);
                    ps.setString(3, TS.format(Instant.now()));
                    ps.setString(4, detail);
                    ps.setString(5, deviceId);
                    ps.setString(6, deviceId);
                    ps.setString(7, DEVICE_CLASS);
                });
    }

    private static String instanceSelect() {
        return "SELECT i.subject_id, i.attrs->>'platformEntityId', i.attrs->>'agentBuild', i.attrs->>'cnfJkt', "
                + "i.record_status::text, i.attrs->>'deviceRef', i.attrs->>'enrolledAt', "
                + "i.attrs->>'attestationExp', i.attrs->>'uvLastVerifiedAt' "
                + "FROM idm.entry i";
    }

    private static AgentInstance readInstance(ResultSet rs) throws SQLException {
        return new AgentInstance(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                instanceStatus(rs.getString(5)), rs.getString(6), parseTs(rs.getString(7)),
                parseTs(rs.getString(8)), parseTs(rs.getString(9)));
    }

    private static String deviceSelect() {
        return "SELECT d.attrs->>'deviceId', d.attrs->>'platform', d.attrs->>'model', d.attrs->>'osVersion', "
                + "d.attrs->>'appAttestKeyId', d.attrs->>'appAttestEnvironment', "
                + "(d.attrs->>'appAttestSignCount')::bigint, d.attrs->>'complianceState', "
                + "d.attrs->>'complianceCheckedAt', d.subject_id "
                + "FROM idm.entry d";
    }

    private static Device readDevice(ResultSet rs) throws SQLException {
        return new Device(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5),
                rs.getString(6), rs.getLong(7), ComplianceState.fromCaepValue(rs.getString(8)),
                parseTs(rs.getString(9)), rs.getString(10));
    }

    private Map<String, Object> instanceAttrs(AgentInstance i) {
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("platformEntityId", i.platformEntityId());
        attrs.put("cnfJkt", i.cnfJkt());
        attrs.put("deviceRef", i.deviceId());
        attrs.put("enrolledAt", TS.format(i.enrolledAt()));
        putIfPresent(attrs, "agentBuild", i.agentBuild());
        if (i.attestationExp() != null) {
            attrs.put("attestationExp", TS.format(i.attestationExp()));
        }
        if (i.uvLastVerifiedAt() != null) {
            attrs.put("uvLastVerifiedAt", TS.format(i.uvLastVerifiedAt()));
        }
        // cryptoBinding: the Secure Enclave key this instance proves possession of
        attrs.put("pqPosture", "classical");
        attrs.put("keyRef", i.cnfJkt());
        attrs.put("keyKty", "EC");
        attrs.put("sigAlgorithm", "ES256");
        return attrs;
    }

    private Map<String, Object> deviceAttrs(Device d) {
        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("deviceId", d.id());
        attrs.put("platform", d.platform());
        putIfPresent(attrs, "model", d.model());
        putIfPresent(attrs, "osVersion", d.osVersion());
        attrs.put("appAttestKeyId", d.appAttestKeyId());
        attrs.put("appAttestEnvironment", d.appAttestEnvironment());
        attrs.put("appAttestSignCount", d.appAttestSignCount());
        attrs.put("complianceState", d.complianceState().caepValue());
        if (d.complianceCheckedAt() != null) {
            attrs.put("complianceCheckedAt", TS.format(d.complianceCheckedAt()));
        }
        // cryptoBinding: the App Attest key. The store holds no key material — only the reference.
        attrs.put("pqPosture", "classical");
        attrs.put("keyRef", d.appAttestKeyId());
        attrs.put("keyKty", "EC");
        attrs.put("sigAlgorithm", "ES256");
        return attrs;
    }

    private static void putIfPresent(Map<String, Object> attrs, String key, String value) {
        if (value != null && !value.isBlank()) {
            attrs.put(key, value);
        }
    }

    /** {@link InstanceStatus} and {@code idm.record_status} carry the same three states. */
    private static String recordStatus(InstanceStatus status) {
        return switch (status) {
            case ACTIVE -> "active";
            case SUSPENDED -> "suspended";
            case REVOKED -> "revoked";
        };
    }

    /** Fail closed: a status this registry does not own reads as REVOKED, never as usable. */
    private static InstanceStatus instanceStatus(String recordStatus) {
        return switch (recordStatus == null ? "" : recordStatus) {
            case "active" -> InstanceStatus.ACTIVE;
            case "suspended" -> InstanceStatus.SUSPENDED;
            default -> InstanceStatus.REVOKED;
        };
    }

    private static Instant parseTs(String value) {
        return value == null || value.isBlank() ? null : Instant.parse(value);
    }

    private static double epoch(Instant when) {
        return when.getEpochSecond() + when.getNano() / 1_000_000_000.0;
    }

    private static Instant instant(double epochSeconds) {
        long secs = (long) epochSeconds;
        return Instant.ofEpochSecond(secs, Math.round((epochSeconds - secs) * 1_000_000_000L));
    }

    private static boolean isUuid(String value) {
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }

    private interface Binder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    private interface RowReader<T> {
        T read(ResultSet rs) throws SQLException;
    }

    private interface Supplier<T> {
        T get();
    }

    private int exec(String sql, Binder binder) throws RegistryException {
        try (Connection c = this.dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw storage(e);
        }
    }

    /** As {@link #exec}, but a unique-index violation is a DUPLICATE rather than a storage fault. */
    private int execUnique(String sql, Binder binder, Supplier<String> duplicateMessage) throws RegistryException {
        try (Connection c = this.dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            return ps.executeUpdate();
        } catch (SQLException e) {
            if (UNIQUE_VIOLATION.equals(e.getSQLState())) {
                throw new RegistryException(RegistryException.DUPLICATE, duplicateMessage.get(), e);
            }
            throw storage(e);
        }
    }

    private <T> T query(String sql, Binder binder, RowReader<T> reader) throws RegistryException {
        try (Connection c = this.dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                return reader.read(rs);
            }
        } catch (SQLException e) {
            throw storage(e);
        }
    }

    private <T> T query(String sql, Binder binder, RowReader<T> reader, Supplier<RegistryException> ifNull)
            throws RegistryException {
        T value = query(sql, binder, reader);
        if (value == null) {
            throw ifNull.get();
        }
        return value;
    }

    private static RegistryException storage(SQLException e) {
        return new RegistryException(RegistryException.STORAGE_FAILURE,
                "instance registry store error: " + e.getMessage(), e);
    }
}
