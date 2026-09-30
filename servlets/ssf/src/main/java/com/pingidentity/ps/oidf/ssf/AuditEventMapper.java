/*
 * Maps PingFederate security-audit events (audit.log MDC fields) to SSF CAEP/RISC emissions.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.signals.CaepRiscEvents;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Pure translation from a PingFederate security-audit event to an SSF emission. PF writes its audit
 * stream (audit.log) through dedicated log4j2 loggers whose events carry everything in the
 * ThreadContext: {@code event} (SSO/SLO/OAuth/…), {@code subject}, {@code status}
 * (success/failure/inprogress), {@code transactionid}, plus session correlators ({@code sri}, {@code uniqueuserkey}).
 * {@code SsfAuditLogSource} feeds those context maps here; this class decides whether they become a
 * Security Event Token.
 *
 * <p>Only {@code status=success} events with a non-blank subject map — failures and in-progress
 * check-ins never signal. The default vocabulary ({@link #DEFAULTS}, plan item H-SSF-5) is every event name
 * PingFederate 13.1.3 writes to its audit loggers that means one CAEP or RISC event without ambiguity; the table in
 * servlets/ssf/README.md ("The audit source") gives each PingFederate event, what it maps to, and why the others do
 * not. A deployment extends or overrides it with {@code OIDF_SSF_AUDIT_EVENT_MAP}, a comma-separated
 * {@code EVENT=action} list where action is one of {@code session-revoked}, {@code session-established},
 * {@code credential-change:<credential_type>[:<change_type>]}, {@code account-disabled}, {@code account-enabled},
 * {@code account-purged}; {@code EVENT=} removes a default. A {@code credential-change} names its CAEP 1.0
 * {@code credential_type}; one without is accepted and never sent (a credential this transmitter cannot name is not
 * sent as a guess), and one CAEP does not register is refused. Unknown audit events are ignored.
 */
public final class AuditEventMapper {

    /** The SSF action a PF audit event maps to. */
    public enum Action {
        SESSION_REVOKED, SESSION_ESTABLISHED, CREDENTIAL_CHANGE, ACCOUNT_DISABLED, ACCOUNT_ENABLED, ACCOUNT_PURGED
    }

    /**
     * What one audit event name becomes: an action and, for a {@code credential-change}, its CAEP
     * {@code credential_type} (null when the mapping named none, and then nothing is sent) and {@code change_type}.
     */
    public record Rule(Action action, String credentialType, String changeType) {
        public Rule {
            Objects.requireNonNull(action, "action");
        }

        static Rule of(Action action) {
            return new Rule(action, null, null);
        }
    }

    /** A mapped, ready-to-emit event: the rule, the subject, the audit event's name and PingFederate's transaction id. */
    public record Mapped(Rule rule, String subject, String auditEvent, String transactionId) {
        public Mapped {
            Objects.requireNonNull(rule, "rule");
            Objects.requireNonNull(subject, "subject");
        }

        public Action action() {
            return this.rule.action();
        }
    }

    /**
     * The default vocabulary: PingFederate 13.1.3's audit event names (read from its classes, 2026-10-01) that map to
     * one CAEP 1.0 or RISC 1.0 event without ambiguity.
     */
    public static final Map<String, Rule> DEFAULTS = defaults();

    private static Map<String, Rule> defaults() {
        LinkedHashMap<String, Rule> m = new LinkedHashMap<>();
        // AuditLogger.EVENT_SLO: a single logout. On 13.1.3 an OIDC logout's record has no subject, so it raises
        // nothing (LogoutEventFilter does); a SAML SLO's names the subject.
        m.put("SLO", Rule.of(Action.SESSION_REVOKED));
        // IdpAuditLogger.EVENT_SESSION_REVOKED, written by logSessionRevocation(ByUserKey): the session revocation API.
        m.put("SRI_REVOKED", Rule.of(Action.SESSION_REVOKED));
        // IdpAuditLogger.EVENT_SESSION_DELETED, written by logSessionDeleted: the subject's authentication sessions deleted.
        m.put("AUTHN_SESSIONS_DELETED", Rule.of(Action.SESSION_REVOKED));
        // IdpAuditLogger$AuthnSessionEvent.EVENT_AUTHN_SESSION_CREATED: CAEP 1.0 §3.6, "a new session for the subject".
        m.put("AUTHN_SESSION_CREATED", Rule.of(Action.SESSION_ESTABLISHED));
        // LocalIdentityAuditLogger$LocalIdentityAuditEvent.PWD_CHANGE: the subject changed their password.
        m.put("PWD_CHANGE", new Rule(Action.CREDENTIAL_CHANGE, "password", "update"));
        // LocalIdentityAuditLogger$LocalIdentityAuditEvent.ACCOUNT_DELETE: RISC 1.0 §2.2, "permanently deleted".
        m.put("ACCOUNT_DELETE", Rule.of(Action.ACCOUNT_PURGED));
        return java.util.Collections.unmodifiableMap(m);
    }

    private final Map<String, Rule> byEvent;

    /** The default vocabulary. */
    public AuditEventMapper() {
        this(null);
    }

    /**
     * @param overrideSpec optional {@code EVENT=action} CSV merged over the defaults; {@code EVENT=} (empty
     *     action) removes a default entry. Null/blank keeps the defaults.
     * @throws IllegalArgumentException for an action this class does not know, or a credential or change type CAEP 1.0
     *     does not register
     */
    public AuditEventMapper(String overrideSpec) {
        LinkedHashMap<String, Rule> m = new LinkedHashMap<>(DEFAULTS);
        if (overrideSpec != null && !overrideSpec.isBlank()) {
            for (String pair : overrideSpec.split(",")) {
                String[] kv = pair.split("=", 2);
                String event = kv[0].trim().toUpperCase(Locale.ROOT);
                if (event.isEmpty()) {
                    continue;
                }
                String action = kv.length > 1 ? kv[1].trim() : "";
                if (action.isEmpty()) {
                    m.remove(event);
                } else {
                    m.put(event, parseRule(action));
                }
            }
        }
        this.byEvent = m;
    }

    static Rule parseRule(String s) {
        String[] parts = s.split(":", -1);
        String action = parts[0].trim().toLowerCase(Locale.ROOT);
        if ("credential-change".equals(action)) {
            if (parts.length > 3) {
                throw new IllegalArgumentException("auditEventMap: credential-change takes at most a credential_type and a"
                        + " change_type (credential-change:<credential_type>[:<change_type>]), not '" + s + "'");
            }
            String type = parts.length > 1 ? parts[1].trim() : "";
            String change = parts.length > 2 ? parts[2].trim() : "update";
            if (!type.isEmpty() && !CaepRiscEvents.CREDENTIAL_TYPES.contains(type)) {
                throw new IllegalArgumentException("auditEventMap: credential_type '" + type + "' is not one of CAEP 1.0's "
                        + CaepRiscEvents.CREDENTIAL_TYPES);
            }
            if (!CaepRiscEvents.CHANGE_TYPES.contains(change)) {
                throw new IllegalArgumentException("auditEventMap: change_type '" + change + "' is not one of CAEP 1.0's "
                        + CaepRiscEvents.CHANGE_TYPES);
            }
            return new Rule(Action.CREDENTIAL_CHANGE, type.isEmpty() ? null : type, change);
        }
        if (parts.length > 1) {
            throw new IllegalArgumentException("auditEventMap: only credential-change takes a qualifier, not '" + s + "'");
        }
        switch (action) {
            case "session-revoked": return Rule.of(Action.SESSION_REVOKED);
            case "session-established": return Rule.of(Action.SESSION_ESTABLISHED);
            case "account-disabled": return Rule.of(Action.ACCOUNT_DISABLED);
            case "account-enabled": return Rule.of(Action.ACCOUNT_ENABLED);
            case "account-purged": return Rule.of(Action.ACCOUNT_PURGED);
            default:
                throw new IllegalArgumentException("unknown auditEventMap action: " + s
                        + " (expected session-revoked | session-established | credential-change:<credential_type>"
                        + " | account-disabled | account-enabled | account-purged)");
        }
    }

    /** {@link #map(String, String, String, String)} with no transaction id. */
    public Optional<Mapped> map(String event, String status, String subject) {
        return map(event, status, subject, null);
    }

    /**
     * Maps one audit event. Empty unless the event name is mapped, {@code status} is {@code success},
     * and {@code subject} is non-blank (PF logs subject-less audit lines for pre-authentication phases, and
     * for an OIDC logout on 13.1.3 — there is nothing to signal about).
     */
    public Optional<Mapped> map(String event, String status, String subject, String transactionId) {
        if (event == null || subject == null || subject.isBlank()
                || status == null || !"success".equalsIgnoreCase(status.trim())) {
            return Optional.empty();
        }
        Rule rule = this.byEvent.get(event.trim().toUpperCase(Locale.ROOT));
        String txn = transactionId == null || transactionId.isBlank() ? null : transactionId.trim();
        return rule == null ? Optional.empty()
                : Optional.of(new Mapped(rule, subject.trim(), event.trim(), txn));
    }

    /** The active event→rule vocabulary (for logging/tests). */
    public Map<String, Rule> vocabulary() {
        return Map.copyOf(this.byEvent);
    }
}
