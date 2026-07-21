/*
 * Maps PingFederate security-audit events (audit.log MDC fields) to SSF CAEP/RISC emissions.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Pure translation from a PingFederate security-audit event to an SSF emission. PF writes its audit
 * stream (audit.log) through five dedicated log4j2 loggers whose events carry everything in the
 * ThreadContext: {@code event} (SSO/SLO/OAuth/…), {@code subject}, {@code status}
 * (success/failure/inprogress), plus session correlators ({@code sri}, {@code uniqueuserkey}).
 * {@code SsfAuditLogSource} feeds those context maps here; this class decides whether they become a
 * Security Event Token.
 *
 * <p>Only {@code status=success} events with a non-blank subject map — failures and in-progress
 * check-ins never signal. The default vocabulary maps PF's session-termination audit events to CAEP
 * {@code session-revoked}; deployments can extend or override it with the {@code auditEventMap}
 * config setting, a comma-separated {@code EVENT=action} list where action is one of
 * {@code session-revoked}, {@code credential-change}, {@code account-disabled},
 * {@code account-enabled} (e.g. {@code auditEventMap=SLO=session-revoked,PWD_CHANGE=credential-change}).
 * Unknown audit events are ignored.
 */
public final class AuditEventMapper {

    /** The SSF action a PF audit event maps to. */
    public enum Action { SESSION_REVOKED, CREDENTIAL_CHANGE, ACCOUNT_DISABLED, ACCOUNT_ENABLED }

    /** A mapped, ready-to-emit event. */
    public record Mapped(Action action, String subject, String auditEvent) {
        public Mapped {
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(subject, "subject");
        }
    }

    private final Map<String, Action> byEvent;

    /** Default mapping: PF's session-termination audit events → CAEP session-revoked. */
    public AuditEventMapper() {
        this(null);
    }

    /**
     * @param overrideSpec optional {@code EVENT=action} CSV merged over the defaults; {@code EVENT=} (empty
     *     action) removes a default entry. Null/blank keeps the defaults.
     */
    public AuditEventMapper(String overrideSpec) {
        LinkedHashMap<String, Action> m = new LinkedHashMap<>();
        // Conservative defaults: only events that unambiguously mean "this subject's session ended".
        m.put("SLO", Action.SESSION_REVOKED);
        m.put("SESSION_REVOKED", Action.SESSION_REVOKED);
        m.put("SESSION_DELETED", Action.SESSION_REVOKED);
        m.put("AUTHN_SESSION_DELETED", Action.SESSION_REVOKED);
        m.put("SRI_REVOKED", Action.SESSION_REVOKED);
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
                    m.put(event, parseAction(action));
                }
            }
        }
        this.byEvent = m;
    }

    private static Action parseAction(String s) {
        switch (s.toLowerCase(Locale.ROOT)) {
            case "session-revoked": return Action.SESSION_REVOKED;
            case "credential-change": return Action.CREDENTIAL_CHANGE;
            case "account-disabled": return Action.ACCOUNT_DISABLED;
            case "account-enabled": return Action.ACCOUNT_ENABLED;
            default:
                throw new IllegalArgumentException("unknown auditEventMap action: " + s
                        + " (expected session-revoked | credential-change | account-disabled | account-enabled)");
        }
    }

    /**
     * Maps one audit event. Empty unless the event name is mapped, {@code status} is {@code success},
     * and {@code subject} is non-blank (PF logs subject-less audit lines for pre-authentication phases —
     * there is nothing to signal about).
     */
    public Optional<Mapped> map(String event, String status, String subject) {
        if (event == null || subject == null || subject.isBlank()
                || status == null || !"success".equalsIgnoreCase(status.trim())) {
            return Optional.empty();
        }
        Action action = this.byEvent.get(event.trim().toUpperCase(Locale.ROOT));
        return action == null ? Optional.empty()
                : Optional.of(new Mapped(action, subject.trim(), event.trim()));
    }

    /** The active event→action vocabulary (for logging/tests). */
    public Map<String, Action> vocabulary() {
        return Map.copyOf(this.byEvent);
    }
}
