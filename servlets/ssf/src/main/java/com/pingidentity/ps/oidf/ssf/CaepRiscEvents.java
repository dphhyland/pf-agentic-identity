/*
 * Event-specific payload builders for the CAEP 1.0 / RISC 1.0 events this transmitter emits.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Builds the event-specific payload object that sits under an event-type URI in a SET's {@code events} map.
 * CAEP events carry an {@code event_timestamp} (epoch seconds) and optional admin/user reasons; RISC events
 * carry {@code event_timestamp} and an optional {@code reason}. These factories keep the wire shapes in one
 * place so the emitter and tests agree.
 *
 * <p>A CAEP reason is not a string. CAEP 1.0 §2 defines {@code reason_admin} and {@code reason_user} as
 * JSON objects keyed by BCP 47 language tag, and the CAEP Interop Profile requires {@code reason_admin} on
 * session-revoked (§3.1) and device-compliance-change (§3.3), "populated with a non-empty object", and its
 * suite checks the shape on every CAEP event. A caller that has only a sentence hands
 * it over as a string and it is wrapped as English ({@link #reasonAdmin}); one that has translations hands
 * over the object. Until 2026-09 this class wrote the string straight through, which a receiver checking
 * the profile refuses.
 */
public final class CaepRiscEvents {

    /** The language a bare reason string is tagged with. */
    static final String DEFAULT_LANGUAGE = "en";

    /** CAEP 1.0 §3.3 {@code credential_type} values. */
    public static final Set<String> CREDENTIAL_TYPES = Set.of("password", "pin", "x509", "fido2-platform",
            "fido2-roaming", "fido-u2f", "verifiable-credential", "phone-voice", "phone-sms", "app");

    /** CAEP 1.0 §3.3 {@code change_type} values. */
    public static final Set<String> CHANGE_TYPES = Set.of("create", "revoke", "update", "delete");

    /** CAEP 1.0 §3.5 {@code previous_status} / {@code current_status} values. */
    public static final Set<String> COMPLIANCE_STATUSES = Set.of("compliant", "not-compliant");

    /** CAEP 1.0 §2 {@code initiating_entity} values. */
    public static final Set<String> INITIATING_ENTITIES = Set.of("admin", "user", "policy", "system");

    private CaepRiscEvents() {
    }

    /** CAEP session-revoked: the subject's session was terminated (logout, admin revoke). */
    public static Map<String, Object> sessionRevoked(long eventTimestamp, String reasonAdmin) {
        return sessionRevoked(eventTimestamp, reasonAdmin(reasonAdmin));
    }

    /** CAEP session-revoked, with the reason already language-tagged ({@code {"en": "..."}}); null omits it. */
    public static Map<String, Object> sessionRevoked(long eventTimestamp, Map<String, Object> reasonAdmin) {
        LinkedHashMap<String, Object> p = new LinkedHashMap<>();
        p.put("event_timestamp", eventTimestamp);
        putReason(p, reasonAdmin);
        return p;
    }

    /**
     * CAEP credential-change: a subject credential was created/revoked/updated/deleted.
     *
     * @param credentialType e.g. {@code password}, {@code pin}, {@code fido2-roaming}
     * @param changeType     one of {@code create}, {@code revoke}, {@code update}, {@code delete}
     */
    public static Map<String, Object> credentialChange(long eventTimestamp, String credentialType, String changeType) {
        return credentialChange(eventTimestamp, credentialType, changeType, null);
    }

    /** CAEP credential-change with a language-tagged {@code reason_admin}; null omits it. */
    public static Map<String, Object> credentialChange(long eventTimestamp, String credentialType, String changeType,
                                                       Map<String, Object> reasonAdmin) {
        LinkedHashMap<String, Object> p = new LinkedHashMap<>();
        p.put("event_timestamp", eventTimestamp);
        p.put("credential_type", credentialType);
        p.put("change_type", changeType);
        putReason(p, reasonAdmin);
        return p;
    }

    /**
     * CAEP device-compliance-change (CAEP 1.0 §3.5): the subject's device moved between {@code compliant}
     * and {@code not-compliant}. Both statuses are required by the event definition, so both are written
     * as given; whether they are legal values is the caller's check ({@link #COMPLIANCE_STATUSES}).
     */
    public static Map<String, Object> deviceComplianceChange(long eventTimestamp, String previousStatus,
                                                             String currentStatus, Map<String, Object> reasonAdmin) {
        LinkedHashMap<String, Object> p = new LinkedHashMap<>();
        p.put("event_timestamp", eventTimestamp);
        p.put("previous_status", previousStatus);
        p.put("current_status", currentStatus);
        putReason(p, reasonAdmin);
        return p;
    }

    /** CAEP assurance-level-change: the session's authentication assurance moved up or down. */
    public static Map<String, Object> assuranceLevelChange(long eventTimestamp, String previousLevel,
                                                           String currentLevel) {
        LinkedHashMap<String, Object> p = new LinkedHashMap<>();
        p.put("event_timestamp", eventTimestamp);
        putIfPresent(p, "previous_level", previousLevel);
        p.put("current_level", currentLevel);
        p.put("change_direction", directionOf(previousLevel, currentLevel));
        return p;
    }

    /** RISC account-disabled: the account was disabled (optionally with a reason: {@code hijacking}, etc.). */
    public static Map<String, Object> accountDisabled(long eventTimestamp, String reason) {
        LinkedHashMap<String, Object> p = new LinkedHashMap<>();
        p.put("event_timestamp", eventTimestamp);
        putIfPresent(p, "reason", reason);
        return p;
    }

    /** RISC account-enabled: the account was re-enabled. */
    public static Map<String, Object> accountEnabled(long eventTimestamp) {
        LinkedHashMap<String, Object> p = new LinkedHashMap<>();
        p.put("event_timestamp", eventTimestamp);
        return p;
    }

    /**
     * A CAEP reason from a plain sentence: {@code {"en": text}}, or {@code null} for a blank one so the
     * member is omitted rather than sent empty (an empty object is the one shape the profile forbids).
     */
    public static Map<String, Object> reasonAdmin(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        LinkedHashMap<String, Object> reason = new LinkedHashMap<>();
        reason.put(DEFAULT_LANGUAGE, text);
        return reason;
    }

    private static void putReason(Map<String, Object> p, Map<String, Object> reasonAdmin) {
        if (reasonAdmin != null && !reasonAdmin.isEmpty()) {
            p.put("reason_admin", new LinkedHashMap<>(reasonAdmin));
        }
    }

    private static String directionOf(String previous, String current) {
        if (previous == null || current == null || previous.equals(current)) {
            return "unknown";
        }
        return previous.compareTo(current) < 0 ? "increase" : "decrease";
    }

    private static void putIfPresent(Map<String, Object> p, String key, String value) {
        if (value != null && !value.isBlank()) {
            p.put(key, value);
        }
    }
}
