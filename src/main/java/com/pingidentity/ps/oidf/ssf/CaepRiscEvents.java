/*
 * Event-specific payload builders for the CAEP 1.0 / RISC 1.0 events this transmitter emits.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the event-specific payload object that sits under an event-type URI in a SET's {@code events} map.
 * CAEP events carry an {@code event_timestamp} (epoch seconds) and optional admin/user reasons; RISC events
 * carry {@code event_timestamp} and an optional {@code reason}. These factories keep the wire shapes in one
 * place so the emitter and tests agree.
 */
public final class CaepRiscEvents {

    private CaepRiscEvents() {
    }

    /** CAEP session-revoked: the subject's session was terminated (logout, admin revoke). */
    public static Map<String, Object> sessionRevoked(long eventTimestamp, String reasonAdmin) {
        LinkedHashMap<String, Object> p = new LinkedHashMap<>();
        p.put("event_timestamp", eventTimestamp);
        putIfPresent(p, "reason_admin", reasonAdmin);
        return p;
    }

    /**
     * CAEP credential-change: a subject credential was created/revoked/updated/deleted.
     *
     * @param credentialType e.g. {@code password}, {@code pin}, {@code fido2-roaming}
     * @param changeType     one of {@code create}, {@code revoke}, {@code update}, {@code delete}
     */
    public static Map<String, Object> credentialChange(long eventTimestamp, String credentialType, String changeType) {
        LinkedHashMap<String, Object> p = new LinkedHashMap<>();
        p.put("event_timestamp", eventTimestamp);
        p.put("credential_type", credentialType);
        p.put("change_type", changeType);
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
