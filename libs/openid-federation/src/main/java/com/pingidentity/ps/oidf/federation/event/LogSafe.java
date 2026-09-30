/*
 * Making a value safe to put in a log line - a façade over platform's LogSafe.
 */
package com.pingidentity.ps.oidf.federation.event;

/**
 * Every caller-influenced string that reaches a log line goes through here: control characters become
 * {@code _}, anything shaped like a compact JWS or JWE becomes {@code jwt:sha256:<12 hex>}, and values are cut
 * at {@link #maxValueLength()} characters. The rules, and the one truncation length per loader, are
 * {@link com.pingidentity.ps.oidf.platform.events.LogSafe}'s.
 *
 * @deprecated Use {@link com.pingidentity.ps.oidf.platform.events.LogSafe}; plan item O-2 (Phase 3) removes this
 *     façade.
 */
@Deprecated(since = "0.5.0", forRemoval = true)
public final class LogSafe {
    /** Default for {@link #maxValueLength()}. */
    public static final int DEFAULT_MAX_VALUE_LENGTH = com.pingidentity.ps.oidf.platform.events.LogSafe.DEFAULT_MAX_VALUE_LENGTH;

    private LogSafe() {
    }

    /** Sets the truncation length; values below 16 are raised to 16. */
    public static void configureMaxValueLength(int length) {
        com.pingidentity.ps.oidf.platform.events.LogSafe.configureMaxValueLength(length);
    }

    public static int maxValueLength() {
        return com.pingidentity.ps.oidf.platform.events.LogSafe.maxValueLength();
    }

    /** The value with tokens digested, control characters replaced and length capped; {@code null} stays {@code null}. */
    public static String value(String raw) {
        return com.pingidentity.ps.oidf.platform.events.LogSafe.value(raw);
    }

    /** {@link #value}, then quoted with {@code "} when it holds a space, {@code =} or {@code "}. */
    public static String quoted(String raw) {
        return com.pingidentity.ps.oidf.platform.events.LogSafe.quoted(raw);
    }

    /** {@code jwt:sha256:<first 12 hex of SHA-256>} for a token, for correlating without logging it. */
    public static String jwtDigest(String jwt) {
        return com.pingidentity.ps.oidf.platform.events.LogSafe.jwtDigest(jwt);
    }
}
