/*
 * Making a value safe to put in a log line.
 */
package com.pingidentity.ps.oidf.platform.events;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Every caller-influenced string that reaches a log line goes through here.
 *
 * <ul>
 *   <li>Control characters (CR and LF above all) become {@code _}: an entity identifier, a client id or a
 *       {@code sub} parameter is attacker-supplied, and a newline in one would forge a log line.</li>
 *   <li>Anything shaped like a compact JWS or JWE - a first segment that is base64url JSON, so it starts
 *       {@code eyJ} - is replaced by {@code jwt:sha256:<12 hex>}. A token can then never reach a log line
 *       through the event API, whatever a caller passes, and two lines about the same token still
 *       correlate.</li>
 *   <li>Values are truncated to {@link #maxValueLength()} characters.</li>
 * </ul>
 *
 * <p>The truncation length is per loaded copy of this class, like every static in platform.
 */
public final class LogSafe {
    /** Default for {@link #maxValueLength()}. */
    public static final int DEFAULT_MAX_VALUE_LENGTH = 512;

    /** The least {@link #configureMaxValueLength} accepts; a smaller value is raised to it. */
    public static final int MIN_MAX_VALUE_LENGTH = 16;

    private static final Pattern COMPACT_JOSE = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*(?:\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*)?");

    private static volatile int maxValueLength = DEFAULT_MAX_VALUE_LENGTH;

    private LogSafe() {
    }

    /** Sets the truncation length; values below 16 are raised to 16. */
    public static void configureMaxValueLength(int length) {
        maxValueLength = Math.max(MIN_MAX_VALUE_LENGTH, length);
    }

    public static int maxValueLength() {
        return maxValueLength;
    }

    /** The value with tokens digested, control characters replaced and length capped; {@code null} stays {@code null}. */
    public static String value(String raw) {
        if (raw == null) {
            return null;
        }
        String digested = digestTokens(raw);
        int cap = maxValueLength;
        StringBuilder out = new StringBuilder(Math.min(digested.length(), cap + 1));
        for (int i = 0; i < digested.length(); i++) {
            char c = digested.charAt(i);
            out.append(Character.isISOControl(c) ? '_' : c);
            if (out.length() >= cap) {
                out.append('…');
                break;
            }
        }
        return out.toString();
    }

    /** {@link #value}, then quoted with {@code "} when it holds a space, {@code =} or {@code "}. */
    public static String quoted(String raw) {
        String safe = value(raw);
        if (safe == null) {
            return "-";
        }
        if (safe.isEmpty() || safe.indexOf(' ') >= 0 || safe.indexOf('=') >= 0 || safe.indexOf('"') >= 0) {
            return "\"" + safe.replace("\"", "\\\"") + "\"";
        }
        return safe;
    }

    /** {@code jwt:sha256:<first 12 hex of SHA-256>} for a token, for correlating without logging it. */
    public static String jwtDigest(String jwt) {
        return "jwt:sha256:" + sha256Hex12(jwt);
    }

    /** The first twelve hex digits of the SHA-256 of {@code value}'s UTF-8 bytes. */
    static String sha256Hex12(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, 12);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    static String digestTokens(String raw) {
        if (raw.indexOf("eyJ") < 0) {
            return raw;
        }
        Matcher matcher = COMPACT_JOSE.matcher(raw);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            matcher.appendReplacement(out, Matcher.quoteReplacement(jwtDigest(matcher.group())));
        }
        matcher.appendTail(out);
        return out.toString();
    }
}
