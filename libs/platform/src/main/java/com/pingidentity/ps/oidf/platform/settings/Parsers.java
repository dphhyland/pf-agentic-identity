/*
 * The strict parsers every settings reader shares.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.net.URI;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import com.pingidentity.ps.oidf.platform.json.Json;

/**
 * The strict parsers a setting's value goes through, moved out of {@code FederationRuntimeConfig} (plan item
 * ST-1) with their messages unchanged.
 *
 * <p>Each takes the setting's name first, so a refusal names it, and throws {@link SettingRefused} - an
 * {@link IllegalStateException}, as before. A message carries the value refused, because an operator needs to
 * see what was read; none of these is ever given a secret's value (the model's {@code secret} type has no
 * parser, and {@link #jsonObject} never quotes its input). A value is trimmed before it is read, and a blank
 * one is unset: {@link #blankToNull}.
 */
public final class Parsers {

    private Parsers() {
    }

    /** {@code value} trimmed, or {@code null} when it is null or blank. */
    public static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    /** The system property for an {@code OIDF_...} variable: lower case, underscores as dots. */
    public static String systemPropertyName(String envName) {
        return envName.toLowerCase(Locale.ROOT).replace('_', '.');
    }

    /**
     * {@code true} or {@code false}, any case; anything else is refused rather than read as {@code false}.
     *
     * @param name  the setting, for the message
     * @param value the value read, not null
     */
    public static boolean strictBoolean(String name, String value) {
        if ("true".equalsIgnoreCase(value.trim())) {
            return true;
        }
        if ("false".equalsIgnoreCase(value.trim())) {
            return false;
        }
        throw new SettingRefused(name, name + " must be true or false, not " + value);
    }

    /** {@link #strictBoolean}, with {@code fallback} for an unset or blank value. */
    public static boolean bool(String name, String value, boolean fallback) {
        String set = blankToNull(value);
        return set == null ? fallback : strictBoolean(name, set);
    }

    /**
     * A whole number (a {@code long}, sign allowed), or {@code fallback} when unset or blank; anything else is
     * refused. No range is checked here: {@link #inRange} does that.
     */
    public static long wholeNumber(String name, String value, long fallback) {
        String set = blankToNull(value);
        if (set == null) {
            return fallback;
        }
        try {
            return Long.parseLong(set);
        } catch (NumberFormatException e) {
            throw new SettingRefused(name, name + " must be a whole number, not " + set);
        }
    }

    /** {@code value} when {@code min <= value <= max}; otherwise refused, naming the range. */
    public static long inRange(String name, long value, long min, long max) {
        if (value < min || value > max) {
            throw new SettingRefused(name, name + " must be between " + min + " and " + max + ", not " + value);
        }
        return value;
    }

    /**
     * One of {@code allowed}, any case, returned as {@code allowed} spells it; unset or blank is
     * {@code fallback}; anything else is refused, listing what is allowed.
     */
    public static String choice(String name, String value, String fallback, String... allowed) {
        String set = blankToNull(value);
        if (set == null) {
            return fallback;
        }
        for (String option : allowed) {
            if (option.equalsIgnoreCase(set)) {
                return option;
            }
        }
        throw new SettingRefused(name, name + " must be one of " + String.join(", ", allowed) + ", not " + set);
    }

    /**
     * Space- or comma-separated words, in order and without repeats; unset or blank is {@code null}, "no list",
     * and a list of nothing (only separators) is refused as a likely slip.
     */
    public static Set<String> words(String name, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        Set<String> words = new LinkedHashSet<>();
        for (String word : value.split("[\\s,]+")) {
            if (!word.isEmpty()) {
                words.add(word);
            }
        }
        if (words.isEmpty()) {
            throw new SettingRefused(name, name + " lists nothing; leave it unset instead");
        }
        return words;
    }

    /**
     * A JSON object, members in document order, read by {@link Json}: {@code null} when the text is unset,
     * blank or the JSON literal {@code null}, as the Jackson read this replaces answered. Anything else that
     * is not one well-formed JSON object - an array, a string, a number, a duplicate member name, content
     * after the object, nesting deeper than {@link Json#MAX_NESTING}, a number literal longer than
     * {@link Json#MAX_NUMBER_LITERAL} - is an {@link IllegalArgumentException} saying only "not a JSON object",
     * so the message never repeats the text, which may be key material. Numbers are {@link java.math.BigDecimal}.
     * Wrap it in {@link #strictly} to name the setting.
     */
    public static Map<String, Object> jsonObject(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        Object parsed;
        try {
            parsed = Json.parse(json);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("not a JSON object");
        }
        if (parsed == null) {
            return null;
        }
        if (!(parsed instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("not a JSON object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> object = (Map<String, Object>) parsed;
        return object;
    }

    /** A setting parsed by {@code parse}; an {@link IllegalArgumentException} from it is refused, naming the setting. */
    public static <T> T strictly(String name, Supplier<T> parse) {
        try {
            return parse.get();
        } catch (IllegalArgumentException e) {
            throw new SettingRefused(name, name + ": " + e.getMessage());
        }
    }

    /** An absolute {@code https} URL with a host, trimmed; unset or blank is {@code null}; anything else is refused. */
    public static URI httpsUrl(String name, String value) {
        return url(name, value, false);
    }

    /** An absolute {@code http} or {@code https} URL with a host, trimmed; unset or blank is {@code null}; anything else is refused. */
    public static URI httpOrHttpsUrl(String name, String value) {
        return url(name, value, true);
    }

    private static URI url(String name, String value, boolean httpAllowed) {
        String set = blankToNull(value);
        if (set == null) {
            return null;
        }
        String scheme = set.regionMatches(true, 0, "https://", 0, 8) ? "https"
                : httpAllowed && set.regionMatches(true, 0, "http://", 0, 7) ? "http" : null;
        URI uri = null;
        if (scheme != null) {
            try {
                uri = new URI(set);
            } catch (java.net.URISyntaxException e) {
                uri = null;
            }
        }
        if (uri == null || uri.getHost() == null) {
            throw new SettingRefused(name, name + " must be " + (httpAllowed ? "an http or https URL" : "an https URL")
                    + " with a host, not " + set);
        }
        return uri;
    }

    /** A file-system path, trimmed; unset or blank is {@code null}; one the platform cannot name is refused. */
    public static Path path(String name, String value) {
        String set = blankToNull(value);
        if (set == null) {
            return null;
        }
        try {
            return Path.of(set);
        } catch (InvalidPathException e) {
            throw new SettingRefused(name, name + " is not a path: " + set);
        }
    }

    /**
     * A setting with a superseded name: the current name wins; the old one is used only when the current one is
     * unset, and leaves a warning; both set to the same value leaves a warning too; both set to different
     * values is refused, naming both and neither value. The values are compared trimmed; blank is unset.
     *
     * @param name     the current name
     * @param current  its value, or null
     * @param oldName  the superseded name
     * @param old      its value, or null
     * @param warnings where a warning is added
     * @return the value in effect, trimmed, or null
     */
    public static String aliased(String name, String current, String oldName, String old, List<String> warnings) {
        String now = blankToNull(current);
        String then = blankToNull(old);
        if (then == null) {
            return now;
        }
        if (now == null) {
            warnings.add(oldName + " is deprecated; set " + name + " instead (the value was taken from " + oldName + ")");
            return then;
        }
        if (!now.equals(then)) {
            throw new SettingRefused(name, name + " and its superseded name " + oldName + " are both set, to different values."
                    + " They name one thing - set only " + name);
        }
        warnings.add(oldName + " is deprecated and redundant beside " + name + "; remove it");
        return now;
    }
}
