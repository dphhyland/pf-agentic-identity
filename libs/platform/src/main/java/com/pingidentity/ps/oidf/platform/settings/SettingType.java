/*
 * What kind of value a setting holds.
 */
package com.pingidentity.ps.oidf.platform.settings;

/** What kind of value a setting holds, by the id a catalogue spells it with. */
public enum SettingType {
    /** {@code true} or {@code false}, any case. A switch always has a default. */
    BOOL("bool"),
    /** A whole number that fits an {@code int}, within the entry's range. */
    INT("int"),
    /** A whole number that fits a {@code long}, within the entry's range. */
    LONG("long"),
    /** A whole number of seconds, within the entry's range, read as a {@link java.time.Duration}. */
    SECONDS("seconds"),
    /** A whole number of milliseconds, within the entry's range, read as a {@link java.time.Duration}. */
    MILLIS("millis"),
    /** Text, trimmed. */
    STRING("string"),
    /** One of the entry's choices, any case, read as the entry spells it. */
    CHOICE("choice"),
    /** An absolute https URL with a host. */
    HTTPS_URL("https-url"),
    /** An absolute http or https URL with a host. */
    URL("url"),
    /** A JSON object. */
    JSON_OBJECT("json-object"),
    /** Space- or comma-separated words. */
    WORDS("words"),
    /** A file-system path. */
    PATH("path"),
    /** Text that is never shown: not in a message, not in a log line, not in {@code toString}. */
    SECRET("secret");

    private final String id;

    SettingType(String id) {
        this.id = id;
    }

    /** The catalogue's spelling. */
    public String id() {
        return this.id;
    }

    /** Whether the entry has a range ({@code min} and {@code max}). */
    public boolean ranged() {
        return this == INT || this == LONG || this == SECONDS || this == MILLIS;
    }

    /** The type a catalogue spells {@code id}, or null. */
    static SettingType byId(String id) {
        for (SettingType type : values()) {
            if (type.id.equals(id)) {
                return type;
            }
        }
        return null;
    }
}
