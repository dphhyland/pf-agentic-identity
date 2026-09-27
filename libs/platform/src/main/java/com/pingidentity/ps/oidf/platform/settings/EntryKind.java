/*
 * What kind of name a catalogue entry is.
 */
package com.pingidentity.ps.oidf.platform.settings;

/**
 * What kind of name a catalogue entry is. The first three are process-wide and resolved from their sources;
 * the last two are supplied by PingFederate - a plugin instance's configuration field, a client's extended
 * property - so they have no sources and their values are only parsed ({@link Settings#parse}).
 */
public enum EntryKind {
    /** Read first as an environment variable (its sources may add a system property or an init-param). */
    ENV("env"),
    /** Read as a system property only, or first. */
    SYSTEM_PROPERTY("system-property"),
    /** Read as a servlet's or filter's init-param only, or first. */
    INIT_PARAM("init-param"),
    /** A field of a PingFederate plugin's configuration screen. */
    PLUGIN_FIELD("plugin-field"),
    /** A PingFederate OAuth client extended property. */
    EXTENDED_PROPERTY("extended-property");

    private final String id;

    EntryKind(String id) {
        this.id = id;
    }

    /** The catalogue's spelling. */
    public String id() {
        return this.id;
    }

    /** Whether entries of this kind are resolved from sources, rather than supplied by PingFederate. */
    public boolean resolved() {
        return this == ENV || this == SYSTEM_PROPERTY || this == INIT_PARAM;
    }

    /** The source whose name an entry of this kind is named by, or null for a PingFederate-supplied kind. */
    Source namingSource() {
        switch (this) {
            case ENV:
                return Source.ENV;
            case SYSTEM_PROPERTY:
                return Source.SYSTEM_PROPERTY;
            case INIT_PARAM:
                return Source.INIT_PARAM;
            default:
                return null;
        }
    }

    /** The kind a catalogue spells {@code id}, or null. */
    static EntryKind byId(String id) {
        for (EntryKind kind : values()) {
            if (kind.id.equals(id)) {
                return kind;
            }
        }
        return null;
    }
}
