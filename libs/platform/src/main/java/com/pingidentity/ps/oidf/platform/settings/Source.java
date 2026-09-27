/*
 * Where a setting's value comes from.
 */
package com.pingidentity.ps.oidf.platform.settings;

/** Where a setting's value comes from: the three places a process reads, and the entry's default. */
public enum Source {
    /** A Java system property. */
    SYSTEM_PROPERTY("system-property"),
    /** A process environment variable. */
    ENV("env"),
    /** A servlet's or filter's init-param. */
    INIT_PARAM("init-param"),
    /** Nothing was set; the entry's default is in effect. Never a catalogue source. */
    DEFAULT("default");

    private final String id;

    Source(String id) {
        this.id = id;
    }

    /** The catalogue's spelling. */
    public String id() {
        return this.id;
    }

    /**
     * The name of the {@code _FILE} variant of a secret named {@code name} in this source: {@code X_FILE} for an
     * environment variable, {@code x.file} for a system property, {@code xFile} for an init-param.
     */
    String fileVariant(String name) {
        switch (this) {
            case ENV:
                return name + "_FILE";
            case SYSTEM_PROPERTY:
                return name + ".file";
            default:
                return name + "File";
        }
    }

    /** The source a catalogue spells {@code id}, or null; {@code default} is not one. */
    static Source byId(String id) {
        for (Source source : new Source[] {SYSTEM_PROPERTY, ENV, INIT_PARAM}) {
            if (source.id.equals(id)) {
                return source;
            }
        }
        return null;
    }
}
