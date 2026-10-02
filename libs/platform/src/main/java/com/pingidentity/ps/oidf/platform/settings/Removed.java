/*
 * A name that is no longer read.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.Objects;

/**
 * A setting name that is no longer read, and is refused when it is set, so a deployment that still sets it
 * hears about it rather than silently losing the setting.
 *
 * @param name        the removed name
 * @param kind        what kind of name it was: an environment variable, a system property or an init-param, which
 *                    {@link Catalogue#refuseRemoved} refuses on any read, or a plugin's field, which the plugin
 *                    refuses when its configuration still carries it ({@link Catalogue#refuseRemovedFields})
 * @param replacement the name to set instead, or null when nothing replaces it
 * @param release     the release it was removed in, for example {@code 0.4.0}
 */
public record Removed(String name, EntryKind kind, String replacement, String release) {

    public Removed {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(release, "release");
        if (kind == EntryKind.EXTENDED_PROPERTY) {
            throw new IllegalArgumentException("a removed name is an env, a system-property, an init-param or a plugin-field");
        }
    }

    /** A removed environment variable, system property or init-param. */
    public Removed(String name, Source source, String replacement, String release) {
        this(name, EntryKind.of(Objects.requireNonNull(source, "source")), replacement, release);
    }

    /** Where it was read from, or null for a plugin's field, which PingFederate supplies. */
    public Source source() {
        return this.kind.namingSource();
    }

    /** The refusal for this name being set. */
    public SettingRefused refusal() {
        return new SettingRefused(this.name, this.replacement == null
                ? this.name + " was removed in " + this.release + " and nothing replaces it; unset it"
                : this.name + " was removed in " + this.release + "; set " + this.replacement + " instead");
    }
}
