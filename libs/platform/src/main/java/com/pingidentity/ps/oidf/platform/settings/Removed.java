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
 * @param source      where it was read
 * @param replacement the name to set instead, or null when nothing replaces it
 * @param release     the release it was removed in, for example {@code 0.4.0}
 */
public record Removed(String name, Source source, String replacement, String release) {

    public Removed {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(release, "release");
    }

    /** The refusal for this name being set. */
    public SettingRefused refusal() {
        return new SettingRefused(this.name, this.replacement == null
                ? this.name + " was removed in " + this.release + " and nothing replaces it; unset it"
                : this.name + " was removed in " + this.release + "; set " + this.replacement + " instead");
    }
}
