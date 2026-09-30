/*
 * Where a resolved value came from.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Where a resolved value came from: the source and the name that supplied it, which is an alias's name when
 * the value came from a superseded name, and the {@code _FILE} variant's name, with the file, when a secret was
 * read from a file. {@link Source#DEFAULT} with the setting's own name when nothing was set.
 *
 * @param source the source
 * @param name   the name that supplied the value
 * @param file   the file a {@code _FILE} variant named, or null
 */
public record Provenance(Source source, String name, Path file) {

    public Provenance {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(name, "name");
    }

    /** Whether the entry's default is in effect. */
    public boolean isDefault() {
        return this.source == Source.DEFAULT;
    }

    /** {@code env OIDF_X}, {@code env OIDF_X_FILE (/run/secrets/x)} or {@code default}. */
    @Override
    public String toString() {
        if (isDefault()) {
            return "default";
        }
        return this.source.id() + " " + this.name + (this.file == null ? "" : " (" + this.file + ")");
    }
}
