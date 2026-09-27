/*
 * One place a setting is read from.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.Objects;

/**
 * One place a setting is read from: a source and the name it has there.
 *
 * @param source the source
 * @param name   the name in it, for example {@code OIDF_PDP_MODE} or {@code oidf.pdp.mode}
 */
public record SourceName(Source source, String name) {

    public SourceName {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(name, "name");
    }

    /** {@code env OIDF_PDP_MODE}. */
    @Override
    public String toString() {
        return this.source.id() + " " + this.name;
    }
}
