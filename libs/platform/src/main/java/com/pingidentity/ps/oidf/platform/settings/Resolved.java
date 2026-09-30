/*
 * A setting's value and where it came from.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.List;
import java.util.Objects;

/**
 * A setting's value, typed as its entry says, and where it came from.
 *
 * @param setting    the entry
 * @param value      the value: {@link Boolean}, {@link Integer}, {@link Long}, {@link java.time.Duration},
 *                   {@link String}, {@link java.net.URI}, {@link java.util.Map}, {@link java.util.Set},
 *                   {@link java.nio.file.Path} or {@link Secret}; null when unset with no default
 * @param provenance which source and which name supplied it
 * @param warnings   what resolving it warned about (a superseded name in use), every time it is resolved;
 *                   {@link Settings} logs each one once
 */
public record Resolved(Setting setting, Object value, Provenance provenance, List<String> warnings) {

    public Resolved {
        Objects.requireNonNull(setting, "setting");
        Objects.requireNonNull(provenance, "provenance");
        warnings = List.copyOf(warnings);
    }
}
