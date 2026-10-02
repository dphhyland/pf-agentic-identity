/*
 * A setting's value and where it came from.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.List;
import java.util.Objects;

/**
 * A setting's value, typed as its entry says, and where it came from.
 *
 * @param setting        the entry
 * @param value          the value: {@link Boolean}, {@link Integer}, {@link Long}, {@link java.time.Duration},
 *                       {@link String}, {@link java.net.URI}, {@link java.util.Map}, {@link java.util.Set},
 *                       {@link java.nio.file.Path} or {@link Secret}; null when unset with no default
 * @param provenance     which source and which name supplied it
 * @param warnings       what resolving it warned about (a superseded name in use, a legacy spelling), every time it is
 *                       resolved; {@link Settings} logs each one once
 * @param legacySpelling the value as it was set, when only a legacy spelling made it readable (development only,
 *                       until 1.0: Phase 3 plan, decision 11); null when it parsed strictly
 */
public record Resolved(Setting setting, Object value, Provenance provenance, List<String> warnings, String legacySpelling) {

    public Resolved {
        Objects.requireNonNull(setting, "setting");
        Objects.requireNonNull(provenance, "provenance");
        warnings = List.copyOf(warnings);
    }

    /** A value that parsed strictly. */
    public Resolved(Setting setting, Object value, Provenance provenance, List<String> warnings) {
        this(setting, value, provenance, warnings, null);
    }

    /** Whether the value was read from a legacy spelling ({@link #legacySpelling()}). */
    public boolean legacy() {
        return this.legacySpelling != null;
    }
}
