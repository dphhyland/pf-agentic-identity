/*
 * A superseded name for a setting.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.List;
import java.util.Objects;

/**
 * A superseded name a setting is still read under: used, with a warning, only when the current name is unset;
 * refused when both are set to different values.
 *
 * @param name    the old name as messages give it, for example {@code OIDF_TRUST_CONTROLLER_HOST}
 * @param sources where the old name is read, in precedence order
 */
public record Alias(String name, List<SourceName> sources) {

    public Alias {
        Objects.requireNonNull(name, "name");
        sources = List.copyOf(sources);
    }
}
