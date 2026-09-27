/*
 * A secret setting's value.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.Objects;

/**
 * A secret setting's value, which {@link #toString} never shows: only {@link #reveal()} hands it out, so a
 * secret written into a log line or a message by mistake prints as {@code [secret]}.
 */
public final class Secret {

    private final String value;

    Secret(String value) {
        this.value = Objects.requireNonNull(value, "value");
    }

    /** The value itself. */
    public String reveal() {
        return this.value;
    }

    /** Always {@code [secret]}. */
    @Override
    public String toString() {
        return "[secret]";
    }
}
