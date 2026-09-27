/*
 * This loader's component registry, as a static entry point.
 */
package com.pingidentity.ps.oidf.platform.component;

import java.util.List;
import java.util.Optional;

/**
 * The {@link ComponentRegistry} of the loader this copy of platform was loaded by. Statics are per loader, so
 * the webapp's copy and the engine's each hold their own components; health reads the webapp's
 * (docs/development/classloaders.md).
 */
public final class Components {
    private static final ComponentRegistry REGISTRY = new ComponentRegistry();

    private Components() {
    }

    /** See {@link ComponentRegistry#register(String, boolean)}. */
    public static ComponentRegistry.Component register(String name, boolean enabled) {
        return REGISTRY.register(name, enabled);
    }

    public static Optional<ComponentStatus> status(String name) {
        return REGISTRY.status(name);
    }

    public static List<ComponentStatus> snapshot() {
        return REGISTRY.snapshot();
    }

    public static ComponentRegistry registry() {
        return REGISTRY;
    }
}
