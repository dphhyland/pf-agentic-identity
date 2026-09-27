/*
 * The places a process reads settings from.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.Objects;
import java.util.function.Function;

/**
 * The three places a setting is read from - the environment, the system properties, and a servlet's or
 * filter's init-params - as lookups, so a test supplies maps and a servlet supplies its config
 * ({@code platform.pf.settings.InitParams}).
 */
public final class Sources {

    private static final Function<String, String> NONE = name -> null;

    private final Function<String, String> env;
    private final Function<String, String> systemProperties;
    private final Function<String, String> initParams;

    private Sources(Function<String, String> env, Function<String, String> systemProperties, Function<String, String> initParams) {
        this.env = env == null ? NONE : env;
        this.systemProperties = systemProperties == null ? NONE : systemProperties;
        this.initParams = initParams == null ? NONE : initParams;
    }

    /** This process: {@link System#getenv(String)} and {@link System#getProperty(String)}, and no init-params. */
    public static Sources process() {
        return new Sources(System::getenv, System::getProperty, null);
    }

    /** Lookups a caller supplies; a null lookup finds nothing. */
    public static Sources of(Function<String, String> env, Function<String, String> systemProperties,
            Function<String, String> initParams) {
        return new Sources(env, systemProperties, initParams);
    }

    /** These sources with {@code initParams} as the init-params. */
    public Sources withInitParams(Function<String, String> initParams) {
        return new Sources(this.env, this.systemProperties, Objects.requireNonNull(initParams, "initParams"));
    }

    /** The value {@code name} has in {@code source}, or null; blank is returned as it is. */
    String get(Source source, String name) {
        switch (source) {
            case ENV:
                return this.env.apply(name);
            case SYSTEM_PROPERTY:
                return this.systemProperties.apply(name);
            case INIT_PARAM:
                return this.initParams.apply(name);
            default:
                throw new IllegalArgumentException("nothing is read from " + source.id());
        }
    }
}
