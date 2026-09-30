/*
 * The places a process reads settings from.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * The three places a setting is read from - the environment, the system properties, and a servlet's or
 * filter's init-params - as lookups, so a test supplies maps and a servlet supplies its config
 * ({@code platform.pf.settings.InitParams}). Sources built from the process or from maps can also list the
 * environment's names, which {@link ProfileAudit} needs to find the unknown ones; sources built from lookups list
 * none.
 */
public final class Sources {

    private static final Function<String, String> NONE = name -> null;

    private final Function<String, String> env;
    private final Function<String, String> systemProperties;
    private final Function<String, String> initParams;
    private final Supplier<Set<String>> environmentNames;

    private Sources(Function<String, String> env, Function<String, String> systemProperties, Function<String, String> initParams,
            Supplier<Set<String>> environmentNames) {
        this.env = env == null ? NONE : env;
        this.systemProperties = systemProperties == null ? NONE : systemProperties;
        this.initParams = initParams == null ? NONE : initParams;
        this.environmentNames = environmentNames == null ? Set::of : environmentNames;
    }

    /** This process: {@link System#getenv(String)} and {@link System#getProperty(String)}, and no init-params. */
    public static Sources process() {
        return new Sources(System::getenv, System::getProperty, null, () -> System.getenv().keySet());
    }

    /** Lookups a caller supplies; a null lookup finds nothing. The environment's names are not known. */
    public static Sources of(Function<String, String> env, Function<String, String> systemProperties,
            Function<String, String> initParams) {
        return new Sources(env, systemProperties, initParams, null);
    }

    /** An environment and system properties a caller holds as maps - an env file, a test - with no init-params. */
    public static Sources of(Map<String, String> env, Map<String, String> systemProperties) {
        Map<String, String> e = Map.copyOf(env);
        Map<String, String> p = Map.copyOf(systemProperties);
        return new Sources(e::get, p::get, null, e::keySet);
    }

    /** These sources with {@code initParams} as the init-params. */
    public Sources withInitParams(Function<String, String> initParams) {
        return new Sources(this.env, this.systemProperties, Objects.requireNonNull(initParams, "initParams"), this.environmentNames);
    }

    /** The names set in the environment, sorted; empty when these sources were built from lookups. */
    public Set<String> environmentNames() {
        return new TreeSet<>(this.environmentNames.get());
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
