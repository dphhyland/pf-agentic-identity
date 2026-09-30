/*
 * A servlet's or filter's init-params as a settings source.
 */
package com.pingidentity.ps.oidf.platform.pf.settings;

import java.util.function.Function;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletConfig;

/**
 * A servlet's or filter's init-params as the {@code init-param} source of {@code platform.settings}, so a
 * servlet reads its catalogued settings with the web.xml it was deployed with:
 *
 * <pre>{@code
 * Settings settings = Settings.of("federation-entity").with(InitParams.sources(config));
 * }</pre>
 *
 * <p>A null config has no init-params, as a servlet built by a test without a container has none.
 */
public final class InitParams {

    private InitParams() {
    }

    /** {@code config}'s init-params as a lookup; a null config finds nothing. */
    public static Function<String, String> of(ServletConfig config) {
        return config == null ? name -> null : config::getInitParameter;
    }

    /** {@code config}'s init-params as a lookup; a null config finds nothing. */
    public static Function<String, String> of(FilterConfig config) {
        return config == null ? name -> null : config::getInitParameter;
    }

    /** This process's environment and system properties, and {@code config}'s init-params. */
    public static Sources sources(ServletConfig config) {
        return Sources.process().withInitParams(of(config));
    }

    /** This process's environment and system properties, and {@code config}'s init-params. */
    public static Sources sources(FilterConfig config) {
        return Sources.process().withInitParams(of(config));
    }
}
