package com.pingidentity.ps.oidf.warassembler;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The filter chain a request to a path meets, as the descriptor says: the filter mappings whose url-patterns
 * match it, in document order, then those that name the servlet serving it, in document order (the Servlet
 * specification's order). Only REQUEST dispatch is shown, and only what web.xml declares: a filter a jar
 * registers by annotation or a container adds itself is not in it.
 */
final class Chains {
    private Chains() {
    }

    /** One line per path: the path, the servlet that serves it and the filters in the order they run. */
    static List<String> describe(WebXml descriptor, Declaration declaration) {
        Set<String> paths = new LinkedHashSet<>();
        for (Declaration.Filter f : declaration.filters) {
            paths.addAll(f.urlPatterns());
        }
        List<String> lines = new ArrayList<>();
        for (String path : paths) {
            WebXml.ServletMapping served = UrlPatterns.servletFor(descriptor.servletMappings, path);
            String servlet = served == null ? "no servlet" : served.servletName();
            lines.add("chain " + path + " (" + servlet + "): " + String.join(" > ", chain(descriptor, path)));
        }
        return lines;
    }

    static List<String> chain(WebXml descriptor, String path) {
        WebXml.ServletMapping served = UrlPatterns.servletFor(descriptor.servletMappings, path);
        boolean defaultServlet = served != null && "/".equals(served.urlPattern());
        List<String> byPath = new ArrayList<>();
        List<String> byServlet = new ArrayList<>();
        for (WebXml.FilterMapping m : descriptor.filterMappings) {
            if (!m.dispatchers().isEmpty() && !m.dispatchers().contains("REQUEST")) {
                continue;
            }
            boolean pathMatch = false;
            for (String p : m.urlPatterns()) {
                pathMatch |= "/".equals(p) ? defaultServlet : UrlPatterns.matches(p, path);
            }
            if (pathMatch) {
                byPath.add(m.name());
            } else if (served != null
                    && (m.servletNames().contains(served.servletName()) || m.servletNames().contains("*"))) {
                byServlet.add(m.name());
            }
        }
        byPath.addAll(byServlet);
        return byPath;
    }
}
