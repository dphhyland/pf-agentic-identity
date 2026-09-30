package com.pingidentity.ps.oidf.warassembler;

import java.util.List;

/** Servlet url-pattern matching, as the Servlet specification's "Mapping Requests to Servlets" chapter has it. */
final class UrlPatterns {
    private UrlPatterns() {
    }

    /**
     * Whether {@code pattern} matches the request path {@code path}, for a filter mapping: an exact path, a
     * path prefix ({@code /as/*} matches {@code /as} and everything under it; {@code /*} everything), an
     * extension ({@code *.oauth2} matches a last segment ending {@code .oauth2}), or the empty string (the
     * context root). {@code /}, the default servlet's pattern, is not decided here: it matches only what no
     * other servlet mapping does, which {@link #servletFor} knows.
     */
    static boolean matches(String pattern, String path) {
        if (pattern.isEmpty()) {
            return "/".equals(path);
        }
        if (pattern.endsWith("/*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            return path.equals(prefix) || path.startsWith(prefix + "/");
        }
        if (pattern.startsWith("*.")) {
            String last = path.substring(path.lastIndexOf('/') + 1);
            return last.endsWith(pattern.substring(1));
        }
        return pattern.equals(path);
    }

    /**
     * The servlet mapping that serves {@code path}: an exact match first, then the longest matching path
     * prefix, then an extension match, then the default servlet ({@code /}); null when none does.
     */
    static WebXml.ServletMapping servletFor(List<WebXml.ServletMapping> mappings, String path) {
        WebXml.ServletMapping prefix = null;
        WebXml.ServletMapping extension = null;
        WebXml.ServletMapping fallback = null;
        for (WebXml.ServletMapping m : mappings) {
            String p = m.urlPattern();
            if (p.equals(path) || (p.isEmpty() && "/".equals(path))) {
                return m;
            }
            if (p.endsWith("/*")) {
                if (matches(p, path) && (prefix == null || p.length() > prefix.urlPattern().length())) {
                    prefix = m;
                }
            } else if (p.startsWith("*.")) {
                if (extension == null && matches(p, path)) {
                    extension = m;
                }
            } else if ("/".equals(p)) {
                fallback = m;
            }
        }
        return prefix != null ? prefix : extension != null ? extension : fallback;
    }
}
