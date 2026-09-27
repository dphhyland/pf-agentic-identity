package com.pingidentity.ps.oidf.warassembler;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * Merges a {@link Declaration} into a stock descriptor, and checks a descriptor against one.
 *
 * <p>The DOM decides; the text is edited only at one place. Every check reads the parsed descriptor, but the
 * merged file is the stock file's own bytes with the new elements inserted before the root's end tag, so
 * PingFederate's descriptor is not re-serialised - its layout, comments and attribute order stay as they
 * were, and the result can be compared byte for byte with what the shell assembler wrote. What is inserted is
 * checked afterwards by parsing the result again ({@link #verify}), never assumed.
 */
final class Merge {
    record Result(byte[] bytes, List<String> notes) {
    }

    private Merge() {
    }

    /**
     * The stock descriptor with every declared filter and listener it lacks added. Refuses a descriptor that
     * is metadata-complete, that serves none of a declared path, or that already registers a declared name
     * other than exactly as declared. A descriptor that already has everything is returned unchanged, byte
     * for byte - which is what makes running the assembler on its own output a no-op.
     */
    static Result merge(byte[] original, WebXml stock, Declaration declaration, String what) throws Refusal {
        if (stock.metadataComplete()) {
            throw new Refusal("ERROR: " + what + " says metadata-complete=\"" + stock.root.getAttribute("metadata-complete")
                    + "\". The container would then scan no annotation, and the modules' @WebServlet servlets - the"
                    + " federation, SSF and attestation endpoints - would never be mapped. Assemble from a stock war"
                    + " whose descriptor leaves annotation scanning on.");
        }
        List<String> unserved = unservedPaths(stock, declaration);
        if (!unserved.isEmpty()) {
            throw new Refusal("ERROR: filters.xml maps filters over paths no <servlet-mapping> in " + what + " serves: "
                    + String.join("; ", unserved) + ". A filter there would run for nothing, and usually means the"
                    + " endpoint moved in this PingFederate. Correct the path, or declare a <path-exception> with the"
                    + " reason it is right.");
        }
        List<String> notes = new ArrayList<>();
        List<String> byPattern = patternServedPaths(stock, declaration);
        if (!byPattern.isEmpty()) {
            notes.add("web.xml: served only by a wildcard <servlet-mapping>, so " + what + " vouches for the pattern and"
                    + " not the endpoint name - a misspelt or moved endpoint under it is not caught here: "
                    + String.join("; ", byPattern));
        }
        List<Declaration.Filter> filters = new ArrayList<>();
        for (Declaration.Filter f : declaration.filters) {
            if (existing(stock, f, what)) {
                notes.add("web.xml: " + f.name() + " already registered as declared - leaving as is");
            } else {
                filters.add(f);
                notes.add("web.xml: registered " + f.name() + " over " + String.join(", ", f.urlPatterns()));
            }
        }
        List<String> listeners = new ArrayList<>();
        for (String l : declaration.listeners) {
            long count = stock.listenerCount(l);
            if (count > 1) {
                throw new Refusal("ERROR: " + what + " registers the listener " + l + " " + count
                        + " times; filters.xml declares it once.");
            }
            if (count == 0) {
                listeners.add(l);
                notes.add("web.xml: registered the listener " + l);
            } else {
                notes.add("web.xml: the listener " + l + " already registered - leaving as is");
            }
        }
        byte[] merged = filters.isEmpty() && listeners.isEmpty()
                ? original
                : splice(original, stock, filters, listeners, what);
        return new Result(merged, notes);
    }

    /**
     * Whether the descriptor already registers {@code f} exactly as declared (true), or not at all (false).
     * Anything in between is refused: the assembler neither keeps a registration it would not have written
     * nor adds a second one beside it.
     */
    static boolean existing(WebXml stock, Declaration.Filter f, String what) throws Refusal {
        if (stock.filtersNamed(f.name()).isEmpty() && stock.mappingsNamed(f.name()).isEmpty()) {
            return false;
        }
        String problem = mappingProblem(stock, f);
        if (problem != null) {
            throw new Refusal("ERROR: " + what + " already registers " + f.name() + ", but not as filters.xml declares it: "
                    + problem + ".");
        }
        return true;
    }

    /** "X over /p" for each declared path the stock descriptor does not serve and no exception covers. */
    static List<String> unservedPaths(WebXml stock, Declaration declaration) {
        List<String> out = new ArrayList<>();
        for (Declaration.Filter f : declaration.filters) {
            for (String p : f.urlPatterns()) {
                if (declaration.isException(p)) {
                    continue;
                }
                boolean served;
                if (p.indexOf('*') < 0) {
                    WebXml.ServletMapping m = UrlPatterns.servletFor(stock.servletMappings, p);
                    // The default servlet serves every path, so it cannot vouch for one.
                    served = m != null && !"/".equals(m.urlPattern());
                } else {
                    served = stock.servletMappings.stream().anyMatch(m -> m.urlPattern().equals(p));
                }
                if (!served) {
                    out.add(f.name() + " over " + p);
                }
            }
        }
        return out;
    }

    /**
     * "/p (servlet via pattern)" for each declared exact path the stock descriptor serves only through a path
     * prefix or an extension mapping. PingFederate 13.1.3 maps its protocol endpoints by extension ({@code
     * *.oauth2}, {@code *.openid}, {@code *.ciba}), so for every path filters.xml declares today the stock
     * descriptor can say that the extension is PingFederate's, and nothing about the name before it. The
     * assembler says so rather than let "served" read as more than it is (U-0186).
     */
    static List<String> patternServedPaths(WebXml stock, Declaration declaration) {
        List<String> out = new ArrayList<>();
        for (Declaration.Filter f : declaration.filters) {
            for (String p : f.urlPatterns()) {
                WebXml.ServletMapping m = p.indexOf('*') < 0 && !declaration.isException(p)
                        ? UrlPatterns.servletFor(stock.servletMappings, p) : null;
                String line = m == null ? null : p + " (" + m.servletName() + " via " + m.urlPattern() + ")";
                if (m != null && m.urlPattern().indexOf('*') >= 0 && !out.contains(line)) {
                    out.add(line);
                }
            }
        }
        return out;
    }

    /** The stock bytes with the new elements inserted before the root's end tag, in the stock file's encoding. */
    static byte[] splice(byte[] original, WebXml stock, List<Declaration.Filter> filters, List<String> listeners,
                         String what) throws Refusal {
        // The declaration's encoding; with none, what the parser detected (a byte order mark), else UTF-8.
        Charset charset = Charset.forName(Objects.requireNonNullElse(stock.document.getXmlEncoding(),
                Objects.requireNonNullElse(stock.document.getInputEncoding(), "UTF-8")));
        String text = new String(original, charset);
        int end = text.lastIndexOf("</" + stock.root.getTagName());
        if (end < 0) {
            throw new Refusal("ERROR: " + what + " has no </" + stock.root.getTagName() + "> to insert before.");
        }
        String nl = text.contains("\r\n") ? "\r\n" : "\n";
        StringBuilder block = new StringBuilder();
        for (Declaration.Filter f : filters) {
            block.append("  <filter>").append(nl)
                    .append("    <filter-name>").append(escape(f.name())).append("</filter-name>").append(nl)
                    .append("    <filter-class>").append(escape(f.className())).append("</filter-class>").append(nl)
                    .append("  </filter>").append(nl)
                    .append("  <filter-mapping>").append(nl)
                    .append("    <filter-name>").append(escape(f.name())).append("</filter-name>").append(nl);
            for (String p : f.urlPatterns()) {
                block.append("    <url-pattern>").append(escape(p)).append("</url-pattern>").append(nl);
            }
            block.append("  </filter-mapping>").append(nl);
        }
        for (String l : listeners) {
            block.append("  <listener>").append(nl)
                    .append("    <listener-class>").append(escape(l)).append("</listener-class>").append(nl)
                    .append("  </listener>").append(nl);
        }
        int lineStart = text.lastIndexOf('\n', end - 1) + 1;
        int at;
        if (text.substring(lineStart, end).isBlank()) {
            at = lineStart;
        } else {
            at = end;
            block.insert(0, nl);
        }
        return (text.substring(0, at) + block + text.substring(at)).getBytes(charset);
    }

    /**
     * Refuses unless {@code merged} registers every declared filter exactly once, as declared, every order
     * pair holds in document order, every declared listener is registered once, and annotation scanning is on.
     */
    static void verify(WebXml merged, Declaration declaration, String what) throws Refusal {
        if (merged.metadataComplete()) {
            throw new Refusal("ERROR: " + what + " is metadata-complete; the modules' @WebServlet servlets would never be mapped.");
        }
        for (Declaration.Filter f : declaration.filters) {
            String problem = mappingProblem(merged, f);
            if (problem != null) {
                throw new Refusal("ERROR: " + what + ": " + problem + ".");
            }
        }
        for (Declaration.Order o : declaration.orders) {
            int earlier = merged.mappingsNamed(o.earlier()).get(0).index();
            int later = merged.mappingsNamed(o.later()).get(0).index();
            if (earlier >= later) {
                throw new Refusal("ERROR: filter order wrong in " + what + " - " + o.earlier() + " (filter-mapping "
                        + (earlier + 1) + ") must be mapped before " + o.later() + " (filter-mapping " + (later + 1)
                        + "): " + o.reason());
            }
        }
        for (String l : declaration.listeners) {
            long count = merged.listenerCount(l);
            if (count != 1) {
                throw new Refusal("ERROR: " + what + " registers the listener " + l + " " + count
                        + " times; filters.xml declares it, so it must be registered exactly once.");
            }
        }
    }

    /** What is wrong with the descriptor's registration of {@code f}, or null when it is exactly as declared. */
    static String mappingProblem(WebXml w, Declaration.Filter f) {
        List<WebXml.FilterDef> defs = w.filtersNamed(f.name());
        List<WebXml.FilterMapping> maps = w.mappingsNamed(f.name());
        if (defs.size() != 1) {
            return "it has " + defs.size() + " <filter> elements named " + f.name() + ", and must have exactly one";
        }
        if (maps.size() != 1) {
            return "it has " + maps.size() + " <filter-mapping> elements for " + f.name() + ", and must have exactly one";
        }
        if (!f.className().equals(defs.get(0).className())) {
            return f.name() + " is the class " + defs.get(0).className() + ", and filters.xml declares " + f.className();
        }
        WebXml.FilterMapping m = maps.get(0);
        if (!m.servletNames().isEmpty() || !m.dispatchers().isEmpty()) {
            return f.name() + "'s mapping names servlets " + m.servletNames() + " or dispatchers " + m.dispatchers()
                    + ", and filters.xml declares url-patterns only";
        }
        if (m.urlPatterns().size() != f.urlPatterns().size()
                || !new HashSet<>(m.urlPatterns()).equals(new HashSet<>(f.urlPatterns()))) {
            return f.name() + " is mapped over " + m.urlPatterns() + ", and filters.xml declares exactly "
                    + f.urlPatterns();
        }
        return null;
    }

    static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
