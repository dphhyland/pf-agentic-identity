package com.pingidentity.ps.oidf.warassembler;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * What {@code filters.xml} declares: the filters to register over PingFederate's own endpoints, with their
 * url-patterns; the order pairs that must hold between their mappings; paths a filter may be mapped over
 * although the stock descriptor serves none of them; and the listeners to register. Parsed strictly - an
 * element or a value this does not know is refused, not skipped.
 */
final class Declaration {
    record Filter(String name, String className, List<String> urlPatterns) {
    }

    /** {@code earlier}'s mapping must come before {@code later}'s in document order, for {@code reason}. */
    record Order(String earlier, String later, String reason) {
    }

    record PathException(String path, String reason) {
    }

    private static final Pattern NAME = Pattern.compile("[A-Za-z][A-Za-z0-9._-]*");
    private static final Pattern CLASS_NAME =
            Pattern.compile("([A-Za-z_$][A-Za-z0-9_$]*\\.)*[A-Za-z_$][A-Za-z0-9_$]*");

    final List<Filter> filters;
    final List<Order> orders;
    final List<PathException> pathExceptions;
    final List<String> listeners;

    private Declaration(List<Filter> filters, List<Order> orders, List<PathException> pathExceptions,
                        List<String> listeners) {
        this.filters = List.copyOf(filters);
        this.orders = List.copyOf(orders);
        this.pathExceptions = List.copyOf(pathExceptions);
        this.listeners = List.copyOf(listeners);
    }

    Filter filter(String name) {
        for (Filter f : filters) {
            if (f.name().equals(name)) {
                return f;
            }
        }
        return null;
    }

    boolean isException(String path) {
        for (PathException e : pathExceptions) {
            if (e.path().equals(path)) {
                return true;
            }
        }
        return false;
    }

    static Declaration parse(byte[] bytes, String source) throws Refusal {
        Document doc = Xml.parse(bytes, source);
        Element root = doc.getDocumentElement();
        if (!"war-filters".equals(Xml.localName(root)) || root.getNamespaceURI() != null) {
            throw new Refusal("ERROR: " + source + " is not a filters declaration: its root element is <"
                    + root.getTagName() + ">, not <war-filters> in no namespace.");
        }
        if (!"1".equals(root.getAttribute("version"))) {
            throw new Refusal("ERROR: " + source + " declares version '" + root.getAttribute("version")
                    + "'; this assembler reads version 1.");
        }
        List<Filter> filters = new ArrayList<>();
        List<Element> orderElements = new ArrayList<>();
        List<PathException> exceptions = new ArrayList<>();
        Set<String> listeners = new LinkedHashSet<>();
        Set<String> names = new LinkedHashSet<>();
        for (Element e : Xml.children(root)) {
            switch (Xml.localName(e)) {
                case "filter" -> {
                    Filter f = filter(e, source);
                    if (!names.add(f.name())) {
                        throw new Refusal("ERROR: " + source + " declares the filter " + f.name() + " twice.");
                    }
                    filters.add(f);
                }
                case "order" -> orderElements.add(e);
                case "path-exception" -> {
                    String path = required(e, "path", source);
                    checkPattern(path, "path-exception", source);
                    exceptions.add(new PathException(path, required(e, "reason", source)));
                }
                case "listener" -> {
                    String cls = required(e, "class", source);
                    if (!CLASS_NAME.matcher(cls).matches()) {
                        throw new Refusal("ERROR: " + source + " declares a listener class '" + cls
                                + "' that is not a Java class name.");
                    }
                    if (!listeners.add(cls)) {
                        throw new Refusal("ERROR: " + source + " declares the listener " + cls + " twice.");
                    }
                }
                default -> throw new Refusal("ERROR: " + source + " has an element this assembler does not know: <"
                        + e.getTagName() + ">.");
            }
        }
        if (filters.isEmpty()) {
            throw new Refusal("ERROR: " + source + " declares no filter.");
        }
        List<Order> orders = new ArrayList<>();
        for (Element e : orderElements) {
            orders.add(order(e, names, source));
        }
        return new Declaration(filters, orders, exceptions, new ArrayList<>(listeners));
    }

    static Filter filter(Element e, String source) throws Refusal {
        String name = required(e, "name", source);
        if (!NAME.matcher(name).matches()) {
            throw new Refusal("ERROR: " + source + " declares a filter named '" + name
                    + "'; a name is a letter followed by letters, digits, '.', '_' or '-'.");
        }
        String cls = required(e, "class", source);
        if (!CLASS_NAME.matcher(cls).matches()) {
            throw new Refusal("ERROR: " + source + " declares " + name + " with class '" + cls
                    + "', which is not a Java class name.");
        }
        Set<String> patterns = new LinkedHashSet<>();
        for (Element child : Xml.children(e)) {
            if (!"url-pattern".equals(Xml.localName(child))) {
                throw new Refusal("ERROR: " + source + " declares " + name + " with a <" + child.getTagName()
                        + ">; a filter takes url-patterns only.");
            }
            String pattern = child.getTextContent().trim();
            checkPattern(pattern, name, source);
            if (!patterns.add(pattern)) {
                throw new Refusal("ERROR: " + source + " declares " + name + " over " + pattern + " twice.");
            }
        }
        if (patterns.isEmpty()) {
            throw new Refusal("ERROR: " + source + " declares " + name + " with no url-pattern.");
        }
        return new Filter(name, cls, new ArrayList<>(patterns));
    }

    static Order order(Element e, Set<String> names, String source) throws Refusal {
        String earlier = required(e, "filter", source);
        String later = required(e, "before", source);
        for (String n : List.of(earlier, later)) {
            if (!names.contains(n)) {
                throw new Refusal("ERROR: " + source + " orders " + earlier + " before " + later + ", but declares no filter "
                        + n + ".");
            }
        }
        if (earlier.equals(later)) {
            throw new Refusal("ERROR: " + source + " orders " + earlier + " before itself.");
        }
        String reason = e.getTextContent().replaceAll("\\s+", " ").trim();
        if (reason.isEmpty()) {
            throw new Refusal("ERROR: " + source + " orders " + earlier + " before " + later
                    + " without saying why; the reason is what a refusal prints.");
        }
        return new Order(earlier, later, reason);
    }

    /** A servlet url-pattern: an exact path, a path prefix ending in /*, or an extension *.ext. */
    static void checkPattern(String pattern, String owner, String source) throws Refusal {
        boolean ok = pattern.startsWith("/")
                ? pattern.indexOf('*') < 0 || (pattern.endsWith("/*") && pattern.indexOf('*') == pattern.length() - 1)
                : pattern.startsWith("*.") && pattern.length() > 2 && pattern.indexOf('/') < 0
                        && pattern.lastIndexOf('*') == 0;
        if (!ok || pattern.chars().anyMatch(Character::isWhitespace)) {
            throw new Refusal("ERROR: " + source + " gives " + owner + " the url-pattern '" + pattern
                    + "', which is not an exact path, a /prefix/* or a *.extension.");
        }
    }

    static String required(Element e, String attribute, String source) throws Refusal {
        String value = e.getAttribute(attribute).trim();
        if (value.isEmpty()) {
            throw new Refusal("ERROR: " + source + " has a <" + e.getTagName() + "> with no " + attribute + ".");
        }
        return value;
    }
}
