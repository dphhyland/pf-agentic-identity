package com.pingidentity.ps.oidf.warassembler;

import java.util.ArrayList;
import java.util.List;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** A deployment descriptor, read: the parts of it the assembler decides on. */
final class WebXml {
    static final String JAKARTA_EE = "https://jakarta.ee/xml/ns/jakartaee";
    static final String JAVA_EE_JCP = "http://xmlns.jcp.org/xml/ns/javaee";
    static final String JAVA_EE_SUN = "http://java.sun.com/xml/ns/javaee";

    record FilterDef(String name, String className) {
    }

    /** One {@code <filter-mapping>}, with its position among all of them in document order. */
    record FilterMapping(int index, String name, List<String> urlPatterns, List<String> servletNames,
                         List<String> dispatchers) {
    }

    record ServletMapping(String servletName, String urlPattern) {
    }

    final Document document;
    final Element root;
    final List<FilterDef> filters = new ArrayList<>();
    final List<FilterMapping> filterMappings = new ArrayList<>();
    final List<ServletMapping> servletMappings = new ArrayList<>();
    final List<String> listeners = new ArrayList<>();

    private WebXml(Document document) {
        this.document = document;
        this.root = document.getDocumentElement();
        for (Element e : Xml.children(root, "filter")) {
            filters.add(new FilterDef(Xml.text(e, "filter-name"), Xml.text(e, "filter-class")));
        }
        for (Element e : Xml.children(root, "filter-mapping")) {
            filterMappings.add(new FilterMapping(filterMappings.size(), Xml.text(e, "filter-name"),
                    Xml.texts(e, "url-pattern"), Xml.texts(e, "servlet-name"), Xml.texts(e, "dispatcher")));
        }
        for (Element e : Xml.children(root, "servlet-mapping")) {
            String servlet = Xml.text(e, "servlet-name");
            for (String pattern : Xml.texts(e, "url-pattern")) {
                servletMappings.add(new ServletMapping(servlet, pattern));
            }
        }
        for (Element e : Xml.children(root, "listener")) {
            listeners.add(Xml.text(e, "listener-class"));
        }
    }

    static WebXml parse(byte[] bytes, String what) throws Refusal {
        Document doc = Xml.parse(bytes, what);
        if (!"web-app".equals(Xml.localName(doc.getDocumentElement()))) {
            throw new Refusal("ERROR: " + what + " is not a deployment descriptor: its root element is <"
                    + doc.getDocumentElement().getTagName() + ">, not <web-app>.");
        }
        if (doc.getDocumentElement().getPrefix() != null) {
            throw new Refusal("ERROR: " + what + " has a prefixed root element <" + doc.getDocumentElement().getTagName()
                    + ">. The assembler inserts unprefixed elements, which would fall outside its namespace and be"
                    + " ignored by the container; write the descriptor with a default namespace.");
        }
        return new WebXml(doc);
    }

    /**
     * The servlet namespace the descriptor's own namespace says the container speaks: {@code jakarta} for
     * Jakarta EE (PingFederate 13.1.x, jakartaee 5.0), {@code javax} for Java EE (13.0.x, javaee 3.1).
     */
    String namespace(String what) throws Refusal {
        String ns = root.getNamespaceURI();
        if (JAKARTA_EE.equals(ns)) {
            return "jakarta";
        }
        if (JAVA_EE_JCP.equals(ns) || JAVA_EE_SUN.equals(ns)) {
            return "javax";
        }
        throw new Refusal("ERROR: " + what + " is in the namespace '" + ns + "', which is neither Jakarta EE's nor"
                + " Java EE's, so it does not say which servlet namespace this PingFederate speaks.");
    }

    /**
     * Whether the root says metadata-complete is true - the container then scans no annotation. The schema
     * type is xsd:boolean, so "1" counts as well as "true", whatever a given container makes of it.
     */
    boolean metadataComplete() {
        String value = root.getAttribute("metadata-complete").trim();
        return "true".equals(value) || "1".equals(value);
    }

    List<FilterDef> filtersNamed(String name) {
        List<FilterDef> out = new ArrayList<>();
        for (FilterDef f : filters) {
            if (name.equals(f.name())) {
                out.add(f);
            }
        }
        return out;
    }

    List<FilterMapping> mappingsNamed(String name) {
        List<FilterMapping> out = new ArrayList<>();
        for (FilterMapping m : filterMappings) {
            if (name.equals(m.name())) {
                out.add(m);
            }
        }
        return out;
    }

    long listenerCount(String className) {
        return listeners.stream().filter(className::equals).count();
    }
}
