package com.pingidentity.ps.oidf.warassembler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/** The JDK's DOM, configured so a document can name nothing outside itself. */
final class Xml {
    private Xml() {
    }

    /**
     * Parses {@code bytes} namespace-aware. A DOCTYPE is refused outright - no descriptor this reads has one
     * (a web.xml has used a schema since Servlet 2.4) - which also rules out external entities and
     * entity expansion.
     */
    static Document parse(byte[] bytes, String what) throws Refusal {
        try {
            return builder().parse(new ByteArrayInputStream(bytes));
        } catch (SAXException | IOException e) {
            throw new Refusal("ERROR: " + what + " is not well-formed XML this assembler accepts: " + e.getMessage());
        }
    }

    private static DocumentBuilder builder() {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setErrorHandler(THROWING);
            return builder;
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("the JDK's own DOM parser does not take its own features", e);
        }
    }

    /**
     * The child elements of {@code parent} with this local name, in the parent's own namespace, in document
     * order. An element of the same name in another namespace is not the container's, so it is not counted.
     */
    static List<Element> children(Element parent, String localName) {
        List<Element> out = new ArrayList<>();
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element && localName.equals(localName(n))
                    && Objects.equals(n.getNamespaceURI(), parent.getNamespaceURI())) {
                out.add((Element) n);
            }
        }
        return out;
    }

    /** Every child element of {@code parent}, in document order. */
    static List<Element> children(Element parent) {
        List<Element> out = new ArrayList<>();
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element) {
                out.add((Element) n);
            }
        }
        return out;
    }

    /** The trimmed text of each child element with this local name. */
    static List<String> texts(Element parent, String localName) {
        List<String> out = new ArrayList<>();
        for (Element e : children(parent, localName)) {
            out.add(e.getTextContent().trim());
        }
        return out;
    }

    /** The trimmed text of the first child element with this local name, or null. */
    static String text(Element parent, String localName) {
        List<String> all = texts(parent, localName);
        return all.isEmpty() ? null : all.get(0);
    }

    static String localName(Node n) {
        return n.getLocalName() != null ? n.getLocalName() : n.getNodeName();
    }

    private static final ErrorHandler THROWING = new ErrorHandler() {
        @Override
        public void warning(SAXParseException e) {
            // A warning does not make a document unusable.
        }

        @Override
        public void error(SAXParseException e) throws SAXException {
            throw e;
        }

        @Override
        public void fatalError(SAXParseException e) throws SAXException {
            throw e;
        }
    };
}
