package com.pingidentity.ps.oidf.warassembler;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The descriptor decisions, on small descriptors written here. */
class MergeTest {
    private static final String NS = "xmlns=\"" + WebXml.JAKARTA_EE + "\"";
    private static final String SERVLETS = "<servlet-mapping><servlet-name>p</servlet-name><url-pattern>*.oauth2</url-pattern></servlet-mapping>"
            + "<servlet-mapping><servlet-name>s</servlet-name><url-pattern>/static/*</url-pattern></servlet-mapping>"
            + "<servlet-mapping><servlet-name>d</servlet-name><url-pattern>/</url-pattern></servlet-mapping>";

    private static Declaration declaration(String body) throws Refusal {
        return Declaration.parse(("<war-filters version=\"1\">" + body + "</war-filters>").getBytes(StandardCharsets.UTF_8), "f.xml");
    }

    private static final String TOKEN = "<filter name=\"T\" class=\"x.T\"><url-pattern>/as/token.oauth2</url-pattern></filter>";
    private static final String PAR = "<filter name=\"P\" class=\"x.P\"><url-pattern>/as/par.oauth2</url-pattern></filter>";

    private static WebXml web(String body) throws Refusal {
        return WebXml.parse(bytes("<web-app " + NS + ">" + body + "</web-app>"), "w.xml");
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String merged(String xml, Declaration d) throws Refusal {
        byte[] b = bytes(xml);
        return new String(Merge.merge(b, WebXml.parse(b, "w.xml"), d, "w.xml").bytes(), StandardCharsets.UTF_8);
    }

    @Test
    void anEndTagMidLineGetsTheBlockOnItsOwnLines() throws Refusal {
        String out = merged("<web-app " + NS + ">" + SERVLETS + "</web-app>", declaration(TOKEN));
        assertTrue(out.endsWith("</servlet-mapping>\n  <filter>\n    <filter-name>T</filter-name>\n"
                + "    <filter-class>x.T</filter-class>\n  </filter>\n  <filter-mapping>\n    <filter-name>T</filter-name>\n"
                + "    <url-pattern>/as/token.oauth2</url-pattern>\n  </filter-mapping>\n</web-app>"), out);
    }

    @Test
    void crlfDescriptorsGetCrlfLines() throws Refusal {
        String out = merged("<web-app " + NS + ">\r\n" + SERVLETS + "\r\n</web-app>\r\n", declaration(TOKEN));
        assertTrue(out.contains("\r\n  <filter>\r\n    <filter-name>T</filter-name>\r\n"), out);
        assertTrue(out.endsWith("  </filter-mapping>\r\n</web-app>\r\n"), out);
    }

    @Test
    void anotherEncodingIsKept() throws Refusal {
        String xml = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<web-app " + NS + "><!-- café -->" + SERVLETS + "\n</web-app>\n";
        byte[] in = xml.getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = Merge.merge(in, WebXml.parse(in, "w.xml"), declaration(TOKEN), "w.xml").bytes();
        assertTrue(new String(out, StandardCharsets.ISO_8859_1).contains("<!-- café -->"));
    }

    @Test
    void aDescriptorWithEverythingIsReturnedAsItWas() throws Refusal {
        String xml = "<web-app " + NS + ">" + SERVLETS + "<filter><filter-name>T</filter-name><filter-class>x.T</filter-class></filter>"
                + "<filter-mapping><filter-name>T</filter-name><url-pattern>/as/token.oauth2</url-pattern></filter-mapping>"
                + "<listener><listener-class>x.L</listener-class></listener></web-app>";
        byte[] in = bytes(xml);
        Merge.Result r = Merge.merge(in, WebXml.parse(in, "w.xml"), declaration(TOKEN + "<listener class=\"x.L\"/>"), "w.xml");
        assertArrayEquals(in, r.bytes());
        assertEquals(List.of("web.xml: T already registered as declared - leaving as is",
                "web.xml: the listener x.L already registered - leaving as is"), r.notes());
    }

    @Test
    void aListenerAloneIsStillSplicedIn() throws Refusal {
        String xml = "<web-app " + NS + ">" + SERVLETS + "<filter><filter-name>T</filter-name><filter-class>x.T</filter-class></filter>"
                + "<filter-mapping><filter-name>T</filter-name><url-pattern>/as/token.oauth2</url-pattern></filter-mapping>\n</web-app>";
        String out = merged(xml, declaration(TOKEN + "<listener class=\"x.L\"/>"));
        assertTrue(out.endsWith("</filter-mapping>\n  <listener>\n    <listener-class>x.L</listener-class>\n  </listener>\n</web-app>"), out);
    }

    @Test
    void noEndTagToInsertBefore() throws Refusal {
        WebXml w = web(SERVLETS);
        Refusal r = assertThrows(Refusal.class, () -> Merge.splice(bytes("<web-app/>"), w, declaration(TOKEN).filters, List.of(), "w.xml"));
        assertEquals("ERROR: w.xml has no </web-app> to insert before.", r.getMessage());
    }

    @Test
    void aRegistrationThatIsNotExactlyTheDeclaredOneIsRefused() throws Refusal {
        Declaration.Filter t = declaration(TOKEN).filters.get(0);
        String def = "<filter><filter-name>T</filter-name><filter-class>x.T</filter-class></filter>";
        String map = "<filter-mapping><filter-name>T</filter-name><url-pattern>/as/token.oauth2</url-pattern></filter-mapping>";
        assertEquals("it has 2 <filter> elements named T, and must have exactly one",
                Merge.mappingProblem(web(def + def + map), t));
        assertEquals("it has 0 <filter-mapping> elements for T, and must have exactly one", Merge.mappingProblem(web(def), t));
        assertEquals("T is the class x.Other, and filters.xml declares x.T", Merge.mappingProblem(web(
                "<filter><filter-name>T</filter-name><filter-class>x.Other</filter-class></filter>" + map), t));
        assertEquals("T's mapping names servlets [p] or dispatchers [], and filters.xml declares url-patterns only",
                Merge.mappingProblem(web(def + "<filter-mapping><filter-name>T</filter-name><url-pattern>/as/token.oauth2</url-pattern>"
                        + "<servlet-name>p</servlet-name></filter-mapping>"), t));
        assertEquals("T's mapping names servlets [] or dispatchers [FORWARD], and filters.xml declares url-patterns only",
                Merge.mappingProblem(web(def + "<filter-mapping><filter-name>T</filter-name><url-pattern>/as/token.oauth2</url-pattern>"
                        + "<dispatcher>FORWARD</dispatcher></filter-mapping>"), t));
        assertEquals("T is mapped over [/as/token.oauth2, /as/token.oauth2], and filters.xml declares exactly [/as/token.oauth2]",
                Merge.mappingProblem(web(def + "<filter-mapping><filter-name>T</filter-name><url-pattern>/as/token.oauth2</url-pattern>"
                        + "<url-pattern>/as/token.oauth2</url-pattern></filter-mapping>"), t));
        assertEquals("T is mapped over [/as/par.oauth2], and filters.xml declares exactly [/as/token.oauth2]",
                Merge.mappingProblem(web(def + "<filter-mapping><filter-name>T</filter-name><url-pattern>/as/par.oauth2</url-pattern>"
                        + "</filter-mapping>"), t));
        assertNull(Merge.mappingProblem(web(def + map), t));

        Refusal r = assertThrows(Refusal.class, () -> Merge.existing(web(SERVLETS + def), t, "w.xml"));
        assertEquals("ERROR: w.xml already registers T, but not as filters.xml declares it: it has 0 <filter-mapping>"
                + " elements for T, and must have exactly one.", r.getMessage());
        assertTrue(Merge.existing(web(def + map), t, "w.xml"));
        assertFalse(Merge.existing(web(SERVLETS), t, "w.xml"));
        assertThrows(Refusal.class, () -> Merge.existing(web(map), t, "w.xml"), "a mapping with no filter is refused too");
    }

    @Test
    void pathsTheDefaultServletAloneServesAreNotServed() throws Refusal {
        Declaration d = declaration("<filter name=\"X\" class=\"x.X\"><url-pattern>/nowhere</url-pattern><url-pattern>/static/a</url-pattern>"
                + "<url-pattern>/static/*</url-pattern><url-pattern>/other/*</url-pattern><url-pattern>*.oauth2</url-pattern></filter>");
        assertEquals(List.of("X over /nowhere", "X over /other/*"), Merge.unservedPaths(web(SERVLETS), d));
        assertEquals(List.of("X over /nowhere", "X over /static/a", "X over /static/*", "X over /other/*", "X over *.oauth2"),
                Merge.unservedPaths(web(""), d));
    }

    @Test
    void aPathExceptionLetsAnUnservedPathThrough() throws Refusal {
        Declaration d = declaration("<filter name=\"X\" class=\"x.X\"><url-pattern>/federation/fetch</url-pattern></filter>"
                + "<path-exception path=\"/federation/fetch\" reason=\"an @WebServlet in the modules serves it\"/>");
        assertEquals(List.of(), Merge.unservedPaths(web(SERVLETS.replace("<servlet-mapping><servlet-name>d</servlet-name>"
                + "<url-pattern>/</url-pattern></servlet-mapping>", "")), d));
    }

    @Test
    void verifyRefusesWhatMergeWouldNeverWriteButAStockWarMightHold() throws Refusal {
        Declaration d = declaration(TOKEN + PAR + "<order filter=\"T\" before=\"P\">T first</order><listener class=\"x.L\"/>");
        String def = "<filter><filter-name>T</filter-name><filter-class>x.T</filter-class></filter>"
                + "<filter><filter-name>P</filter-name><filter-class>x.P</filter-class></filter>";
        String t = "<filter-mapping><filter-name>T</filter-name><url-pattern>/as/token.oauth2</url-pattern></filter-mapping>";
        String p = "<filter-mapping><filter-name>P</filter-name><url-pattern>/as/par.oauth2</url-pattern></filter-mapping>";
        String l = "<listener><listener-class>x.L</listener-class></listener>";
        Merge.verify(web(def + t + p + l), d, "w.xml");
        assertEquals("ERROR: filter order wrong in w.xml - T (filter-mapping 2) must be mapped before P (filter-mapping 1): T first",
                assertThrows(Refusal.class, () -> Merge.verify(web(def + p + t + l), d, "w.xml")).getMessage());
        assertEquals("ERROR: w.xml registers the listener x.L 0 times; filters.xml declares it, so it must be registered exactly once.",
                assertThrows(Refusal.class, () -> Merge.verify(web(def + t + p), d, "w.xml")).getMessage());
        assertEquals("ERROR: w.xml registers the listener x.L 2 times; filters.xml declares it, so it must be registered exactly once.",
                assertThrows(Refusal.class, () -> Merge.verify(web(def + t + p + l + l), d, "w.xml")).getMessage());
        assertEquals("ERROR: w.xml: it has 0 <filter-mapping> elements for P, and must have exactly one.",
                assertThrows(Refusal.class, () -> Merge.verify(web(def + t + l), d, "w.xml")).getMessage());
        WebXml complete = WebXml.parse(bytes("<web-app " + NS + " metadata-complete=\"1\">" + def + t + p + l + "</web-app>"), "w.xml");
        assertTrue(assertThrows(Refusal.class, () -> Merge.verify(complete, d, "w.xml")).getMessage().contains("is metadata-complete"));
    }

    @Test
    void metadataCompleteIsReadAsAnXsdBoolean() throws Refusal {
        for (String v : List.of("true", " true ", "1")) {
            assertTrue(WebXml.parse(bytes("<web-app " + NS + " metadata-complete=\"" + v + "\"/>"), "w").metadataComplete(), v);
        }
        for (String v : List.of("false", "0", "TRUE")) {
            assertFalse(WebXml.parse(bytes("<web-app " + NS + " metadata-complete=\"" + v + "\"/>"), "w").metadataComplete(), v);
        }
        assertFalse(web("").metadataComplete(), "absent is false");
    }

    @Test
    void theNamespaceSaysWhichServletApi() throws Refusal {
        assertEquals("jakarta", web("").namespace("w"));
        assertEquals("javax", WebXml.parse(bytes("<web-app xmlns=\"" + WebXml.JAVA_EE_JCP + "\"/>"), "w").namespace("w"));
        assertEquals("javax", WebXml.parse(bytes("<web-app xmlns=\"" + WebXml.JAVA_EE_SUN + "\"/>"), "w").namespace("w"));
        assertTrue(assertThrows(Refusal.class, () -> WebXml.parse(bytes("<web-app/>"), "w").namespace("w")).getMessage()
                .contains("is in the namespace 'null'"));
    }

    @Test
    void theParserRefusesADoctypeAndWhatIsNotXml() {
        String doctype = "<?xml version=\"1.0\"?><!DOCTYPE web-app [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><web-app>&x;</web-app>";
        assertTrue(assertThrows(Refusal.class, () -> Xml.parse(bytes(doctype), "w.xml")).getMessage()
                .startsWith("ERROR: w.xml is not well-formed XML this assembler accepts: "));
        assertThrows(Refusal.class, () -> Xml.parse(bytes("<web-app>"), "w.xml"));
    }
}
