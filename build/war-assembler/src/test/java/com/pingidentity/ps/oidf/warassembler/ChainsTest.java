package com.pingidentity.ps.oidf.warassembler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Servlet url-pattern matching and the effective filter chain. */
class ChainsTest {
    private static WebXml.ServletMapping m(String servlet, String pattern) {
        return new WebXml.ServletMapping(servlet, pattern);
    }

    @Test
    void filterPatterns() {
        assertTrue(UrlPatterns.matches("", "/"));
        assertFalse(UrlPatterns.matches("", "/a"));
        assertTrue(UrlPatterns.matches("/*", "/as/token.oauth2"));
        assertTrue(UrlPatterns.matches("/as/*", "/as"));
        assertTrue(UrlPatterns.matches("/as/*", "/as/token.oauth2"));
        assertFalse(UrlPatterns.matches("/as/*", "/assets/x"));
        assertTrue(UrlPatterns.matches("*.oauth2", "/as/token.oauth2"));
        assertFalse(UrlPatterns.matches("*.oauth2", "/as.oauth2/token"));
        assertTrue(UrlPatterns.matches("/as/token.oauth2", "/as/token.oauth2"));
        assertFalse(UrlPatterns.matches("/as/token.oauth2", "/as/par.oauth2"));
    }

    @Test
    void theServletThatServesAPath() {
        List<WebXml.ServletMapping> mappings = List.of(m("root", ""), m("ext", "*.oauth2"), m("ext2", "*.oauth2"),
                m("as", "/as/*"), m("deep", "/as/deep/*"), m("shallow", "/*"), m("exact", "/as/exact.oauth2"), m("default", "/"));
        assertEquals("root", UrlPatterns.servletFor(mappings, "/").servletName());
        assertEquals("exact", UrlPatterns.servletFor(mappings, "/as/exact.oauth2").servletName());
        assertEquals("deep", UrlPatterns.servletFor(mappings, "/as/deep/x.oauth2").servletName(), "the longest prefix");
        assertEquals("as", UrlPatterns.servletFor(mappings, "/as/token.oauth2").servletName(), "a prefix before an extension");
        assertEquals("shallow", UrlPatterns.servletFor(mappings, "/idp/x").servletName());
        List<WebXml.ServletMapping> noPrefix = List.of(m("ext", "*.oauth2"), m("ext2", "*.oauth2"), m("default", "/"), m("other", "*.ciba"));
        assertEquals("ext", UrlPatterns.servletFor(noPrefix, "/as/token.oauth2").servletName(), "the first extension match");
        assertEquals("default", UrlPatterns.servletFor(noPrefix, "/idp/x").servletName());
        assertNull(UrlPatterns.servletFor(List.of(m("ext", "*.ciba"), m("p", "/as/*")), "/idp/x"));
    }

    @Test
    void theChainIsPathMappingsInOrderThenServletMappingsInOrder() throws Refusal {
        WebXml w = WebXml.parse(("<web-app xmlns=\"" + WebXml.JAKARTA_EE + "\">"
                + fm("byServlet", null, "protocol", null) + fm("all", "/*", null, null) + fm("forwardOnly", "/*", null, "FORWARD")
                + fm("requestToo", "/*", null, "REQUEST") + fm("anyServlet", null, "*", null) + fm("defaultOnly", "/", null, null)
                + fm("token", "/as/token.oauth2", null, null) + fm("otherServlet", null, "static", null)
                + "<servlet-mapping><servlet-name>protocol</servlet-name><url-pattern>*.oauth2</url-pattern></servlet-mapping>"
                + "<servlet-mapping><servlet-name>static</servlet-name><url-pattern>/</url-pattern></servlet-mapping>"
                + "</web-app>").getBytes(StandardCharsets.UTF_8), "w");
        assertEquals(List.of("all", "requestToo", "token", "byServlet", "anyServlet"), Chains.chain(w, "/as/token.oauth2"));
        assertEquals(List.of("all", "requestToo", "defaultOnly", "anyServlet", "otherServlet"), Chains.chain(w, "/idp/x"));
        WebXml none = WebXml.parse(("<web-app xmlns=\"" + WebXml.JAKARTA_EE + "\">" + fm("all", "/*", null, null)
                + fm("byServlet", null, "protocol", null) + "</web-app>").getBytes(StandardCharsets.UTF_8), "w");
        assertEquals(List.of("all"), Chains.chain(none, "/as/token.oauth2"), "no servlet serves it: no servlet-name mapping applies");
        Declaration d = Declaration.parse(("<war-filters version=\"1\"><filter name=\"T\" class=\"x.T\"><url-pattern>/as/token.oauth2"
                + "</url-pattern></filter></war-filters>").getBytes(StandardCharsets.UTF_8), "f");
        assertEquals(List.of("chain /as/token.oauth2 (protocol): all > requestToo > token > byServlet > anyServlet"), Chains.describe(w, d));
        assertEquals(List.of("chain /as/token.oauth2 (no servlet): all"), Chains.describe(none, d));
    }

    private static String fm(String name, String pattern, String servlet, String dispatcher) {
        return "<filter-mapping><filter-name>" + name + "</filter-name>"
                + (pattern == null ? "" : "<url-pattern>" + pattern + "</url-pattern>")
                + (servlet == null ? "" : "<servlet-name>" + servlet + "</servlet-name>")
                + (dispatcher == null ? "" : "<dispatcher>" + dispatcher + "</dispatcher>") + "</filter-mapping>";
    }
}
