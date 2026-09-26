package au.com.idpartners.gm.servlet;

import jakarta.servlet.ServletContext;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The version the MCP server reports in {@code initialize} is the war's, read from its manifest: the
 * pom's version, which maven-war-plugin writes as Implementation-Version. It used to be the literal
 * "1.0.0" whatever the war was, so an agent could not tell one build from another.
 *
 * <p>The context is a proxy that answers only {@code getResourceAsStream}: what the servlet reads is
 * the one thing under test, and a full servlet container is not.
 */
class McpServletVersionTest {

    @Test
    void theWarsManifestVersionIsTheServerVersion() {
        assertEquals("0.3.7", McpServlet.versionOf(contextServing(
                "Manifest-Version: 1.0\r\nImplementation-Version: 0.3.7\r\n\r\n")));
    }

    @Test
    void surroundingWhitespaceIsNotPartOfTheVersion() {
        assertEquals("0.3.7", McpServlet.versionOf(contextServing(
                "Manifest-Version: 1.0\r\nImplementation-Version:  0.3.7 \r\n\r\n")));
    }

    @Test
    void aManifestWithoutTheEntryFallsBack() {
        assertEquals(McpServlet.DEVELOPMENT_VERSION, McpServlet.versionOf(contextServing(
                "Manifest-Version: 1.0\r\n\r\n")));
        assertEquals(McpServlet.DEVELOPMENT_VERSION, McpServlet.versionOf(contextServing(
                "Manifest-Version: 1.0\r\nImplementation-Version: \r\n\r\n")));
    }

    @Test
    void noManifestAtAllFallsBack() {
        assertEquals(McpServlet.DEVELOPMENT_VERSION, McpServlet.versionOf(context(() -> null)));
        assertEquals(McpServlet.DEVELOPMENT_VERSION, McpServlet.versionOf(null));
    }

    @Test
    void aManifestThatCannotBeReadFallsBack() {
        assertEquals(McpServlet.DEVELOPMENT_VERSION, McpServlet.versionOf(context(() -> new InputStream() {
            @Override
            public int read() throws java.io.IOException {
                throw new java.io.IOException("unreadable");
            }
        })));
    }

    private static ServletContext contextServing(String manifest) {
        return context(() -> new ByteArrayInputStream(manifest.getBytes(StandardCharsets.UTF_8)));
    }

    /** A ServletContext whose {@code getResourceAsStream("/META-INF/MANIFEST.MF")} is the supplier. */
    private static ServletContext context(Supplier<InputStream> manifest) {
        return (ServletContext) Proxy.newProxyInstance(
                ServletContext.class.getClassLoader(), new Class<?>[] {ServletContext.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getResourceAsStream")
                            && "/META-INF/MANIFEST.MF".equals(args[0])) {
                        return manifest.get();
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }
}
