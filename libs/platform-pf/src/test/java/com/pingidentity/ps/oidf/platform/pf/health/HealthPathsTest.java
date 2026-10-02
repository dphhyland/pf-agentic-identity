/*
 * The health servlet's paths collide with nothing PingFederate's stock pf-runtime.war maps, nor with this repository's servlets.
 */
package com.pingidentity.ps.oidf.platform.pf.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class HealthPathsTest {

    /** Whether a request for {@code path} could be served by a servlet mapped at {@code pattern} (Servlet 5.0, 12.2). */
    static boolean matches(String pattern, String path) {
        if (pattern.equals(path) || pattern.equals("/")) {
            return true;
        }
        if (pattern.endsWith("/*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            return path.equals(prefix) || path.startsWith(prefix + "/");
        }
        if (pattern.startsWith("*.")) {
            String last = path.substring(path.lastIndexOf('/') + 1);
            return last.endsWith(pattern.substring(1));
        }
        return false;
    }

    private static List<String> healthPaths() {
        return List.of(HealthServlet.class.getAnnotation(WebServlet.class).urlPatterns());
    }

    private static List<String> stock() throws IOException {
        List<String> out = new ArrayList<>();
        try (InputStream in = HealthPathsTest.class.getResourceAsStream("/pf-runtime-13.1.3-servlet-mappings.txt")) {
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                if (!line.isBlank() && !line.startsWith("#")) {
                    out.add(line.strip());
                }
            }
        }
        return out;
    }

    @Test
    void theMatchingRuleIsTheServletSpecs() {
        assertTrue(matches("/as/*", "/as/x"));
        assertTrue(matches("/as/*", "/as"));
        assertFalse(matches("/as/*", "/asx"));
        assertTrue(matches("*.ping", "/pf/heartbeat.ping"));
        assertFalse(matches("*.ping", "/pf/heartbeat"));
        assertTrue(matches("/", "/anything"));
        assertTrue(matches("/error", "/error"));
        assertFalse(matches("/error", "/errors"));
    }

    @Test
    void theHealthServletsPathsAreTheFourDocumented() {
        assertEquals(List.of("/agentic-identity/health/live", "/agentic-identity/health/ready", "/agentic-identity/health",
                "/agentic-identity/info"), healthPaths());
    }

    @Test
    void noStockPingFederateServletMappingCoversAHealthPath() throws IOException {
        List<String> stock = stock();
        assertEquals(21, stock.size(), "the fixture's 21 patterns");
        for (String path : healthPaths()) {
            for (String pattern : stock) {
                assertFalse(matches(pattern, path), path + " is covered by PingFederate's " + pattern);
            }
        }
    }

    @Test
    void noServletOfThisRepositoryIsMappedUnderAgenticIdentity() throws IOException {
        Path root = Path.of("").toAbsolutePath().resolve("../..").normalize();
        Pattern annotation = Pattern.compile("@WebServlet\\((?:urlPatterns\\s*=\\s*)?\\{?([^)]*)\\)");
        Pattern literal = Pattern.compile("\"(/[^\"]*)\"");
        List<String> found = new ArrayList<>();
        for (String top : List.of("libs", "servlets", "services", "plugins")) {
            try (Stream<Path> files = Files.walk(root.resolve(top))) {
                for (Path file : files.filter(p -> p.toString().endsWith(".java") && p.toString().contains("/src/main/")
                        && !p.toString().contains("/target/")).toList()) {
                    Matcher m = annotation.matcher(Files.readString(file));
                    while (m.find()) {
                        Matcher l = literal.matcher(m.group(1));
                        while (l.find()) {
                            found.add(file.getFileName() + " " + l.group(1));
                        }
                    }
                }
            }
        }
        assertTrue(found.size() > 20, "the scan found the repository's servlets: " + found);
        for (String entry : found) {
            String pattern = entry.substring(entry.indexOf(' ') + 1);
            for (String path : healthPaths()) {
                assertFalse(matches(pattern, path) || pattern.startsWith("/agentic-identity"), entry + " collides with " + path);
            }
        }
    }
}
