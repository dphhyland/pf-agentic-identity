/*
 * Every SSF path is classed, and each servlet authenticates the way its class says.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.annotation.WebServlet;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Plan item S8b's completeness test for the SSF servlets: the patterns come from the {@code @WebServlet} annotations in
 * this module's sources, and each is in {@link SsfRoutes} - a receiver's, a provisioner's, the metadata or the push
 * endpoint - so a new SSF path fails here until it is classed (and, if it administers more than a receiver's own
 * streams, given the operator scope {@code ssf.admin}).
 */
class SsfRoutesTest {
    private static final Path SOURCES = Path.of("src/main/java");

    @Test
    void everySsfPathIsClassedAndEachServletAuthenticatesAsItsClassSays() throws Exception {
        Map<String, Set<SsfRoutes.Access>> byServlet = new HashMap<>();
        Map<String, String> sourceOf = new HashMap<>();
        List<Path> files;
        try (Stream<Path> walk = Files.walk(SOURCES)) {
            files = walk.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }
        int patterns = 0;
        for (Path file : files) {
            String source = Files.readString(file, StandardCharsets.UTF_8);
            if (!source.contains("@WebServlet(")) {
                continue;
            }
            String name = SOURCES.relativize(file).toString().replace('/', '.').replace('\\', '.');
            Class<?> type = Class.forName(name.substring(0, name.length() - ".java".length()));
            WebServlet mapping = type.getAnnotation(WebServlet.class);
            for (String pattern : mapping.urlPatterns().length > 0 ? mapping.urlPatterns() : mapping.value()) {
                patterns++;
                SsfRoutes.Access access = SsfRoutes.BY_PATTERN.get(pattern);
                assertTrue(access != null, pattern + " (" + type.getSimpleName() + ") is not classed in SsfRoutes");
                byServlet.computeIfAbsent(type.getSimpleName(), k -> EnumSet.noneOf(SsfRoutes.Access.class)).add(access);
                sourceOf.put(type.getSimpleName(), source);
            }
        }
        assertEquals(SsfRoutes.BY_PATTERN.size(), patterns, "no stale pattern in SsfRoutes");
        for (Map.Entry<String, Set<SsfRoutes.Access>> e : byServlet.entrySet()) {
            assertEquals(1, e.getValue().size(), e.getKey() + " serves one kind of caller");
            String source = sourceOf.get(e.getKey());
            switch (e.getValue().iterator().next()) {
                case RECEIVER -> {
                    assertTrue(source.contains("SsfHttp.authorize(req, resp, cfg)"), e.getKey());
                    assertFalse(source.contains("authorizeProvisioner"), e.getKey());
                }
                case PROVISIONER -> assertTrue(source.contains("SsfHttp.authorizeProvisioner("), e.getKey());
                case PUBLIC -> assertFalse(source.contains("SsfHttp.authorize"), e.getKey());
                case PUSH -> assertTrue(source.contains("receiverPushToken") || source.contains("Bearer "), e.getKey());
            }
            assertFalse(source.contains("OperatorAuthenticator"), "SSF's callers are not operators: " + e.getKey());
        }
    }
}
