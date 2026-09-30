/*
 * Every operator path this module maps is in a route table, with a scope, and nothing in a table is stale.
 */
package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.pingidentity.ps.oidf.platform.pf.auth.OperatorRoute;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorRoutes;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorScopes;
import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Plan item S8b's completeness test for pf-integration: the servlets are found from their {@code @WebServlet}
 * annotations in this module's sources, never from a hand list, so a new operator path or method fails here until it is
 * given a route (and a scope) or listed in {@link OperatorApi#NOT_OPERATOR} with its reason.
 */
class OperatorApiRoutesTest {

    /** The path prefixes operator surfaces live under (the spec's list, less health, which is platform-pf's). */
    private static final List<String> OPERATOR_PREFIXES = List.of("/federation/admin", "/federation/agents",
            "/federation/resources", "/federation/registered-clients");

    /** Each operator mapping's table, and how a request path within it is written in that table. */
    private static final Map<String, OperatorRoutes> TABLES = Map.of(
            "/federation/admin/*", OperatorApi.FEDERATION_ADMIN,
            "/federation/agents/*", OperatorApi.HOSTED_ENTITIES,
            "/federation/resources/*", OperatorApi.HOSTED_ENTITIES,
            "/federation/registered-clients", OperatorApi.REGISTERED_CLIENTS);

    private static final Path SOURCES = Path.of("src/main/java");

    /** Every {@code @WebServlet} class in this module's sources, by pattern. */
    private static Map<String, Class<?>> mappings() throws IOException, ClassNotFoundException {
        Map<String, Class<?>> out = new LinkedHashMap<>();
        List<Path> files;
        try (Stream<Path> walk = Files.walk(SOURCES)) {
            files = walk.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }
        for (Path file : files) {
            if (!Files.readString(file, StandardCharsets.UTF_8).contains("@WebServlet(")) {
                continue;
            }
            String name = SOURCES.relativize(file).toString().replace('/', '.').replace('\\', '.');
            Class<?> type = Class.forName(name.substring(0, name.length() - ".java".length()));
            WebServlet mapping = type.getAnnotation(WebServlet.class);
            assertTrue(mapping != null, file + " says @WebServlet but its class carries none");
            for (String pattern : mapping.urlPatterns().length > 0 ? mapping.urlPatterns() : mapping.value()) {
                out.put(pattern, type);
            }
        }
        return out;
    }

    private static boolean operatorPath(String pattern) {
        return OPERATOR_PREFIXES.stream().anyMatch(p -> pattern.equals(p) || pattern.startsWith(p + "/"));
    }

    /** The HTTP methods {@code type} serves itself: each {@code doX} it declares, and HEAD with GET. */
    private static Set<String> methods(Class<?> type) {
        Set<String> out = new LinkedHashSet<>();
        for (Method m : type.getDeclaredMethods()) {
            switch (m.getName()) {
                case "doGet" -> {
                    out.add("GET");
                    out.add("HEAD");
                }
                case "doPost" -> out.add("POST");
                case "doPut" -> out.add("PUT");
                case "doDelete" -> out.add("DELETE");
                case "doPatch" -> out.add("PATCH");
                case "doHead" -> out.add("HEAD");
                default -> { }
            }
        }
        return out;
    }

    /** The {@code case "..."} labels of the body of the method {@code declaration} starts, in {@code source}. */
    private static List<String> cases(String source, String declaration) {
        int start = source.indexOf(declaration);
        assertTrue(start > 0, declaration + " not found");
        int end = source.indexOf("\n    }\n", start);
        Matcher m = Pattern.compile("case \"([^\"]+)\"").matcher(source.substring(start, end));
        List<String> out = new ArrayList<>();
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    private static String source(String relative) throws IOException {
        return Files.readString(SOURCES.resolve(relative), StandardCharsets.UTF_8);
    }

    @Test
    void everyMethodOfEveryOperatorMappingIsARouteOrListedAsNotOne() throws Exception {
        Map<String, Class<?>> mappings = mappings();
        assertTrue(mappings.size() >= 6, "the scan found this module's servlets: " + mappings.keySet());
        List<String> operator = mappings.keySet().stream().filter(OperatorApiRoutesTest::operatorPath).toList();
        assertEquals(TABLES.keySet(), Set.copyOf(operator), "every operator mapping has a table, and no table is stale");
        for (String pattern : operator) {
            OperatorRoutes table = TABLES.get(pattern);
            String sample = pattern.endsWith("/*") ? pattern.substring(0, pattern.length() - 2) : pattern;
            for (String method : methods(mappings.get(pattern))) {
                String key = method + " " + pattern;
                boolean listed = OperatorApi.NOT_OPERATOR.containsKey(key);
                boolean routed = table != OperatorApi.FEDERATION_ADMIN
                        ? table.match(method, sample).isPresent() || table.match(method, sample + "/x").isPresent()
                        : !cases(source("com/pingidentity/ps/oidf/servlet/trustanchor/FederationAdminServlet.java"),
                                "GET".equals(method) || "HEAD".equals(method) ? "void read(" : "void change(").isEmpty();
                if (listed == routed) {
                    fail(key + (listed ? " is both a route and listed as not one" : " is neither a route nor listed as not one"));
                }
            }
        }
        for (String key : OperatorApi.NOT_OPERATOR.keySet()) {
            String pattern = key.substring(key.indexOf(' ') + 1);
            assertTrue(mappings.containsKey(pattern), key + " names a mapping this module does not have");
            assertTrue(methods(mappings.get(pattern)).contains(key.substring(0, key.indexOf(' '))), key + " names a method not served");
        }
    }

    @Test
    void everyPathTheAdminApiAnswersIsARouteForItsMethod() throws Exception {
        String admin = source("com/pingidentity/ps/oidf/servlet/trustanchor/FederationAdminServlet.java");
        List<String> gets = cases(admin, "void read(");
        assertEquals(List.of("/trust-marks", "/trust-marks/audit", "/keys", "/entities", "/entities/audit"), gets);
        for (String path : gets) {
            for (String method : List.of("GET", "HEAD")) {
                OperatorRoute route = OperatorApi.FEDERATION_ADMIN.match(method, path).orElseThrow(() -> new AssertionError(path));
                assertFalse(route.mutation(), path);
                assertEquals(OperatorScopes.ADMIN_READ, route.scope(), path);
            }
            assertTrue(OperatorApi.FEDERATION_ADMIN.match("DELETE", path).isEmpty());
        }
        List<String> posts = new ArrayList<>(cases(admin, "void change("));
        for (String action : cases(source("com/pingidentity/ps/oidf/servlet/trustanchor/HostedEntityAdmin.java"), "Answer change(")) {
            posts.add("/entities/" + action);
        }
        assertEquals(9, posts.size(), posts.toString());
        for (String path : posts) {
            OperatorRoute route = OperatorApi.FEDERATION_ADMIN.match("POST", path).orElseThrow(() -> new AssertionError(path));
            assertTrue(route.mutation(), path);
        }
        assertEquals(OperatorScopes.ADMIN_TRUST_MARKS, OperatorApi.FEDERATION_ADMIN.match("POST", "/trust-marks").orElseThrow().scope());
        assertEquals(OperatorScopes.ADMIN_TRUST_MARKS, OperatorApi.FEDERATION_ADMIN.match("POST", "/trust-marks/revoke").orElseThrow().scope());
        assertEquals(OperatorScopes.ADMIN_KEYS, OperatorApi.FEDERATION_ADMIN.match("POST", "/keys/revoke").orElseThrow().scope());
        assertEquals(OperatorScopes.ADMIN_KEYS, OperatorApi.FEDERATION_ADMIN.match("POST", "/entities/rotate-key").orElseThrow().scope());
        for (String action : List.of("suspend", "reactivate", "revoke", "metadata", "metadata-policy")) {
            assertEquals(OperatorScopes.ADMIN_ENTITIES, OperatorApi.FEDERATION_ADMIN.match("POST", "/entities/" + action)
                    .orElseThrow().scope(), action);
        }
        assertTrue(OperatorApi.FEDERATION_ADMIN.match("POST", "/entities/unknown").isEmpty(), "no prefix route opens a new action");
    }

    @Test
    void hostedEntityEnrolmentAndRevocationNeedTheEntitiesScope() {
        for (String collection : List.of("/federation/agents", "/federation/resources")) {
            OperatorRoute enrol = OperatorApi.HOSTED_ENTITIES.match("POST", collection).orElseThrow();
            assertEquals(OperatorScopes.ADMIN_ENTITIES, enrol.scope());
            assertTrue(enrol.mutation());
            assertTrue(OperatorApi.HOSTED_ENTITIES.match("POST", collection + "/a1").isEmpty(), "POST only the root");
            OperatorRoute revoke = OperatorApi.HOSTED_ENTITIES.match("DELETE", collection + "/a1").orElseThrow();
            assertEquals(OperatorScopes.ADMIN_ENTITIES, revoke.scope());
            assertTrue(revoke.mutation());
            assertTrue(OperatorApi.HOSTED_ENTITIES.match("GET", collection + "/a1/.well-known/openid-federation").isEmpty(),
                    "resolution is not an operator route");
            assertTrue(OperatorApi.HOSTED_ENTITIES.match("PUT", collection + "/a1/entity-configuration").isEmpty(),
                    "self-signed publication is not an operator route");
        }
    }

    @Test
    void theRegisteredClientsNeedTheirOwnReadScope() {
        for (String method : List.of("GET", "HEAD")) {
            OperatorRoute route = OperatorApi.REGISTERED_CLIENTS.match(method, "/federation/registered-clients").orElseThrow();
            assertEquals(OperatorScopes.ADMIN_CLIENTS_READ, route.scope());
            assertFalse(route.mutation());
        }
        assertTrue(OperatorApi.REGISTERED_CLIENTS.match("POST", "/federation/registered-clients").isEmpty());
    }

    @Test
    void theStaticBearerIsTheInitParamThenThePropertyThenTheEnvironment() {
        jakarta.servlet.ServletConfig config = org.mockito.Mockito.mock(jakarta.servlet.ServletConfig.class);
        org.mockito.Mockito.when(config.getInitParameter("adminToken")).thenReturn("from-init-param");
        assertEquals("from-init-param", OperatorApi.staticBearer(config));
        assertEquals(System.getenv("OIDF_AUTHORITY_ADMIN_TOKEN"), OperatorApi.staticBearer(null), "this JVM sets none");
        assertEquals("from-init-param", OperatorApi.authenticator(config).withStaticBearer(null) == null ? null : "from-init-param");
    }

    @Test
    void anAuthenticatorThatCannotBeBuiltIsNullAndEveryOperatorRouteAnswers503() throws Exception {
        assertEquals(null, OperatorApi.authenticator(() -> {
            throw new NoClassDefFoundError("com/pingidentity/ps/oidf/rs/JwksSource");
        }));
        assertEquals(null, OperatorApi.authenticator(() -> {
            throw new IllegalStateException("no Redis");
        }));
        jakarta.servlet.http.HttpServletResponse response = org.mockito.Mockito.mock(jakarta.servlet.http.HttpServletResponse.class);
        assertEquals(null, OperatorApi.authorise(null, org.mockito.Mockito.mock(jakarta.servlet.http.HttpServletRequest.class),
                response, OperatorApi.REGISTERED_CLIENTS.match("GET", "/federation/registered-clients").orElseThrow()));
        org.mockito.Mockito.verify(response).setStatus(503);
        org.mockito.Mockito.verify(response).setHeader("Cache-Control", "no-store");
        com.pingidentity.ps.oidf.platform.health.ComponentParts.Part part =
                com.pingidentity.ps.oidf.platform.health.Startup.begin("S8B_OPERATOR_TEST", "OperatorUnbuildable");
        assertFalse(com.pingidentity.ps.oidf.servlet.trustanchor.FederationAdminServletAccess.operatorConfigured(part, null));
        assertEquals(com.pingidentity.ps.oidf.platform.component.ComponentState.FAILED_CONFIG, part.status().state());
    }

    /** A token with {@code oidf.admin.read} reads and changes nothing: no mutation anywhere asks only for it. */
    @Test
    void noChangeIsOpenedByTheReadScope() throws Exception {
        for (OperatorRoutes table : List.of(OperatorApi.FEDERATION_ADMIN, OperatorApi.HOSTED_ENTITIES, OperatorApi.REGISTERED_CLIENTS)) {
            for (String path : List.of("/trust-marks", "/trust-marks/revoke", "/keys/revoke", "/entities/suspend",
                    "/entities/rotate-key", "/federation/agents", "/federation/agents/a1", "/federation/registered-clients")) {
                for (String method : List.of("POST", "PUT", "DELETE", "PATCH")) {
                    table.match(method, path).ifPresent(route -> {
                        assertTrue(route.mutation(), method + " " + path);
                        assertNotEquals(OperatorScopes.ADMIN_READ, route.scope(), method + " " + path);
                    });
                }
            }
        }
    }
}
