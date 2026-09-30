package com.pingidentity.ps.oidf.platform.pf.internals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * No production class outside platform-pf names PingFederate's internal services: the issuer utilities, the
 * management factory, the discovery handlers, and the two managers the factory hands out. {@link PfInternals} is
 * the one place that calls them, so a PingFederate release that changes one changes one class here. The data
 * types PingFederate hands back ({@code Client}, {@code ParamValues}, {@code ClientAuthenticationType}) are not
 * services and stay where they are used (platform-pf's README, "internals").
 */
class InternalsBoundaryTest {
    /**
     * A package, or a service type, from PingFederate's internals; matched anywhere in a source file. A wildcard
     * import of the domain package counts too, since it would let a source name either manager by its simple name.
     */
    static final Pattern INTERNAL = Pattern.compile("org\\.sourceid\\.(?:oauth20\\.issuer|saml20\\.domain\\.mgmt"
            + "|openid\\.connect\\.handlers)\\b|org\\.sourceid\\.oauth20\\.domain\\.(?:ClientManager|AuthzServerManager)\\b"
            + "|import\\s+org\\.sourceid\\.oauth20\\.domain\\.\\*");

    /**
     * Files that still name an internal, each with the finding that records why. None since 0.6.0: the last one,
     * servlets/ssf's PfIdTokenVerifier, moved onto {@link PfInternals#issuer} (HSSF3, finding F-0215).
     */
    static final Map<String, String> RECORDED = Map.of();

    private static final Path ROOT = Path.of("").toAbsolutePath().resolve("../..").normalize();

    /** Every tracked production Java source outside platform-pf that names an internal, by repository path. */
    static Map<String, List<String>> offenders(Path root) throws IOException {
        Map<String, List<String>> found = new TreeMap<>();
        for (String top : List.of("libs", "servlets", "services", "plugins")) {
            Path dir = root.resolve(top);
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> files = Files.walk(dir)) {
                for (Path file : files.filter(InternalsBoundaryTest::production).toList()) {
                    String rel = root.relativize(file).toString().replace('\\', '/');
                    if (rel.startsWith("libs/platform-pf/")) {
                        continue;
                    }
                    List<String> lines = Files.readAllLines(file);
                    for (int i = 0; i < lines.size(); i++) {
                        if (INTERNAL.matcher(lines.get(i)).find()) {
                            found.computeIfAbsent(rel, k -> new ArrayList<>()).add((i + 1) + ": " + lines.get(i).strip());
                        }
                    }
                }
            }
        }
        return found;
    }

    private static boolean production(Path file) {
        String path = file.toString().replace('\\', '/');
        return path.endsWith(".java") && path.contains("/src/main/") && !path.contains("/target/");
    }

    @Test
    void noProductionClassOutsidePlatformPfNamesAnInternalService() throws IOException {
        Map<String, List<String>> found = offenders(ROOT);
        Map<String, List<String>> unrecorded = new TreeMap<>(found);
        unrecorded.keySet().removeAll(RECORDED.keySet());
        assertTrue(unrecorded.isEmpty(), "call PingFederate's internals through PfInternals instead: " + unrecorded);
        for (String path : RECORDED.keySet()) {
            assertTrue(found.containsKey(path), path + " no longer names an internal: remove its entry, and close "
                    + RECORDED.get(path));
        }
    }

    @Test
    void theScanReadsTheRepositoryAndSeesTheFacade() throws IOException {
        long sources;
        try (Stream<Path> files = Files.walk(ROOT.resolve("servlets"))) {
            sources = files.filter(InternalsBoundaryTest::production).count();
        }
        assertTrue(sources > 100, "the scan found the servlets' sources: " + sources);
        String facade = Files.readString(ROOT.resolve(
                "libs/platform-pf/src/main/java/com/pingidentity/ps/oidf/platform/pf/internals/PfInternals.java"));
        assertEquals(3, facade.lines().filter(l -> l.startsWith("import ") && INTERNAL.matcher(l).find()).count(),
                "the pattern matches the facade's own imports");
    }

    @Test
    void thePatternMatchesEveryWayASourceNamesAnInternal() {
        for (String line : List.of(
                "import org.sourceid.oauth20.issuer.OAuthIssuerUtils;",
                "import org.sourceid.saml20.domain.mgmt.*;",
                "return org.sourceid.saml20.domain.mgmt.MgmtFactory.getAuthzServerManager().getTokenEndpointBaseUrl();",
                "import org.sourceid.openid.connect.handlers.ProviderConfigurationInfoHandler;",
                "org.sourceid.oauth20.domain.ClientManager manager = null;",
                "import org.sourceid.oauth20.domain.AuthzServerManager;",
                "import org.sourceid.oauth20.domain.*;")) {
            assertTrue(INTERNAL.matcher(line).find(), line);
        }
        for (String line : List.of(
                "import org.sourceid.oauth20.domain.Client;",
                "import org.sourceid.oauth20.domain.ParamValues;",
                "import org.sourceid.oauth20.domain.ClientAuthenticationType;",
                "import org.sourceid.saml20.adapter.attribute.AttributeValue;",
                "import org.sourceid.oauth20.domain.ClientManagerFactoryLookalike;",
                "// OAuthIssuerUtils.getInstance() needs a booted server")) {
            assertFalse(INTERNAL.matcher(line).find(), line);
        }
    }

    @Test
    void aNewCallerIsFoundAndARecordedOneIsNot(@org.junit.jupiter.api.io.TempDir Path root) throws IOException {
        Path caller = root.resolve("servlets/demo/src/main/java/demo/Caller.java");
        Files.createDirectories(caller.getParent());
        Files.writeString(caller, "package demo;\nimport org.sourceid.oauth20.issuer.OAuthIssuerUtils;\n");
        Path test = root.resolve("servlets/demo/src/test/java/demo/CallerTest.java");
        Files.createDirectories(test.getParent());
        Files.writeString(test, "import org.sourceid.oauth20.issuer.OAuthIssuerUtils;\n");
        Path facade = root.resolve("libs/platform-pf/src/main/java/Facade.java");
        Files.createDirectories(facade.getParent());
        Files.writeString(facade, "import org.sourceid.saml20.domain.mgmt.MgmtFactory;\n");
        assertEquals(Map.of("servlets/demo/src/main/java/demo/Caller.java",
                List.of("2: import org.sourceid.oauth20.issuer.OAuthIssuerUtils;")), offenders(root));
    }
}
