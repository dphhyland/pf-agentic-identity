package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Every {@code OIDF_*} setting the federation code reads is in the configuration reference, so a setting can't be added
 * without an operator being able to find it.
 */
class ConfigurationDocumentedTest {
    private static final Path ROOT = Path.of("../..");
    private static final Pattern SETTING = Pattern.compile("\"(OIDF_[A-Z0-9_]+)\"");
    private static final List<String> READERS = List.of("libs/openid-federation/src/main/java", "servlets/pf-integration/src/main/java",
            "libs/oidf-jose/src/main/java");

    @Test
    void everySettingTheFederationCodeReadsIsDocumented() throws IOException {
        String reference = Files.readString(ROOT.resolve("docs/federation/configuration.md"));
        Set<String> settings = new TreeSet<>();
        for (String tree : READERS) {
            try (Stream<Path> files = Files.walk(ROOT.resolve(tree))) {
                for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                    Matcher named = SETTING.matcher(Files.readString(file));
                    while (named.find()) {
                        settings.add(named.group(1));
                    }
                }
            }
        }
        List<String> missing = settings.stream()
                .filter(name -> !Pattern.compile("(?<![A-Z0-9_])" + name + "(?![A-Z0-9_])").matcher(reference).find())
                .toList();

        assertTrue(settings.size() > 60, "the scan found the settings, not an empty tree: " + settings.size());
        assertEquals(List.of(), missing, "add these to docs/federation/configuration.md");
    }
}
