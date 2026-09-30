package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The jar's entry point in process, on the test class path (every module's catalogue, from the modules' own jars):
 * its options, its parity with {@link Preflight}, and the two fixtures' exit status and lines. PreflightJarCheck runs
 * the packed jar itself.
 */
class PreflightJarTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 10, 1);
    private static final ClassLoader LOADER = PreflightJarTest.class.getClassLoader();

    /** The start of each line the violations fixture prints: one of each kind, then the warnings and the total. */
    static final String[] VIOLATIONS = {
        // a component switch that does not parse
        "REFUSED: OIDF_SSF_ENABLED must be one of true, false, not maybe [SSF]",
        // forbidden, its component switched off
        "not refused (switched off): OIDF_ATTESTER_CIMD_URL is set, which the production profile forbids",
        // the JVM-wide flag
        "REFUSED: jdk.internal.httpclient.disableHostnameVerification is set, which the production profile forbids",
        // a risk not accepted
        "REFUSED: OIDF_FEDERATION_RESOLVE_DISCOVERY=any, which the production profile allows only with the risk"
                + " 'resolve-any' accepted",
        // unreadable
        "REFUSED: OIDF_FEDERATION_IGNORE_SSL_ERRORS cannot be read",
        // required, its component switched on
        "REFUSED: OIDF_OPERATOR_AUDIENCE is unset, and the production profile requires it",
        "REFUSED: OIDF_OPERATOR_BASE_URL is unset, and the production profile requires it",
        // forbidden
        "REFUSED: OIDF_FETCH_ALLOW_HTTP=true, which the production profile forbids",
        // unknown, under a family
        "REFUSED: OIDF_FEDERATION_TRUST_ANCHOR is set, under the OIDF_FEDERATION_ family",
        // the warnings
        "warning: OIDF_NOT_A_FAMILY is set and no settings catalogue declares it",
        "warning: OIDF_ACCEPTED_RISKS names 'no-such-risk'",
        "8 line(s) under the production profile refuse the components named; each answers 503 until it is fixed",
    };

    @TempDir
    Path dir;

    /** One run's exit status and streams. */
    record Run(int status, String out, String err) {
        List<String> lines() {
            return out.lines().toList();
        }
    }

    static Run jar(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int status = PreflightJar.run(args, print(out), print(err), LOADER, TODAY);
        return new Run(status, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    static Run preflight(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int status = Preflight.run(args, print(out), print(err), LOADER, TODAY);
        return new Run(status, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private static PrintStream print(ByteArrayOutputStream bytes) {
        return new PrintStream(bytes, true, StandardCharsets.UTF_8);
    }

    static String fixture(String name) {
        URL url = PreflightJarTest.class.getResource("/fixtures/" + name);
        try {
            return Path.of(url.toURI()).toString();
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The file {@code name} with {@code line} added at its end. */
    private String withLine(String name, String line) throws IOException {
        List<String> lines = new ArrayList<>(Files.readAllLines(Path.of(fixture(name)), StandardCharsets.UTF_8));
        lines.add(line);
        Path copy = dir.resolve(name);
        Files.write(copy, lines, StandardCharsets.UTF_8);
        return copy.toString();
    }

    @Test
    void theCleanFixtureExitsZeroAndSaysSo() {
        Run run = jar("--env-file", fixture("clean.env"));
        assertEquals(Preflight.CLEAN, run.status(), run.out());
        assertFalse(run.out().contains("REFUSED: "), run.out());
        assertEquals("clean under the production profile: nothing would be refused (2 violation(s) listed that refuse"
                + " nothing here)", run.lines().get(run.lines().size() - 1));
        assertEquals("", run.err());
    }

    @Test
    void theViolationsFixtureExitsOneWithALineForEachKind() {
        Run run = jar("--env-file", fixture("violations.env"));
        assertEquals(Preflight.REFUSED, run.status(), run.out());
        assertViolationLines(run.lines(), run.out());
    }

    /** {@code lines} are the violations fixture's: each of {@link #VIOLATIONS} once, and nothing else. */
    static void assertViolationLines(List<String> lines, String out) {
        assertEquals(VIOLATIONS.length, lines.size(), out);
        for (String start : VIOLATIONS) {
            assertEquals(1, lines.stream().filter(line -> line.startsWith(start)).count(), start + "\n" + out);
        }
        // The violations in the order the catalogues give them; the warnings, and the total, last.
        assertEquals(VIOLATIONS[VIOLATIONS.length - 1], lines.get(lines.size() - 1));
        assertTrue(lines.get(lines.size() - 2).startsWith("warning: "), out);
        assertTrue(lines.stream().filter(line -> line.startsWith("REFUSED: jdk.internal.httpclient"))
                .allMatch(line -> line.contains("[FEDERATION, ") && line.contains(", FAPI")), out);
    }

    @Test
    void withoutAcceptedRisksTheCheckIsPreflightsOwn() {
        for (String name : List.of("clean.env", "violations.env")) {
            for (String profile : List.of("production", "development")) {
                assertEquals(preflight("--env-file", fixture(name), "--profile", profile),
                        jar("--profile", profile, "--env-file", fixture(name)), name + " " + profile);
            }
            assertEquals(preflight("--env-file", fixture(name)), jar("--env-file", fixture(name)), name);
        }
    }

    @Test
    void acceptedRisksStandsInForTheFilesList() throws IOException {
        Run accepted = jar("--env-file", fixture("violations.env"), "--accepted-risks", "resolve-any");
        assertEquals(preflight("--env-file", withLine("violations.env", "OIDF_ACCEPTED_RISKS=resolve-any")), accepted);
        assertFalse(accepted.out().contains("REFUSED: OIDF_FEDERATION_RESOLVE_DISCOVERY"), accepted.out());
        assertFalse(accepted.out().contains("no-such-risk"), accepted.out());
        assertEquals(Preflight.REFUSED, accepted.status());

        // Empty accepts nothing, the dated risk the clean file accepts included.
        Run none = jar("--accepted-risks", "", "--env-file", fixture("clean.env"));
        assertEquals(preflight("--env-file", withLine("clean.env", "OIDF_ACCEPTED_RISKS=")), none);
        assertEquals(Preflight.REFUSED, none.status(), none.out());
        assertTrue(none.out().contains("REFUSED: OIDF_REGISTRATION_EXPIRY_ENFORCEMENT=log"), none.out());

        // With --profile, as Preflight takes it.
        Run development = jar("--env-file", fixture("violations.env"), "--profile", "development", "--accepted-risks",
                "resolve-any");
        assertEquals(preflight("--profile", "development", "--env-file",
                withLine("violations.env", "OIDF_ACCEPTED_RISKS=resolve-any")), development);
    }

    @Test
    void acceptedRisksReportsAFileItCannotReadAsPreflightDoes() throws IOException {
        String missing = dir.resolve("missing.env").toString();
        Run run = jar("--env-file", missing, "--accepted-risks", "pkce-off");
        assertEquals(Preflight.USAGE, run.status());
        assertEquals(preflight("--env-file", missing).err(), run.err());

        Path bad = dir.resolve("bad.env");
        Files.writeString(bad, "OIDF_FETCH_ALLOW_HTTP=false\nnot a line\n", StandardCharsets.UTF_8);
        Run badRun = jar("--env-file", bad.toString(), "--accepted-risks", "pkce-off");
        assertEquals(Preflight.USAGE, badRun.status());
        assertEquals(preflight("--env-file", bad.toString()).err(), badRun.err());
        assertTrue(badRun.err().contains("line 2 is not NAME=value"), badRun.err());

        Run nul = jar("--env-file", "bad\0path", "--accepted-risks", "pkce-off");
        assertEquals(Preflight.USAGE, nul.status());
        assertTrue(nul.err().contains("cannot be read (InvalidPathException)"), nul.err());
    }

    @Test
    void argumentsItCannotReadAreAUsageError() {
        String file = fixture("clean.env");
        List<String[]> wrong = List.of(new String[0], new String[] {"--list", "--env-file", file},
                new String[] {"--env-file"}, new String[] {"--env-file", file, "--bogus"},
                new String[] {"--accepted-risks", "pkce-off"}, new String[] {"--env-file", file, "--profile", "staging"},
                new String[] {"--env-file", file, "--accepted-risks"}, new String[] {"--profile", "production"});
        for (String[] args : wrong) {
            Run run = jar(args);
            assertEquals(Preflight.USAGE, run.status(), String.join(" ", args));
            assertEquals(PreflightJar.USAGE_LINE + System.lineSeparator(), run.err(), String.join(" ", args));
            assertEquals("", run.out());
        }
    }

    @Test
    void listPrintsEveryCatalogueOnTheClassPath() {
        Run run = jar("--list");
        assertEquals(Preflight.CLEAN, run.status(), run.out());
        Catalogues.Loaded loaded = Catalogues.onClassPath(LOADER);
        assertTrue(loaded.problems().isEmpty(), loaded.problems().toString());
        List<String> lines = run.lines();
        assertEquals(loaded.catalogues().size() + 1, lines.size(), run.out());
        int settings = loaded.catalogues().stream().mapToInt(c -> c.settings().size()).sum();
        assertEquals("oidf-preflight (version unknown: not run from its jar): " + loaded.catalogues().size()
                + " catalogues, " + settings + " settings", lines.get(0));
        for (int i = 0; i < loaded.catalogues().size(); i++) {
            Catalogue c = loaded.catalogues().get(i);
            String line = lines.get(i + 1);
            assertTrue(line.startsWith("  " + c.component() + " "), line);
            assertTrue(line.contains(" " + c.module() + " "), line);
            assertTrue(line.endsWith(" " + c.settings().size() + " settings, " + c.removed().size() + " removed"), line);
        }
    }

    @Test
    void listExitsOneWhenACatalogueCannotBeLoaded() throws IOException {
        Path settings = Files.createDirectories(dir.resolve("META-INF/oidf-settings"));
        Files.writeString(settings.resolve("broken.json"), "{}", StandardCharsets.UTF_8);
        try (URLClassLoader loader = new URLClassLoader(new URL[] {dir.toUri().toURL()}, null)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int status = PreflightJar.list(Catalogues.onClassPath(loader), "about", print(out));
            String printed = out.toString(StandardCharsets.UTF_8);
            assertEquals(Preflight.REFUSED, status, printed);
            List<String> lines = printed.lines().toList();
            assertEquals("about: 0 catalogues, 0 settings", lines.get(0));
            assertTrue(lines.get(1).startsWith("  cannot load broken: "), printed);
        }
    }

    @Test
    void aboutSaysWhenItIsNotRunFromItsJar() {
        assertEquals("oidf-preflight (version unknown: not run from its jar)", PreflightJar.about(PreflightJar.class));
        // A class the JDK loads has no code source at all.
        assertEquals("oidf-preflight (version unknown: not run from its jar)", PreflightJar.about(String.class));
    }

    @Test
    void aboutReadsTheVersionAndCommitFromItsJarsManifest() throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.IMPLEMENTATION_VERSION, "9.9.9");
        manifest.getMainAttributes().putValue("Build-Commit", "abc1234");
        Path jar = markerJar("with-manifest.jar", manifest);
        try (URLClassLoader loader = new URLClassLoader(new URL[] {jar.toUri().toURL()}, null)) {
            assertEquals("oidf-preflight 9.9.9, commit abc1234", PreflightJar.about(loader.loadClass(Marker.class.getName())));
        }
    }

    @Test
    void aboutSaysSoWhenItsJarHasNoManifestOrCannotBeRead() throws Exception {
        Path bare = markerJar("no-manifest.jar", null);
        try (URLClassLoader loader = new URLClassLoader(new URL[] {bare.toUri().toURL()}, null)) {
            assertEquals("oidf-preflight (version unknown: not run from its jar)",
                    PreflightJar.about(loader.loadClass(Marker.class.getName())));
        }
        Path damaged = markerJar("damaged.jar", new Manifest());
        try (URLClassLoader loader = new URLClassLoader(new URL[] {damaged.toUri().toURL()}, null)) {
            Class<?> marker = loader.loadClass(Marker.class.getName());
            Files.write(damaged, new byte[] {1, 2, 3});
            assertEquals("oidf-preflight (version unknown: not run from its jar)", PreflightJar.about(marker));
        }
    }

    /** A class with nothing to link, for a jar of its own. */
    static final class Marker {
    }

    /** A jar in the temp directory holding {@link Marker}, with {@code manifest} when it is not null. */
    private Path markerJar(String name, Manifest manifest) throws IOException {
        String entry = Marker.class.getName().replace('.', '/') + ".class";
        byte[] bytes;
        try (InputStream in = LOADER.getResourceAsStream(entry)) {
            bytes = in.readAllBytes();
        }
        Path jar = dir.resolve(name);
        try (JarOutputStream out = manifest == null
                ? new JarOutputStream(Files.newOutputStream(jar))
                : new JarOutputStream(Files.newOutputStream(jar), manifest)) {
            out.putNextEntry(new JarEntry(entry));
            out.write(bytes);
            out.closeEntry();
        }
        return jar;
    }
}
