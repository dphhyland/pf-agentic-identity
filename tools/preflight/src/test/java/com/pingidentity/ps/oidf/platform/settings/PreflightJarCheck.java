package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The packed {@code oidf-preflight.jar}, after package (the surefire execution {@code preflight-jar}, at verify): it
 * holds every catalogue of every reactor module, byte for byte, and nothing else of theirs; its manifest names the
 * version, the commit and the catalogues; and {@code java -jar} gives the fixtures' exit status and lines on the
 * build's java and on each of {@code -Dpreflight.javas}.
 */
class PreflightJarCheck {

    private static final String SETTINGS = Catalogue.RESOURCE_DIRECTORY;
    private static final Pattern MODULE = Pattern.compile("<module>([^<]+)</module>");
    private static final Pattern COMMENT = Pattern.compile("<!--.*?-->", Pattern.DOTALL);

    private static Path jarPath;
    private static Map<String, byte[]> jarCatalogues;

    @BeforeAll
    static void readTheJar() throws IOException {
        jarPath = Path.of(System.getProperty("preflight.jar"));
        assertTrue(Files.isRegularFile(jarPath), jarPath + " is not built");
        jarCatalogues = new TreeMap<>();
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            for (JarEntry entry : Collections.list(jar.entries())) {
                String name = entry.getName();
                if (name.startsWith(SETTINGS) && name.endsWith(".json")) {
                    jarCatalogues.put(name.substring(SETTINGS.length(), name.length() - ".json".length()),
                            jar.getInputStream(entry).readAllBytes());
                }
            }
        }
    }

    /** Every catalogue in the reactor's modules' main resources, by name, with the modules that hold one of that name. */
    static Map<String, List<Path>> reactorCatalogues(Path root) throws IOException {
        String pom = COMMENT.matcher(Files.readString(root.resolve("pom.xml"), StandardCharsets.UTF_8)).replaceAll("");
        Map<String, List<Path>> found = new TreeMap<>();
        Matcher m = MODULE.matcher(pom);
        int modules = 0;
        while (m.find()) {
            modules++;
            Path dir = root.resolve(m.group(1).trim()).resolve("src/main/resources").resolve(SETTINGS);
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> files = Files.list(dir)) {
                for (Path file : files.filter(f -> f.getFileName().toString().endsWith(".json")).sorted().toList()) {
                    String name = file.getFileName().toString();
                    found.computeIfAbsent(name.substring(0, name.length() - ".json".length()), k -> new ArrayList<>())
                            .add(file);
                }
            }
        }
        assertTrue(modules > 20, "the root pom's <modules> were not read: " + modules);
        return found;
    }

    @Test
    void theJarHoldsEveryReactorCatalogueByteForByteAndNoOther() throws IOException {
        Path root = Path.of(System.getProperty("preflight.reactor")).toRealPath();
        Map<String, List<Path>> reactor = reactorCatalogues(root);
        List<String> wrong = new ArrayList<>();
        for (Map.Entry<String, List<Path>> e : reactor.entrySet()) {
            if (e.getValue().size() > 1) {
                wrong.add(e.getKey() + ".json is in more than one module (" + e.getValue() + "): one would overwrite the"
                        + " other in the jar, and Catalogue.load refuses two that differ; rename one");
                continue;
            }
            Path source = e.getValue().get(0);
            byte[] packed = jarCatalogues.get(e.getKey());
            if (packed == null) {
                wrong.add(root.relativize(source) + " is not in the jar: add its module to tools/preflight/pom.xml's"
                        + " dependencies");
            } else if (!Arrays.equals(Files.readAllBytes(source), packed)) {
                wrong.add(root.relativize(source) + " differs from the jar's copy");
            }
        }
        for (String name : jarCatalogues.keySet()) {
            if (!reactor.containsKey(name)) {
                wrong.add("the jar holds " + name + ".json, which no reactor module's main resources hold");
            }
        }
        if (!wrong.isEmpty()) {
            fail(String.join("\n", wrong));
        }
        assertEquals(reactor.keySet(), jarCatalogues.keySet());
    }

    @Test
    void theJarHoldsPlatformsClassesAndNothingElseOfTheModules() throws IOException {
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            List<String> classes = Collections.list(jar.entries()).stream().map(JarEntry::getName)
                    .filter(n -> n.endsWith(".class")).toList();
            assertTrue(classes.contains("com/pingidentity/ps/oidf/platform/settings/Preflight.class"), "no Preflight");
            assertTrue(classes.contains("com/pingidentity/ps/oidf/platform/settings/PreflightJar.class"), "no PreflightJar");
            List<String> foreign = classes.stream().filter(n -> !n.startsWith("com/pingidentity/ps/oidf/platform/"))
                    .toList();
            assertEquals(List.of(), foreign, "classes from outside platform");
        }
    }

    @Test
    void theManifestNamesTheVersionTheCommitAndTheCatalogues() throws IOException {
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Attributes main = jar.getManifest().getMainAttributes();
            assertEquals(PreflightJar.class.getName(), main.getValue(Attributes.Name.MAIN_CLASS));
            assertEquals(System.getProperty("preflight.version"), main.getValue(Attributes.Name.IMPLEMENTATION_VERSION));
            assertEquals(System.getProperty("preflight.commit"), main.getValue("Build-Commit"));
            assertEquals(String.join(" ", jarCatalogues.keySet()), main.getValue("Oidf-Catalogues"));
        }
    }

    /** The build's java, then each of -Dpreflight.javas. */
    static List<String> javas() {
        List<String> javas = new ArrayList<>();
        javas.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        String more = System.getProperty("preflight.javas", "");
        for (String java : more.split(Pattern.quote(File.pathSeparator))) {
            if (!java.isBlank()) {
                javas.add(java.trim());
            }
        }
        return javas;
    }

    record Ran(int status, List<String> lines, String out) {
    }

    static Ran run(String java, String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>(List.of(java, "-jar", jarPath.toString()));
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        byte[] out = process.getInputStream().readAllBytes();
        assertTrue(process.waitFor(2, TimeUnit.MINUTES), String.join(" ", command) + " did not finish");
        String text = new String(out, StandardCharsets.UTF_8);
        return new Ran(process.exitValue(), text.lines().toList(), text);
    }

    @Test
    void theJarRunsTheFixturesOnEveryJava() throws IOException, InterruptedException {
        String clean = PreflightJarTest.fixture("clean.env");
        String violations = PreflightJarTest.fixture("violations.env");
        for (String java : javas()) {
            Ran version = run(java, "--list");
            assertEquals(0, version.status(), java + "\n" + version.out());
            assertEquals(jarCatalogues.size() + 1, version.lines().size(), java + "\n" + version.out());
            assertTrue(version.lines().get(0).startsWith("oidf-preflight " + System.getProperty("preflight.version")
                    + ", commit " + System.getProperty("preflight.commit") + ": " + jarCatalogues.size() + " catalogues, "),
                    version.lines().get(0));

            Ran ok = run(java, "--env-file", clean);
            assertEquals(0, ok.status(), java + "\n" + ok.out());
            assertTrue(ok.lines().get(ok.lines().size() - 1).startsWith("clean under the production profile"), ok.out());

            Ran refused = run(java, "--env-file", violations, "--profile", "production");
            assertEquals(1, refused.status(), java + "\n" + refused.out());
            PreflightJarTest.assertViolationLines(refused.lines(), refused.out());

            Ran usage = run(java, "--env-file");
            assertEquals(2, usage.status(), java + "\n" + usage.out());
            System.out.println(java + ": --list 0, clean 0, violations 1, usage 2");
        }
    }

    @Test
    void aFileThatSaysDevelopmentRefusesNothing() throws IOException, InterruptedException {
        Ran development = run(javas().get(0), "--env-file", PreflightJarTest.fixture("violations.env"), "--profile",
                "development");
        // Under development only the switch that does not parse refuses its component.
        assertEquals(1, development.status(), development.out());
        assertArrayEquals(new String[] {"REFUSED: OIDF_SSF_ENABLED must be one of true, false, not maybe [SSF]"},
                development.lines().stream().filter(l -> l.startsWith("REFUSED: ")).toArray(String[]::new), development.out());
        assertTrue(development.lines().stream().anyMatch(l -> l.startsWith("not refused (development): OIDF_FETCH_ALLOW_HTTP")),
                development.out());
    }
}
