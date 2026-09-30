package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.rar.model.RarModels;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The jar PingFederate loads, as the shade plugin wrote it. Plan S-1: "The plugin shades and relocates it". The
 * library's own package must not be in the jar and no class may still name it - relocated, this copy can never be
 * the class another jar's code links to - and the relocated copy must compute the library's fingerprint, the value
 * the attestation filter's unrelocated copy publishes.
 *
 * <p>Run after package by the pom's {@code shaded-jar} execution; the name is outside surefire's default patterns,
 * so the test phase, which runs before the jar exists, does not pick it up.
 */
class ShadedJarCheck {

    private static final Path JAR = Path.of("target", "pf.plugins.pf-rar-paz-plugin.jar");
    private static final String LIBRARY = "com/pingidentity/ps/oidf/rar/model/";
    private static final String RELOCATED = "com/pingidentity/ps/oidf/rar/shaded/rarmodel/";
    private static final String PLATFORM = "com/pingidentity/ps/oidf/platform/";
    private static final String PLATFORM_RELOCATED = "com/pingidentity/ps/oidf/rar/shaded/platform/";

    private static byte[] read(ZipFile jar, ZipEntry entry) throws IOException {
        try (InputStream in = jar.getInputStream(entry)) {
            return in.readAllBytes();
        }
    }

    @Test
    void theModelIsInTheJarUnderTheRelocatedPackageOnly() throws IOException {
        assertTrue(Files.isRegularFile(JAR), JAR.toAbsolutePath() + " is not there: run after package");
        List<String> named = new ArrayList<>();
        try (ZipFile jar = new ZipFile(JAR.toFile())) {
            List<? extends ZipEntry> entries = jar.stream().toList();
            assertTrue(entries.stream().anyMatch(e -> e.getName().equals(RELOCATED + "RarModels.class")), "the model is shaded in");
            assertTrue(entries.stream().noneMatch(e -> e.getName().startsWith(LIBRARY)), "the library's own package is not exported");
            assertTrue(entries.stream().noneMatch(e -> e.getName().startsWith("com/fasterxml/")), "jackson stays relocated");
            for (ZipEntry entry : entries) {
                if (!entry.getName().endsWith(".class")) {
                    continue;
                }
                String text = new String(read(jar, entry), StandardCharsets.ISO_8859_1);
                if (text.contains(LIBRARY) || text.contains(LIBRARY.replace('/', '.'))) {
                    named.add(entry.getName());
                }
            }
            String gate = new String(read(jar, jar.getEntry("com/pingidentity/ps/oidf/rar/ModelGate.class")),
                    StandardCharsets.ISO_8859_1);
            assertTrue(gate.contains(RELOCATED + "RarModels"), "the plugin's own classes link to the relocated model");
        }
        assertEquals(List.of(), named, "classes that still name the library's unrelocated package");
    }

    @Test
    void platformIsInTheJarUnderTheRelocatedPackageOnly() throws IOException {
        assertTrue(Files.isRegularFile(JAR), JAR.toAbsolutePath() + " is not there: run after package");
        List<String> named = new ArrayList<>();
        try (ZipFile jar = new ZipFile(JAR.toFile())) {
            List<? extends ZipEntry> entries = jar.stream().toList();
            assertTrue(entries.stream().anyMatch(e -> e.getName().equals(PLATFORM_RELOCATED + "profile/DeploymentProfile.class")),
                    "the profile is shaded in");
            assertTrue(entries.stream().anyMatch(e -> e.getName().equals(PLATFORM_RELOCATED + "tls/InsecureTls.class")),
                    "InsecureTls is shaded in");
            assertTrue(entries.stream().noneMatch(e -> e.getName().startsWith(PLATFORM)), "platform's own package is not exported");
            assertTrue(entries.stream().noneMatch(e -> e.getName().startsWith("org/apache/commons/logging/")),
                    "commons-logging stays PingFederate's");
            for (ZipEntry entry : entries) {
                if (!entry.getName().endsWith(".class")) {
                    continue;
                }
                String text = new String(read(jar, entry), StandardCharsets.ISO_8859_1);
                if (text.contains(PLATFORM) || text.contains(PLATFORM.replace('/', '.'))) {
                    named.add(entry.getName());
                }
            }
            String transport = new String(read(jar, jar.getEntry("com/pingidentity/ps/oidf/rar/PdpTransport.class")),
                    StandardCharsets.ISO_8859_1);
            assertTrue(transport.contains(PLATFORM_RELOCATED + "http/OutboundHttp"), "the transport links to the relocated OutboundHttp");
            String tls = new String(read(jar, jar.getEntry("com/pingidentity/ps/oidf/rar/PdpTls.class")), StandardCharsets.ISO_8859_1);
            assertTrue(tls.contains(PLATFORM_RELOCATED + "http/TlsTrust"), "the trust links to the relocated TlsTrust");
            // HttpCore travels inside platform, relocated twice: under platform's package, then under this plugin's.
            assertTrue(entries.stream().anyMatch(e -> e.getName().startsWith(PLATFORM_RELOCATED + "http/internal/hc5/")),
                    "HttpCore is shaded in under the plugin's copy of platform");
            assertTrue(entries.stream().noneMatch(e -> e.getName().startsWith("org/apache/hc/")), "no unrelocated HttpCore");
        }
        assertEquals(List.of(), named, "classes that still name platform's unrelocated package");
    }

    /**
     * The shading clean-up (package PLG, H-RAR-1): every class is the plugin's own or one of the three bundled libraries
     * under this plugin's relocated packages - Jackson, rar-model and platform, with the HttpCore platform carries - and
     * no class, multi-release copies included, keeps an unrelocated name or links to one. The README lists the same.
     */
    @Test
    void everyClassIsThePluginsOwnOrRelocated() throws IOException {
        Set<String> packages = new TreeSet<>();
        List<String> unrelocated = new ArrayList<>();
        try (ZipFile jar = new ZipFile(JAR.toFile())) {
            for (ZipEntry entry : jar.stream().toList()) {
                String name = entry.getName();
                if (name.startsWith("com/fasterxml/") || name.contains("/com/fasterxml/") || name.startsWith("META-INF/versions/")) {
                    unrelocated.add(name);
                }
                if (!name.endsWith(".class")) {
                    continue;
                }
                packages.add(topOf(name));
                String text = new String(read(jar, entry), StandardCharsets.ISO_8859_1);
                if (text.contains("com/fasterxml/") || text.contains("Lcom/fasterxml/") || linksOutsideThePlugin(text)) {
                    unrelocated.add(name + " (links to an unrelocated name)");
                }
            }
        }
        assertEquals(List.of(), unrelocated, "unrelocated classes, multi-release copies or links");
        assertEquals(new TreeSet<>(List.of("au/idp/rar/", "com/pingidentity/ps/oidf/rar/",
                "com/pingidentity/ps/oidf/rar/shaded/jackson/", "com/pingidentity/ps/oidf/rar/shaded/platform/",
                "com/pingidentity/ps/oidf/rar/shaded/rarmodel/")), packages, "what the jar carries");
    }

    /** No resource is in the jar twice, each service file is Jackson's relocated, and both event indexes are read. */
    @Test
    void serviceFilesAreRelocatedOnceAndTheEventIndexesAppended() throws IOException {
        List<String> names = new ArrayList<>();
        Set<String> services = new TreeSet<>();
        String index;
        try (ZipFile jar = new ZipFile(JAR.toFile())) {
            for (ZipEntry entry : jar.stream().toList()) {
                names.add(entry.getName());
                if (entry.getName().startsWith("META-INF/services/") && !entry.isDirectory()) {
                    String service = entry.getName().substring("META-INF/services/".length());
                    services.add(service);
                    for (String line : new String(read(jar, entry), StandardCharsets.UTF_8).lines().toList()) {
                        String implementation = line.strip();
                        if (!implementation.isEmpty() && !implementation.startsWith("#")) {
                            assertTrue(jar.getEntry(implementation.replace('.', '/') + ".class") != null,
                                    service + " names " + implementation + ", which is not in the jar");
                        }
                    }
                }
            }
            index = new String(read(jar, jar.getEntry("META-INF/oidf-events/index.txt")), StandardCharsets.UTF_8);
        }
        assertEquals(names.size(), new LinkedHashSet<>(names).size(), "a resource twice in the jar");
        for (String service : services) {
            assertTrue(service.startsWith("com.pingidentity.ps.oidf.rar.shaded."), service + " is not relocated");
        }
        List<String> components = index.lines().map(String::strip).filter(l -> !l.isEmpty() && !l.startsWith("#")).toList();
        assertEquals(List.of("rar", "platform"), components, "the plugin's index with platform's appended");
    }

    /** The first package level that says whose a class is: the plugin's own, or one bundled library. */
    private static String topOf(String name) {
        String shaded = "com/pingidentity/ps/oidf/rar/shaded/";
        if (name.startsWith(shaded)) {
            return shaded + name.substring(shaded.length(), name.indexOf('/', shaded.length()) + 1);
        }
        return name.substring(0, name.lastIndexOf('/') + 1);
    }

    /** Whether a class's bytes name a class of this repository outside the plugin's own package. */
    private static boolean linksOutsideThePlugin(String text) {
        int at = text.indexOf("com/pingidentity/ps/oidf/");
        while (at >= 0) {
            if (!text.startsWith("com/pingidentity/ps/oidf/rar/", at)) {
                return true;
            }
            at = text.indexOf("com/pingidentity/ps/oidf/", at + 1);
        }
        return false;
    }

    @Test
    void theRelocatedProfileReadsTheRuleAsPlatformDoes() throws Exception {
        try (URLClassLoader loader = new URLClassLoader(new URL[] {JAR.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            Class<?> profile = loader.loadClass(PLATFORM_RELOCATED.replace('/', '.') + "profile.DeploymentProfile");
            for (String value : new String[] {null, "development", " Development ", "staging"}) {
                Object parsed = profile.getMethod("parse", String.class).invoke(null, value);
                assertEquals(com.pingidentity.ps.oidf.platform.profile.DeploymentProfile.parse(value).value(),
                        profile.getMethod("value").invoke(parsed), String.valueOf(value));
            }
        }
    }

    @Test
    void theRelocatedModelComputesTheLibrarysFingerprint() throws Exception {
        // A loader with no parent but the JDK's: only the jar's own classes, as PingFederate's isolated loader sees them.
        try (URLClassLoader loader = new URLClassLoader(new URL[] {JAR.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            Class<?> models = loader.loadClass(RELOCATED.replace('/', '.') + "RarModels");
            Object builtIn = models.getMethod("builtIn").invoke(null);
            assertEquals(RarModels.builtIn().fingerprint(), models.getMethod("fingerprint").invoke(builtIn));
            assertEquals(RarModels.builtIn().canonicalJson(), models.getMethod("canonicalJson").invoke(builtIn));
        }
    }
}
