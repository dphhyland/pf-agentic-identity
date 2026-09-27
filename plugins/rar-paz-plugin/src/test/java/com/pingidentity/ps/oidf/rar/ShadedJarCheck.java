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
import java.util.List;
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
            String transport = new String(read(jar, jar.getEntry("com/pingidentity/ps/oidf/rar/JdkHttpTransport.class")),
                    StandardCharsets.ISO_8859_1);
            assertTrue(transport.contains(PLATFORM_RELOCATED + "tls/InsecureTls"), "the transport links to the relocated InsecureTls");
        }
        assertEquals(List.of(), named, "classes that still name platform's unrelocated package");
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
