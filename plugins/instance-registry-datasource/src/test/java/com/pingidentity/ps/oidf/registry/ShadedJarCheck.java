package com.pingidentity.ps.oidf.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.junit.jupiter.api.Test;

/**
 * The jar PingFederate loads, as the shade plugin wrote it: platform is inside under this plugin's relocated
 * package and nowhere under its own, no class still names the unrelocated package, the relocated profile reads the
 * rule as platform does, and the relocated settings find the instance-registry catalogue in the jar. Run after
 * package by the pom's {@code shaded-jar} execution, as ciba-sim's is.
 */
class ShadedJarCheck {

    private static final Path JAR = Path.of("target", "pf.plugins.instance-registry-datasource.jar");
    private static final String PLATFORM = "com/pingidentity/ps/oidf/platform/";
    private static final String RELOCATED = "com/pingidentity/ps/oidf/registry/shaded/platform/";

    private static byte[] read(ZipFile jar, ZipEntry entry) throws IOException {
        try (InputStream in = jar.getInputStream(entry)) {
            return in.readAllBytes();
        }
    }

    @Test
    void platformIsInTheJarUnderTheRelocatedPackageOnly() throws IOException {
        assertTrue(Files.isRegularFile(JAR), JAR.toAbsolutePath() + " is not there: run after package");
        List<String> named = new ArrayList<>();
        try (ZipFile jar = new ZipFile(JAR.toFile())) {
            List<? extends ZipEntry> entries = jar.stream().toList();
            assertTrue(entries.stream().anyMatch(e -> e.getName().equals(RELOCATED + "profile/DeploymentProfile.class")),
                    "the profile is shaded in");
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
            String driver = new String(read(jar, jar.getEntry("com/pingidentity/ps/oidf/registry/InstanceRegistryDataSource.class")),
                    StandardCharsets.ISO_8859_1);
            assertTrue(driver.contains(RELOCATED + "settings/Settings"), "the driver links to the relocated settings");
            assertTrue(entries.stream().noneMatch(e -> e.getName().startsWith("com/pingidentity/ps/oidf/device/")),
                    "device-instance is not shaded here (X-A20)");
        }
        assertEquals(List.of(), named, "classes that still name platform's unrelocated package");
    }

    @Test
    void theRelocatedProfileReadsTheRuleAsPlatformDoes() throws Exception {
        try (URLClassLoader loader = new URLClassLoader(new URL[] {JAR.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            Class<?> profile = loader.loadClass(RELOCATED.replace('/', '.') + "profile.DeploymentProfile");
            for (String value : new String[] {null, "development", " Development ", "staging"}) {
                Object parsed = profile.getMethod("parse", String.class).invoke(null, value);
                assertEquals(com.pingidentity.ps.oidf.platform.profile.DeploymentProfile.parse(value).value(),
                        profile.getMethod("value").invoke(parsed), String.valueOf(value));
            }
        }
    }

    @Test
    void theRelocatedSettingsReadTheCatalogueInTheJar() throws Exception {
        try (URLClassLoader loader = new URLClassLoader(new URL[] {JAR.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            Class<?> catalogue = loader.loadClass(RELOCATED.replace('/', '.') + "settings.Catalogue");
            Object loaded = catalogue.getMethod("load", ClassLoader.class, String.class).invoke(null, loader, InstanceRegistryDataSource.CATALOGUE);
            assertEquals(InstanceRegistryDataSource.CATALOGUE, catalogue.getMethod("component").invoke(loaded));
        }
    }
}
