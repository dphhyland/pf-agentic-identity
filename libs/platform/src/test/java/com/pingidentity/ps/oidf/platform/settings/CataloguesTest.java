package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Finding every catalogue a loader sees: listed in a directory and in a jar, found by the table's name in a jar with
 * no directory entries, and a catalogue that cannot be loaded reported rather than thrown.
 */
class CataloguesTest {

    @TempDir
    Path dir;

    static String named(String component) {
        return "{\"format\": 1, \"component\": \"" + component + "\", \"module\": \"libs/platform\","
                + " \"package\": \"com.pingidentity.ps.oidf.platform.settings\", \"families\": [], \"settings\": [], \"removed\": []}";
    }

    private Path jar(String name, boolean directoryEntries, String... components) throws IOException {
        Path jar = this.dir.resolve(name);
        try (OutputStream out = Files.newOutputStream(jar); JarOutputStream j = new JarOutputStream(out)) {
            if (directoryEntries) {
                j.putNextEntry(new JarEntry("META-INF/"));
                j.putNextEntry(new JarEntry(Catalogue.RESOURCE_DIRECTORY));
            }
            for (String component : components) {
                j.putNextEntry(new JarEntry(Catalogue.RESOURCE_DIRECTORY + component + ".json"));
                j.write(named(component).getBytes(StandardCharsets.UTF_8));
            }
            j.putNextEntry(new JarEntry(Catalogue.RESOURCE_DIRECTORY + "README.txt"));
            j.putNextEntry(new JarEntry(Catalogue.RESOURCE_DIRECTORY + "Not-A-Name.json"));
        }
        return jar;
    }

    private static List<String> names(Catalogues.Loaded loaded) {
        return loaded.catalogues().stream().map(Catalogue::component).toList();
    }

    @Test
    void aJarsAndADirectorysCataloguesAreListedAndLoaded() throws IOException {
        Path classes = this.dir.resolve("classes");
        Files.createDirectories(classes.resolve(Catalogue.RESOURCE_DIRECTORY));
        Files.writeString(classes.resolve(Catalogue.RESOURCE_DIRECTORY + "from-dir.json"), named("from-dir"));
        Files.writeString(classes.resolve(Catalogue.RESOURCE_DIRECTORY + "notes.txt"), "not a catalogue");
        Path jar = jar("a.jar", true, "from-jar");
        try (URLClassLoader loader = new URLClassLoader(new URL[] {classes.toUri().toURL(), jar.toUri().toURL()}, null)) {
            Catalogues.Loaded loaded = Catalogues.onClassPath(loader);
            assertEquals(List.of("from-dir", "from-jar"), names(loaded));
            assertEquals(List.of(), loaded.problems());
        }
    }

    @Test
    void theTablesNamesAreFoundInAJarWithNoDirectoryEntries() throws IOException {
        Path jar = jar("b.jar", false, "ssf-transmitter", "unlisted");
        try (URLClassLoader loader = new URLClassLoader(new URL[] {jar.toUri().toURL()}, null)) {
            assertEquals(List.of("ssf-transmitter"), names(Catalogues.onClassPath(loader)),
                    "a name the table does not know needs a directory entry to be listed");
        }
    }

    @Test
    void aCatalogueThatCannotBeLoadedIsAProblemAndTheRestLoad() throws IOException {
        Path one = jar("one.jar", true, "ssf-transmitter", "fine");
        Path other = this.dir.resolve("other.jar");
        try (OutputStream out = Files.newOutputStream(other); JarOutputStream j = new JarOutputStream(out)) {
            j.putNextEntry(new JarEntry(Catalogue.RESOURCE_DIRECTORY + "ssf-transmitter.json"));
            j.write(named("ssf-transmitter").replace("\"families\": []", "\"families\": [\"OIDF_SSF_\"]").getBytes(StandardCharsets.UTF_8));
        }
        try (URLClassLoader loader = new URLClassLoader(new URL[] {one.toUri().toURL(), other.toUri().toURL()}, null)) {
            Catalogues.Loaded loaded = Catalogues.onClassPath(loader);
            assertEquals(List.of("fine"), names(loaded));
            assertEquals(1, loaded.problems().size());
            assertEquals("ssf-transmitter", loaded.problems().get(0).component());
            assertTrue(loaded.problems().get(0).message().contains("differ; a catalogue has exactly one owning module"),
                    loaded.problems().get(0).message());
        }
    }

    @Test
    void aListingThatCannotBeReadAddsNothing() throws IOException {
        ClassLoader failing = new ClassLoader(null) {
            @Override
            public Enumeration<URL> getResources(String name) throws IOException {
                throw new IOException("unreadable");
            }
        };
        assertEquals(Collections.emptySet(), Catalogues.listed(failing));
        ClassLoader odd = new ClassLoader(null) {
            @Override
            public Enumeration<URL> getResources(String name) throws IOException {
                return Collections.enumeration(List.of(new URL("file:/no/such/directory/"), new URL("http://example.com/x/"),
                        new URL("jar:file:/no/such.jar!/META-INF/oidf-settings/")));
            }
        };
        assertEquals(Collections.emptySet(), Catalogues.listed(odd), "a missing directory, another protocol, a missing jar");
    }

    @Test
    void thisClassPathsCataloguesIncludePlatformsOwnAndTheWorkedExample() {
        List<String> names = names(Catalogues.onClassPath(getClass().getClassLoader()));
        assertTrue(names.containsAll(List.of("components", "deployment-profile", "example", "platform-redis")), names.toString());
    }
}
