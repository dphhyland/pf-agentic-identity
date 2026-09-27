package com.pingidentity.ps.oidf.testkit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Which files are migrations, and the order they run in - no database needed. */
class MigrationsTest {

    @Test
    void aVersionedMigrationsVersionIsItsNumberWithUnderscoresAsDots() {
        assertEquals(Optional.of("100"), Migrations.version("V100__hosted_entity.sql"));
        assertEquals(Optional.of("1.10"), Migrations.version("V1_10__ten.sql"));
        assertEquals(Optional.of("1.1"), Migrations.version("V1.1__two.sql"));
    }

    @Test
    void anythingElseIsNotAMigration() {
        for (String name : List.of("R__repeatable.sql", "V1_description.sql", "V__none.sql", "v1__lower.sql",
                "V1__x.txt", "README.md", "0000-base-schema.sql", "U1__undo.sql")) {
            assertEquals(Optional.empty(), Migrations.version(name), name);
        }
    }

    @Test
    void versionsCompareAsNumbersPartByPart() {
        assertTrue(Migrations.compare("1.10", "1.9") > 0, "1.10 comes after 1.9, not before it as text would have it");
        assertTrue(Migrations.compare("100", "99") > 0);
        assertTrue(Migrations.compare("1", "1.0.1") < 0, "a version that runs out of parts first is the lower");
        assertTrue(Migrations.compare("1.0.1", "1") > 0);
        assertEquals(0, Migrations.compare("1.01", "1.1"), "leading zeros are numbers, not text");
        assertTrue(Migrations.compare("99999999999999999999", "100") > 0, "wider than a long");
    }

    @Test
    void theOrderIsByVersionAndTwoScriptsWithOneVersionAreRefused() throws Exception {
        URL u = new URL("file:/x");
        List<Migrations.Script> sorted = Migrations.order(List.of(new Migrations.Script("1.10", "c", u),
                new Migrations.Script("1", "a", u), new Migrations.Script("1.9", "b", u)));
        assertEquals(List.of("a", "b", "c"), sorted.stream().map(Migrations.Script::fileName).toList());

        IllegalStateException e = assertThrows(IllegalStateException.class, () -> Migrations.order(List.of(
                new Migrations.Script("1.1", "V1.1__a.sql", u), new Migrations.Script("1.1", "V1_1__b.sql", u))));
        assertTrue(e.getMessage().contains("two migrations have version 1.1"), e.getMessage());
    }

    @Test
    void aFamilyIsARangeOfMajorVersions() {
        assertTrue(Migrations.inFamily("100", 100, 199));
        assertTrue(Migrations.inFamily("199.3", 100, 199));
        assertFalse(Migrations.inFamily("200", 100, 199));
        assertFalse(Migrations.inFamily("99.9", 100, 199));
    }

    @Test
    void migrationsAreFoundInADirectoryOnTheClasspath() throws Exception {
        List<Migrations.Script> found = Migrations.find(getClass().getClassLoader(), "testkit-migrations");

        assertEquals(List.of("V1__one.sql", "V1.1__two.sql", "V1_10__ten.sql", "V200__other_family.sql"),
                found.stream().map(Migrations.Script::fileName).toList());
    }

    /** A module's migrations reach another module's tests in a jar when the build did not run from the reactor. */
    @Test
    void migrationsAreFoundInAJarOnTheClasspath(@TempDir Path dir) throws Exception {
        Path jar = dir.resolve("migrations.jar");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
            for (String entry : List.of("db/", "db/migration/", "db/migration/V2__second.sql", "db/migration/V1__first.sql",
                    "db/migration/nested/V3__too_deep.sql", "db/migration/notes.txt", "db/other/V4__elsewhere.sql")) {
                out.putNextEntry(new JarEntry(entry));
                if (!entry.endsWith("/")) {
                    out.write(("-- " + entry).getBytes(StandardCharsets.UTF_8));
                }
                out.closeEntry();
            }
        }
        try (URLClassLoader loader = new URLClassLoader(new URL[] {jar.toUri().toURL()}, null)) {
            List<Migrations.Script> found = Migrations.find(loader, "db/migration");

            assertEquals(List.of("V1__first.sql", "V2__second.sql"), found.stream().map(Migrations.Script::fileName).toList());
            try (InputStream in = found.get(0).url().openStream()) {
                assertEquals("-- db/migration/V1__first.sql", new String(in.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
    }

    @Test
    void aLocationNowhereOnTheClasspathHasNoMigrations() throws Exception {
        assertEquals(List.of(), Migrations.find(getClass().getClassLoader(), "no/such/location"));
    }
}
