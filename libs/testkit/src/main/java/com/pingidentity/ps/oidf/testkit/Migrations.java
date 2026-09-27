/*
 * Applies a module's shipped db/migration scripts to a test database, in version order, with plain JDBC.
 */
package com.pingidentity.ps.oidf.testkit;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.JarURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.sql.DataSource;

/**
 * The shipped migrations, run the way a deployment runs them: every {@code V<version>__<description>.sql} under
 * {@code db/migration} on the classpath, in version order, each script in its own transaction. Versions compare
 * part by part as numbers ({@code V1.10} after {@code V1.9}), as Flyway compares them. A family is a range of
 * major versions (plan decision 11: federation V100-V199, agent V200-V299, and so on), so a module whose test
 * classpath carries another module's migrations applies only its own.
 *
 * <p>Nothing is recorded in the database: there is no history table. Running migrations is DB-3's
 * {@code tools/db-migrate} (Flyway), not this; this only puts the shipped DDL under test.
 */
public final class Migrations {

    /** Where the modules keep their migrations, as Flyway's default location. */
    public static final String LOCATION = "db/migration";

    private static final Pattern VERSIONED = Pattern.compile("V(\\d+(?:[._]\\d+)*)__[^/]+\\.sql");

    /** One script: its version (dots only), its file name, and where to read it. */
    public record Script(String version, String fileName, URL url) {
    }

    private Migrations() {
    }

    /**
     * Applies every migration under {@link #LOCATION} whose major version is in {@code [first, last]}, in version
     * order. Returns the file names applied, so a test can assert it ran the scripts it meant to.
     */
    public static List<String> apply(DataSource dataSource, long first, long last) throws IOException, SQLException {
        List<String> applied = new ArrayList<>();
        for (Script script : find(Migrations.class.getClassLoader(), LOCATION)) {
            if (inFamily(script.version(), first, last)) {
                run(dataSource, script.fileName(), read(script.url()));
                applied.add(script.fileName());
            }
        }
        return applied;
    }

    /**
     * Applies classpath resources in the order given - for scripts that are not versioned migrations, such as
     * the Identity Object Model's vendored {@code /idm/*.sql}. Each resource is resolved against {@code anchor}.
     */
    public static void applyResources(DataSource dataSource, Class<?> anchor, String... resources)
            throws IOException, SQLException {
        for (String resource : resources) {
            URL url = anchor.getResource(resource);
            if (url == null) {
                throw new IOException("no such resource on the test classpath: " + resource);
            }
            run(dataSource, resource, read(url));
        }
    }

    /** Every versioned migration directly under {@code location} on the loader's classpath, in version order. */
    public static List<Script> find(ClassLoader loader, String location) throws IOException {
        List<Script> found = new ArrayList<>();
        for (URL root : Collections.list(loader.getResources(location))) {
            if ("jar".equals(root.getProtocol())) {
                fromJar(root, location, found);
            } else {
                fromDirectory(root, found);
            }
        }
        return order(found);
    }

    private static void fromDirectory(URL root, List<Script> found) throws IOException {
        Path dir;
        try {
            dir = Path.of(root.toURI());
        } catch (URISyntaxException e) {
            throw new IOException("unreadable migration location " + root, e);
        }
        try (Stream<Path> files = Files.list(dir)) {
            for (Path file : (Iterable<Path>) files::iterator) {
                String fileName = file.getFileName().toString();
                Optional<String> version = version(fileName);
                if (version.isPresent()) {
                    found.add(new Script(version.get(), fileName, file.toUri().toURL()));
                }
            }
        }
    }

    private static void fromJar(URL root, String location, List<Script> found) throws IOException {
        URLConnection connection = root.openConnection();
        connection.setUseCaches(false);
        String prefix = location.endsWith("/") ? location : location + "/";
        URL jar = ((JarURLConnection) connection).getJarFileURL();
        try (JarFile file = ((JarURLConnection) connection).getJarFile()) {
            for (Enumeration<JarEntry> entries = file.entries(); entries.hasMoreElements(); ) {
                String entry = entries.nextElement().getName();
                if (entry.startsWith(prefix) && entry.indexOf('/', prefix.length()) < 0) {
                    String fileName = entry.substring(prefix.length());
                    Optional<String> version = version(fileName);
                    if (version.isPresent()) {
                        found.add(new Script(version.get(), fileName, URI.create("jar:" + jar + "!/" + entry).toURL()));
                    }
                }
            }
        }
    }

    /** The version of a versioned migration's file name, with {@code _} separators as dots; empty for any other file. */
    static Optional<String> version(String fileName) {
        Matcher m = VERSIONED.matcher(fileName);
        return m.matches() ? Optional.of(m.group(1).replace('_', '.')) : Optional.empty();
    }

    /** Numeric, part by part; a version that runs out of parts first is the lower ({@code 1} before {@code 1.0.1}). */
    static int compare(String a, String b) {
        String[] x = a.split("\\.");
        String[] y = b.split("\\.");
        for (int i = 0; i < Math.min(x.length, y.length); i++) {
            int c = new BigInteger(x[i]).compareTo(new BigInteger(y[i]));
            if (c != 0) {
                return c;
            }
        }
        return Integer.compare(x.length, y.length);
    }

    /** Sorted by version; two scripts with one version are refused, as Flyway refuses them. */
    static List<Script> order(List<Script> scripts) {
        List<Script> sorted = new ArrayList<>(scripts);
        sorted.sort((p, q) -> compare(p.version(), q.version()));
        for (int i = 1; i < sorted.size(); i++) {
            if (compare(sorted.get(i - 1).version(), sorted.get(i).version()) == 0) {
                throw new IllegalStateException("two migrations have version " + sorted.get(i).version() + ": "
                        + sorted.get(i - 1).url() + " and " + sorted.get(i).url());
            }
        }
        return sorted;
    }

    /** Whether the version's major part is in {@code [first, last]}. */
    static boolean inFamily(String version, long first, long last) {
        int dot = version.indexOf('.');
        long major = Long.parseLong(dot < 0 ? version : version.substring(0, dot));
        return major >= first && major <= last;
    }

    private static String read(URL url) throws IOException {
        URLConnection connection = url.openConnection();
        connection.setUseCaches(false);
        try (InputStream in = connection.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** One script, one transaction: a script that fails leaves nothing of itself behind. */
    private static void run(DataSource dataSource, String name, String sql) throws SQLException {
        try (Connection c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try (Statement s = c.createStatement()) {
                s.execute(sql);
                c.commit();
            } catch (SQLException e) {
                c.rollback();
                throw new SQLException("migration " + name + " failed: " + e.getMessage(), e.getSQLState(), e);
            }
        }
    }
}
