/*
 * The one PostgreSQL server a test JVM uses: the one the environment names, or one Testcontainers starts.
 */
package com.pingidentity.ps.oidf.testkit;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import javax.sql.DataSource;
import org.junit.jupiter.api.extension.ExtensionConfigurationException;
import org.opentest4j.TestAbortedException;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Where the tests' PostgreSQL comes from, decided once per JVM, in this order:
 * <ol>
 *   <li>{@value #URL} (with {@value #USER} and {@value #PASSWORD}): a server the build can reach, whose user may
 *       {@code CREATE DATABASE}. CI's service container, or one you started. The {@code IDM_TEST_JDBC_*} names
 *       device-instance used before are read as aliases for 0.5.0, with a warning, and go after it.</li>
 *   <li>Otherwise Testcontainers, when Docker answers: one {@value #IMAGE} container for the whole JVM.</li>
 *   <li>Otherwise none: the class is skipped with a message naming CONTRIBUTING.md's recipe - except where
 *       {@code CI=true}, where it fails, so a CI job that lost its database cannot go green by skipping.</li>
 * </ol>
 */
final class PostgresServer {

    static final String URL = "OIDF_TEST_JDBC_URL";
    static final String USER = "OIDF_TEST_JDBC_USER";
    static final String PASSWORD = "OIDF_TEST_JDBC_PASSWORD";
    static final String LEGACY_PREFIX = "IDM_TEST_JDBC_";
    static final String IMAGE = "postgres:16-alpine";
    static final String RECIPE = "see CONTRIBUTING.md, \"Tests that need Postgres\"";

    private static final System.Logger LOG = System.getLogger(PostgresServer.class.getName());

    /** What the environment gives: a named server, a container to start, or nothing (skip or fail). */
    enum Kind { EXTERNAL, CONTAINER, SKIP, FAIL }

    record Resolution(Kind kind, String url, String user, String password, List<String> warnings, String message) {
    }

    private static PostgresServer shared;
    private static Resolution sharedResolution;

    private final String url;
    private final String user;
    private final String password;

    private PostgresServer(String url, String user, String password) {
        this.url = url;
        this.user = user;
        this.password = password;
    }

    /**
     * The server for this JVM, resolved and (for a container) started on first use. Throws
     * {@link TestAbortedException} to skip the calling class, or {@link ExtensionConfigurationException} to fail
     * it, when there is none.
     */
    static synchronized PostgresServer shared() {
        Resolution r = sharedResolution();
        switch (r.kind()) {
            case SKIP:
                throw new TestAbortedException(r.message());
            case FAIL:
                throw new ExtensionConfigurationException(r.message());
            default:
                break;
        }
        if (shared == null) {
            shared = r.kind() == Kind.EXTERNAL ? new PostgresServer(r.url(), r.user(), r.password()) : startContainer();
        }
        return shared;
    }

    /** Why the tests are skipped in this JVM, or null when they run (or fail). */
    static synchronized String skipReason() {
        Resolution r = sharedResolution();
        return r.kind() == Kind.SKIP ? r.message() : null;
    }

    private static synchronized Resolution sharedResolution() {
        if (sharedResolution == null) {
            sharedResolution = resolve(System::getenv, () -> DockerClientFactory.instance().isDockerAvailable());
            sharedResolution.warnings().forEach(w -> LOG.log(System.Logger.Level.WARNING, w));
        }
        return sharedResolution;
    }

    /** The decision itself, from an environment and a Docker probe that is asked only when no server is named. */
    static Resolution resolve(Function<String, String> env, BooleanSupplier dockerAvailable) {
        List<String> warnings = new ArrayList<>();
        String url = setting(env, URL, warnings);
        String user = setting(env, USER, warnings);
        String password = setting(env, PASSWORD, warnings);
        if (url != null) {
            if (!url.startsWith("jdbc:postgresql:")) {
                return new Resolution(Kind.FAIL, null, null, null, warnings, URL + " must be a jdbc:postgresql: URL: "
                        + "the tests run on PostgreSQL only (H2 and HSQLDB were dropped in 0.5.0); " + RECIPE);
            }
            return new Resolution(Kind.EXTERNAL, url, user, password, warnings, null);
        }
        if (dockerAvailable.getAsBoolean()) {
            return new Resolution(Kind.CONTAINER, null, null, null, warnings, null);
        }
        String message = "no PostgreSQL for this test class: set " + URL + " (with " + USER + " and " + PASSWORD
                + ") to a server whose user may CREATE DATABASE, or make Docker reachable for Testcontainers; " + RECIPE;
        if ("true".equalsIgnoreCase(env.apply("CI"))) {
            return new Resolution(Kind.FAIL, null, null, null, warnings,
                    message + ". CI=true, so this fails rather than skips: a store suite that did not run is not a pass");
        }
        return new Resolution(Kind.SKIP, null, null, null, warnings, message);
    }

    /** A variable, or its deprecated {@code IDM_TEST_JDBC_*} alias with a warning; blank counts as unset. */
    static String setting(Function<String, String> env, String name, List<String> warnings) {
        String value = env.apply(name);
        if (value != null && !value.isBlank()) {
            return value;
        }
        String legacyName = LEGACY_PREFIX + name.substring(name.lastIndexOf('_') + 1);
        String legacy = env.apply(legacyName);
        if (legacy == null || legacy.isBlank()) {
            return null;
        }
        warnings.add(legacyName + " is deprecated: set " + name + " instead (the old name is read in 0.5.x only)");
        return legacy;
    }

    private static PostgresServer startContainer() {
        PostgreSQLContainer<?> container = new PostgreSQLContainer<>(DockerImageName.parse(IMAGE));
        container.start();
        // Testcontainers' reaper removes it when the JVM exits; the hook covers a run with the reaper turned off.
        Runtime.getRuntime().addShutdownHook(new Thread(container::stop, "testkit-postgres-stop"));
        return new PostgresServer(container.getJdbcUrl(), container.getUsername(), container.getPassword());
    }

    /** A data source on the database the server's URL names, for creating and dropping the others. */
    DataSource admin() {
        return dataSource(null);
    }

    /** A data source on the named database of this server, with the server's credentials. */
    PGSimpleDataSource dataSource(String database) {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(this.url);
        if (database != null) {
            ds.setDatabaseName(database);
        }
        if (this.user != null) {
            ds.setUser(this.user);
        }
        if (this.password != null) {
            ds.setPassword(this.password);
        }
        return ds;
    }

    void createDatabase(String name) {
        try (Connection c = admin().getConnection(); Statement s = c.createStatement()) {
            s.execute("CREATE DATABASE \"" + name + "\"");
        } catch (SQLException e) {
            throw new ExtensionConfigurationException("could not create the test database " + name + " on "
                    + this.redactedUrl() + " (" + e.getMessage() + "): the user needs CREATEDB, or name another server; "
                    + RECIPE, e);
        }
    }

    /** Drops the database, closing whatever connections a test left open. A failure is logged, not thrown. */
    void dropDatabase(String name) {
        try (Connection c = admin().getConnection(); Statement s = c.createStatement()) {
            s.execute("DROP DATABASE IF EXISTS \"" + name + "\" WITH (FORCE)");
        } catch (SQLException e) {
            LOG.log(System.Logger.Level.WARNING, "could not drop the test database " + name + " on " + this.redactedUrl()
                    + ": " + e.getMessage() + " - drop it by hand (every test database is named oidf_test_*)");
        }
    }

    /** The URL without its query, which is where a password in the URL would be. */
    String redactedUrl() {
        int q = this.url.indexOf('?');
        return q < 0 ? this.url : this.url.substring(0, q);
    }
}
