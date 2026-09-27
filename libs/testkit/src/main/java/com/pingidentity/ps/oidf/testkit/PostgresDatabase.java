/*
 * A PostgreSQL database of its own for each test class, created before the class and dropped after it.
 */
package com.pingidentity.ps.oidf.testkit;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Random;
import javax.sql.DataSource;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Gives the test class it is registered on a database nobody else uses: created in {@code beforeAll} with a
 * unique name ({@code oidf_test_<class>_<random>}), dropped in {@code afterAll}, on the server
 * {@link PostgresServer} finds - {@code OIDF_TEST_JDBC_URL}, else one Testcontainers container per JVM, else the
 * class is skipped (failed under {@code CI=true}). Classes in one JVM, and builds in several worktrees against one
 * server, share nothing but the server.
 *
 * <pre>{@code
 * @RegisterExtension
 * static final PostgresDatabase POSTGRES = new PostgresDatabase();
 *
 * @BeforeAll
 * static void schema() throws Exception {
 *     Migrations.apply(POSTGRES.dataSource(), 100, 199);
 * }
 * }</pre>
 *
 * Register it as a {@code static} field of the concrete test class, so that {@code beforeAll} runs before the
 * class's own {@code @BeforeAll} methods and each class gets its own instance. A class that needs a clean schema
 * per test calls {@link #resetPublicSchema()} and re-applies its migrations; that is milliseconds on Postgres.
 */
public final class PostgresDatabase implements ExecutionCondition, BeforeAllCallback, AfterAllCallback {

    static final String PREFIX = "oidf_test_";
    /** Postgres truncates identifiers at 63 bytes; the prefix, the class and the suffix fit inside it. */
    static final int MAX_CLASS_PART = 63 - PREFIX.length() - 1 - 12;

    private static final Random RANDOM = new SecureRandom();

    private PostgresServer server;
    private String name;
    private DataSource dataSource;

    /**
     * With no server and no Docker, the class is disabled here rather than aborted in {@code beforeAll}: a disabled
     * class is reported as skipped, where an aborted one vanishes from surefire's counts (3.2.5, seen 2026-09-28).
     * Under {@code CI=true} it is not disabled, and {@code beforeAll} fails it.
     */
    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
        String skip = PostgresServer.skipReason();
        return skip == null ? ConditionEvaluationResult.enabled("a PostgreSQL server is available")
                : ConditionEvaluationResult.disabled(skip);
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        PostgresServer found = PostgresServer.shared();
        String database = databaseNameFor(context.getRequiredTestClass(), RANDOM);
        found.createDatabase(database);
        this.server = found;
        this.name = database;
        this.dataSource = found.dataSource(database);
    }

    @Override
    public void afterAll(ExtensionContext context) {
        if (this.name != null) {
            this.server.dropDatabase(this.name);
        }
        this.server = null;
        this.name = null;
        this.dataSource = null;
    }

    /** The class's own database. Connections are unpooled: each {@code getConnection()} opens one. */
    public DataSource dataSource() {
        if (this.dataSource == null) {
            throw new IllegalStateException("no test database: register PostgresDatabase as a static @RegisterExtension "
                    + "field of the test class, and use it only while that class runs");
        }
        return this.dataSource;
    }

    /** The name of the class's database, for a test that asserts on it or connects some other way. */
    public String databaseName() {
        dataSource();
        return this.name;
    }

    /** Drops everything in the {@code public} schema: for a class whose tests each start from an empty schema. */
    public void resetPublicSchema() throws SQLException {
        try (Connection c = dataSource().getConnection(); Statement s = c.createStatement()) {
            s.execute("DROP SCHEMA public CASCADE");
            s.execute("CREATE SCHEMA public");
        }
    }

    /** {@code oidf_test_}, the class's simple name folded to a Postgres identifier, and 48 random bits. */
    static String databaseNameFor(Class<?> testClass, Random random) {
        String folded = testClass.getSimpleName().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "_");
        if (folded.isEmpty()) {
            folded = "anonymous";
        }
        if (folded.length() > MAX_CLASS_PART) {
            folded = folded.substring(0, MAX_CLASS_PART);
        }
        byte[] suffix = new byte[6];
        random.nextBytes(suffix);
        return PREFIX + folded + "_" + HexFormat.of().formatHex(suffix);
    }
}
