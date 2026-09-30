package com.pingidentity.ps.oidf.testkit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.RegisterExtension;

/** The extension against a live Postgres: the database is this class's, the migrations run in order, and it goes. */
class PostgresDatabaseTest {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    @BeforeEach
    void empty() throws SQLException {
        POSTGRES.resetPublicSchema();
    }

    @Test
    void theClassIsConnectedToADatabaseOfItsOwn() throws SQLException {
        assertTrue(POSTGRES.databaseName().startsWith("oidf_test_postgresdatabasetest_"), POSTGRES.databaseName());
        assertEquals(POSTGRES.databaseName(), scalar(POSTGRES.dataSource(), "SELECT current_database()"));
    }

    @Test
    void aFamilysMigrationsRunInVersionOrderAndNoOthers() throws Exception {
        List<String> applied = Migrations.apply(POSTGRES.dataSource(), 1, 99);

        assertEquals(List.of("V1__probe.sql", "V2__probe_row.sql"), applied, "V2 inserts into V1's table, so order matters");
        assertEquals("from V2", scalar(POSTGRES.dataSource(), "SELECT note FROM probe WHERE id = 1"));
        assertFalse(tableExists("probe_other_family"), "V300 is another family's");

        assertEquals(List.of("V300__other_family.sql"), Migrations.apply(POSTGRES.dataSource(), 300, 399));
        assertTrue(tableExists("probe_other_family"));
    }

    @Test
    void resettingThePublicSchemaLeavesNothingBehind() throws Exception {
        Migrations.apply(POSTGRES.dataSource(), 1, 99);
        assertTrue(tableExists("probe"));

        POSTGRES.resetPublicSchema();

        assertFalse(tableExists("probe"));
        assertEquals(List.of("V1__probe.sql", "V2__probe_row.sql"), Migrations.apply(POSTGRES.dataSource(), 1, 99),
                "and the migrations apply again from the start");
    }

    @Test
    void aScriptThatFailsIsNamedAndLeavesNothingOfItselfBehind() throws SQLException {
        SQLException e = assertThrows(SQLException.class,
                () -> Migrations.applyResources(POSTGRES.dataSource(), getClass(), "/testkit-bad/half.sql"));

        assertTrue(e.getMessage().startsWith("migration /testkit-bad/half.sql failed"), e.getMessage());
        assertFalse(tableExists("half_applied"), "one script, one transaction");
    }

    @Test
    void resourcesRunInTheOrderGivenAndAMissingOneIsRefused() throws Exception {
        Migrations.applyResources(POSTGRES.dataSource(), getClass(), "/db/migration/V1__probe.sql",
                "/db/migration/V2__probe_row.sql");
        assertEquals("from V2", scalar(POSTGRES.dataSource(), "SELECT note FROM probe WHERE id = 1"));

        IOException e = assertThrows(IOException.class,
                () -> Migrations.applyResources(POSTGRES.dataSource(), getClass(), "/no/such.sql"));
        assertTrue(e.getMessage().contains("/no/such.sql"), e.getMessage());
    }

    /** Created before its class and dropped after it: a server that many builds share does not fill up. */
    @Test
    void anotherClassesDatabaseIsCreatedApartAndDroppedAfterIt() throws Exception {
        ExtensionContext context = mock(ExtensionContext.class);
        when(context.getRequiredTestClass()).thenAnswer(invocation -> MigrationsTest.class);
        PostgresDatabase other = new PostgresDatabase();

        other.beforeAll(context);
        String name = other.databaseName();
        assertTrue(name.startsWith("oidf_test_migrationstest_"), name);
        assertEquals(name, scalar(other.dataSource(), "SELECT current_database()"));
        assertTrue(databaseExists(name));
        Connection leftOpen = other.dataSource().getConnection();

        other.afterAll(context);

        assertFalse(databaseExists(name), "dropped, even with a connection a test left open");
        assertTrue(leftOpen.isClosed() || !leftOpen.isValid(2));
        assertThrows(IllegalStateException.class, other::dataSource);
        other.afterAll(context); // a second afterAll is harmless
    }

    private static boolean tableExists(String table) throws SQLException {
        return "1".equals(scalar(POSTGRES.dataSource(),
                "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '" + table + "'"));
    }

    private static boolean databaseExists(String name) throws SQLException {
        try (Connection c = POSTGRES.dataSource().getConnection();
                PreparedStatement ps = c.prepareStatement("SELECT 1 FROM pg_database WHERE datname = ?")) {
            ps.setString(1, name);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static String scalar(DataSource ds, String sql) throws SQLException {
        try (Connection c = ds.getConnection(); Statement s = c.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            assertTrue(rs.next());
            return rs.getString(1);
        }
    }
}
