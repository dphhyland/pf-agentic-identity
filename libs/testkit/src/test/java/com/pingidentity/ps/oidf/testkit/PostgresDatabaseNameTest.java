package com.pingidentity.ps.oidf.testkit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;
import org.junit.jupiter.api.Test;

/** The database each class gets is named for it, unique, and a legal Postgres identifier - no database needed. */
class PostgresDatabaseNameTest {

    private static final String LEGAL = "[a-z0-9_]{1,63}";

    @Test
    void aClassesDatabaseIsNamedForItWithARandomSuffix() {
        String name = PostgresDatabase.databaseNameFor(PostgresDatabaseNameTest.class, new Random(1));

        assertTrue(name.startsWith("oidf_test_postgresdatabasenametest_"), name);
        assertTrue(name.matches("oidf_test_postgresdatabasenametest_[0-9a-f]{12}"), name);
        assertNotEquals(name, PostgresDatabase.databaseNameFor(PostgresDatabaseNameTest.class, new Random(2)),
                "two runs of one class against one server must not collide");
    }

    @Test
    void aLongClassNameIsCutSoTheWholeNameFitsInAnIdentifier() {
        String name = PostgresDatabase.databaseNameFor(
                AClassWithANameSoLongThatTheDatabaseNameWouldRunPastSixtyThreeBytes.class, new Random(1));

        assertEquals(63, name.length(), name);
        assertTrue(name.matches(LEGAL), name);
    }

    @Test
    void whatAnIdentifierCannotHoldBecomesAnUnderscore() {
        assertTrue(PostgresDatabase.databaseNameFor(Odd$Name.class, new Random(1)).startsWith("oidf_test_odd_name_"));
    }

    @Test
    void anAnonymousClassStillGetsAName() {
        Object anonymous = new Object() { };
        String name = PostgresDatabase.databaseNameFor(anonymous.getClass(), new Random(1));

        assertTrue(name.startsWith("oidf_test_anonymous_"), name);
        assertTrue(name.matches(LEGAL), name);
    }

    @Test
    void theDataSourceIsRefusedOutsideTheClassItServes() {
        PostgresDatabase unregistered = new PostgresDatabase();

        IllegalStateException e = assertThrows(IllegalStateException.class, unregistered::dataSource);
        assertTrue(e.getMessage().contains("static @RegisterExtension"), e.getMessage());
        assertThrows(IllegalStateException.class, unregistered::databaseName);
    }

    private static final class AClassWithANameSoLongThatTheDatabaseNameWouldRunPastSixtyThreeBytes {
    }

    @SuppressWarnings("checkstyle:TypeName")
    private static final class Odd$Name {
    }
}
