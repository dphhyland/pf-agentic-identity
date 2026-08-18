/*
 * The environment plumbing that decides which directory this service writes to.
 */
package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * {@link Main#toJdbcUrl} — the one piece of startup wiring with a wrong answer rather than just a
 * missing one. Railway expands a database reference variable to a {@code postgresql://user:pass@host/db}
 * DSN, which the PostgreSQL JDBC driver does not accept; handing it over unconverted fails at the first
 * connection, long after the process reports healthy.
 */
class MainTest {

    @Test
    void aJdbcUrlIsPassedThrough() {
        assertEquals("jdbc:postgresql://db:5432/railway",
                Main.toJdbcUrl("jdbc:postgresql://db:5432/railway"));
        assertEquals("jdbc:postgresql://db:5432/railway",
                Main.toJdbcUrl("  jdbc:postgresql://db:5432/railway  "), "surrounding whitespace");
    }

    @Test
    void aRailwayDsnBecomesAJdbcUrlWithCredentialsAsParameters() {
        String jdbc = Main.toJdbcUrl("postgresql://postgres:secret@postgres-d8lj.railway.internal:5432/railway");
        assertTrue(jdbc.startsWith("jdbc:postgresql://postgres-d8lj.railway.internal:5432/railway?"), jdbc);
        assertTrue(jdbc.contains("user=postgres"), jdbc);
        assertTrue(jdbc.contains("password=secret"), jdbc);
    }

    /** Generated passwords routinely contain characters that are not URL-safe. */
    @Test
    void credentialsArePercentDecodedThenReEncoded() {
        String jdbc = Main.toJdbcUrl("postgresql://user%40corp:p%40ss%2Fword@host:5432/db");
        assertTrue(jdbc.contains("user=user%40corp"), jdbc);
        assertTrue(jdbc.contains("password=p%40ss%2Fword"), jdbc);
    }

    @Test
    void theShorterSchemeAndAnAbsentPortBothWork() {
        assertEquals("jdbc:postgresql://host/db", Main.toJdbcUrl("postgres://host/db"));
    }

    @Test
    void anExistingQueryStringSurvives() {
        String jdbc = Main.toJdbcUrl("postgresql://u:p@host:5432/db?sslmode=require");
        assertTrue(jdbc.contains("sslmode=require"), jdbc);
        assertTrue(jdbc.contains("user=u"), jdbc);
    }

    @Test
    void somethingThatIsNotAPostgresUrlIsRefusedRatherThanGuessedAt() {
        assertThrows(IllegalArgumentException.class, () -> Main.toJdbcUrl("mysql://host/db"));
        assertThrows(IllegalArgumentException.class, () -> Main.toJdbcUrl("host:5432/db"));
    }
}
