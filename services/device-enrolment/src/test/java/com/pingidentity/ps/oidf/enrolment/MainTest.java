/*
 * The environment plumbing that decides which directory this service writes to.
 */
package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
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

    @Test
    @SuppressWarnings("unchecked")
    void theAgentMissionVouchesForTheAgentAndCapsWhatItMayClaim() throws Exception {
        Map<String, String> env = Map.of(
                "AGENT_DISPLAY_NAME", "Claude bank connector",
                "AGENT_DESCRIPTION", "Reads balances. It cannot move money.",
                "AGENT_KEYWORDS", "[\"Customer Position\"]",
                "AGENT_MISSION_TYPES", "[\"T/retrieve_customer_position__balance\"]",
                "AGENT_MISSION_PURPOSES", "[\"https://w3id.org/dpv#AccountManagement\"]");
        Main.AgentMission mission = Main.agentMission("claude-bank-connector", env::get);

        Map<String, Object> client = (Map<String, Object>) mission.metadata().get("oauth_client");
        org.junit.jupiter.api.Assertions.assertEquals("Reads balances. It cannot move money.", client.get("description"));
        org.junit.jupiter.api.Assertions.assertEquals(java.util.List.of("Customer Position"), client.get("keywords"));
        org.junit.jupiter.api.Assertions.assertEquals("Claude bank connector", client.get("display_name"));
        Map<String, Object> policy = (Map<String, Object>) mission.policy().get("oauth_client");
        org.junit.jupiter.api.Assertions.assertEquals(
                Map.of("subset_of", java.util.List.of("T/retrieve_customer_position__balance"), "essential", true),
                policy.get("authorization_details_types"));
        org.junit.jupiter.api.Assertions.assertEquals(
                Map.of("subset_of", java.util.List.of("https://w3id.org/dpv#AccountManagement"), "essential", true),
                policy.get("purposes"));
        org.junit.jupiter.api.Assertions.assertEquals(Map.of("value", "claude-bank-connector"), policy.get("software_id"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void withoutAMissionConfiguredOnlyTheSoftwareIsPinned() throws Exception {
        Main.AgentMission mission = Main.agentMission("claude-bank-connector", name -> name.equals("AGENT_KEYWORDS") ? " " : null);
        Map<String, Object> policy = (Map<String, Object>) mission.policy().get("oauth_client");
        org.junit.jupiter.api.Assertions.assertEquals(java.util.Set.of("software_id", "token_endpoint_auth_method"), policy.keySet());
        org.junit.jupiter.api.Assertions.assertEquals(java.util.Set.of("client_name", "software_id", "token_endpoint_auth_method"),
                ((Map<String, Object>) mission.metadata().get("oauth_client")).keySet());
    }
}
