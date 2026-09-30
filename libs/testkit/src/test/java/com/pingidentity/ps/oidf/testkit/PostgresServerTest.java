package com.pingidentity.ps.oidf.testkit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.pingidentity.ps.oidf.testkit.PostgresServer.Kind;
import com.pingidentity.ps.oidf.testkit.PostgresServer.Resolution;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;

/** Where the Postgres comes from, decided from an environment and a Docker probe - no database needed. */
class PostgresServerTest {

    private static final BooleanSupplier NO_DOCKER = () -> false;
    private static final BooleanSupplier DOCKER = () -> true;
    private static final BooleanSupplier NOT_ASKED = () -> fail("Docker must not be asked when a server is named");

    private static Resolution resolve(Map<String, String> env, BooleanSupplier docker) {
        return PostgresServer.resolve(env::get, docker);
    }

    @Test
    void aNamedServerIsUsedAndDockerIsNeverAsked() {
        Resolution r = resolve(Map.of("OIDF_TEST_JDBC_URL", "jdbc:postgresql://127.0.0.1:55432/idm",
                "OIDF_TEST_JDBC_USER", "u", "OIDF_TEST_JDBC_PASSWORD", "p"), NOT_ASKED);

        assertEquals(Kind.EXTERNAL, r.kind());
        assertEquals("jdbc:postgresql://127.0.0.1:55432/idm", r.url());
        assertEquals("u", r.user());
        assertEquals("p", r.password());
        assertEquals(List.of(), r.warnings());
    }

    @Test
    void aNamedServerNeedsNoCredentials() {
        Resolution r = resolve(Map.of("OIDF_TEST_JDBC_URL", "jdbc:postgresql://localhost/x?user=u"), NOT_ASKED);

        assertEquals(Kind.EXTERNAL, r.kind());
        assertNull(r.user());
        assertNull(r.password());
    }

    @Test
    void theOldNamesStillWorkForOneReleaseWithAWarningEach() {
        Resolution r = resolve(Map.of("IDM_TEST_JDBC_URL", "jdbc:postgresql://localhost:5432/idm",
                "IDM_TEST_JDBC_USER", "dashboard", "IDM_TEST_JDBC_PASSWORD", "dashboard"), NOT_ASKED);

        assertEquals(Kind.EXTERNAL, r.kind());
        assertEquals("jdbc:postgresql://localhost:5432/idm", r.url());
        assertEquals("dashboard", r.user());
        assertEquals(3, r.warnings().size());
        assertTrue(r.warnings().get(0).startsWith("IDM_TEST_JDBC_URL is deprecated: set OIDF_TEST_JDBC_URL instead"),
                r.warnings().get(0));
    }

    @Test
    void theNewNameWinsOverTheOldAndABlankOneCountsAsUnset() {
        List<String> warnings = new ArrayList<>();
        assertEquals("new", PostgresServer.setting(Map.of("OIDF_TEST_JDBC_USER", "new", "IDM_TEST_JDBC_USER", "old")::get,
                "OIDF_TEST_JDBC_USER", warnings));
        assertEquals(List.of(), warnings);

        assertEquals("old", PostgresServer.setting(Map.of("OIDF_TEST_JDBC_USER", " ", "IDM_TEST_JDBC_USER", "old")::get,
                "OIDF_TEST_JDBC_USER", warnings));
        assertEquals(1, warnings.size());

        assertNull(PostgresServer.setting(Map.of("IDM_TEST_JDBC_USER", "")::get, "OIDF_TEST_JDBC_USER", warnings));
        assertNull(PostgresServer.setting(Map.<String, String>of()::get, "OIDF_TEST_JDBC_USER", warnings));
        assertEquals(1, warnings.size());
    }

    @Test
    void aServerThatIsNotPostgresFailsTheClass() {
        for (String url : List.of("jdbc:h2:mem:x;MODE=PostgreSQL", "jdbc:hsqldb:mem:x", "postgres://localhost/x")) {
            Resolution r = resolve(Map.of("OIDF_TEST_JDBC_URL", url), NOT_ASKED);

            assertEquals(Kind.FAIL, r.kind(), url);
            assertTrue(r.message().contains("must be a jdbc:postgresql: URL"), r.message());
            assertTrue(r.message().contains("CONTRIBUTING.md"), r.message());
        }
    }

    @Test
    void withNoServerNamedTestcontainersStartsOneWhenDockerAnswers() {
        assertEquals(Kind.CONTAINER, resolve(Map.of(), DOCKER).kind());
    }

    @Test
    void withNeitherTheClassIsSkippedAndToldWhereTheRecipeIs() {
        Resolution r = resolve(Map.of("CI", "false"), NO_DOCKER);

        assertEquals(Kind.SKIP, r.kind());
        assertTrue(r.message().startsWith("no PostgreSQL for this test class: set OIDF_TEST_JDBC_URL"), r.message());
        assertTrue(r.message().endsWith("see CONTRIBUTING.md, \"Tests that need Postgres\""), r.message());
        assertEquals(Kind.SKIP, resolve(Map.of(), NO_DOCKER).kind(), "CI unset is not CI");
    }

    /** A CI job that lost its database must not go green by skipping every store suite. */
    @Test
    void withNeitherUnderCiTheClassFails() {
        Resolution r = resolve(Map.of("CI", "true"), NO_DOCKER);

        assertEquals(Kind.FAIL, r.kind());
        assertTrue(r.message().contains("CI=true, so this fails rather than skips"), r.message());
        assertEquals(Kind.FAIL, resolve(Map.of("CI", "TRUE"), NO_DOCKER).kind());
        assertFalse(r.message().isBlank());
    }
}
