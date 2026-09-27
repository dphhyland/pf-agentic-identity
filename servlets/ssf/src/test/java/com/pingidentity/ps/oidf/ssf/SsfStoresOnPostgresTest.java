/*
 * The two database stores' push selection and the push loop over them, against a real Postgres.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * {@link JdbcSsfStore} (its own DDL) and {@link LdmSsfStore} (the model repo's migrations, vendored under
 * {@code src/test/resources/idm/}) against a real PostgreSQL. The other store tests in this module are
 * Mockito tests that pin the SQL as text; this is where it runs. The selection {@code dueForPush} makes
 * since 0.4.0 is a join on the stream's state (the B5 stopgap, S10-0), and a join that only a mock has
 * seen is a claim, not a result (U-0078).
 *
 * <p>The Postgres comes from {@code IDM_TEST_JDBC_URL} (with {@code IDM_TEST_JDBC_USER} and
 * {@code _PASSWORD}), as for device-instance's registry suite, or else from Testcontainers; with neither
 * the class is skipped, not failed. On the database the variable names, the class creates a database of its
 * own and drops it afterwards, so it shares nothing with the other suites that use the same server. Where
 * the user may not create databases it falls back to the named one, and drops and rebuilds the SSF tables
 * and the {@code idm} schema there - point it only at a database you are willing to lose.
 */
class SsfStoresOnPostgresTest {

    private static final String[] MIGRATIONS = {
        "/idm/0000-base-schema.sql",
        "/idm/0001-add-shared-signals-ssf.sql",
    };

    private static PostgreSQLContainer<?> container;
    private static DataSource admin;
    private static String ownDatabase;
    private static DataSource db;

    @BeforeAll
    static void database() throws Exception {
        Optional<PGSimpleDataSource> external = externalDataSource();
        if (external.isPresent()) {
            admin = external.get();
            db = ownDatabaseOr(external.get());
        } else {
            db = containerDataSource();
        }
        try (Connection c = db.getConnection(); Statement s = c.createStatement()) {
            s.execute("DROP TABLE IF EXISTS ssf_pending_sets, ssf_stream_subjects, ssf_streams");
            s.execute("DROP SCHEMA IF EXISTS idm CASCADE");
            for (String migration : MIGRATIONS) {
                s.execute(read(migration));
            }
        }
        new JdbcSsfStore(db).ensureSchema();
    }

    @AfterAll
    static void dropDatabase() throws SQLException {
        if (ownDatabase != null) {
            try (Connection c = admin.getConnection(); Statement s = c.createStatement()) {
                s.execute("DROP DATABASE IF EXISTS " + ownDatabase + " WITH (FORCE)");
            }
        }
        if (container != null) {
            container.stop();
        }
    }

    @BeforeEach
    void empty() throws SQLException {
        try (Connection c = db.getConnection(); Statement s = c.createStatement()) {
            s.execute("TRUNCATE ssf_pending_sets, ssf_stream_subjects, ssf_streams");
            s.execute("TRUNCATE idm.entry CASCADE");
        }
    }

    private static Optional<PGSimpleDataSource> externalDataSource() {
        String url = System.getenv("IDM_TEST_JDBC_URL");
        if (url == null || url.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(dataSource(url));
    }

    private static PGSimpleDataSource dataSource(String url) {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(url);
        String user = System.getenv("IDM_TEST_JDBC_USER");
        String password = System.getenv("IDM_TEST_JDBC_PASSWORD");
        if (user != null && !user.isBlank()) {
            ds.setUser(user);
        }
        if (password != null && !password.isBlank()) {
            ds.setPassword(password);
        }
        return ds;
    }

    /** A database of this class's own on the named server, or the named database if that is refused. */
    private static DataSource ownDatabaseOr(PGSimpleDataSource named) {
        String name = "ssf_store_test_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        try (Connection c = named.getConnection(); Statement s = c.createStatement()) {
            s.execute("CREATE DATABASE " + name);
        } catch (SQLException refused) {
            return named;
        }
        ownDatabase = name;
        PGSimpleDataSource own = dataSource(System.getenv("IDM_TEST_JDBC_URL"));
        own.setDatabaseName(name);
        return own;
    }

    private static DataSource containerDataSource() {
        Assumptions.assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                "no Postgres for the SSF store suite: set IDM_TEST_JDBC_URL, or make the Docker API reachable "
                        + "for Testcontainers");
        container = new PostgreSQLContainer<>("postgres:16-alpine");
        container.start();
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(container.getJdbcUrl());
        ds.setUser(container.getUsername());
        ds.setPassword(container.getPassword());
        return ds;
    }

    private static String read(String resource) throws IOException {
        try (InputStream in = SsfStoresOnPostgresTest.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("missing test resource " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // ─────────────────────────────── fixtures ───────────────────────────────

    /** A stream with a UUID id, which the ldm store needs (the id is the entry's {@code entry_uuid}). */
    private static String stream(SsfStore store, DeliveryMethod method, StreamStatus status) {
        String id = UUID.randomUUID().toString();
        Stream.Builder b = Stream.builder().id(id).audience("https://receiver.example.com").deliveryMethod(method)
                .eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED)).status(status)
                .createdAt(1000).updatedAt(1000);
        if (method == DeliveryMethod.PUSH) {
            b.pushEndpointUrl("https://receiver.example.com/set");
        }
        store.createStream(b.build());
        return id;
    }

    private static void due(SsfStore store, String streamId, String jti, long issuedAt) {
        store.enqueue(PendingSet.fresh(jti, streamId, "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-" + jti,
                issuedAt, 0));
    }

    private static List<String> jtis(List<PendingSet> sets) {
        return sets.stream().map(PendingSet::jti).toList();
    }

    // ─────────────────────────────── what dueForPush selects ───────────────────────────────

    /**
     * SSF 1.0 §8.1.2.1: enabled, "The Transmitter MUST transmit events over the stream, according to the
     * stream's configured delivery method"; paused and disabled, "The Transmitter MUST NOT transmit events
     * over the stream". Every kind of stream holds a SET that is due, and the oldest belong to the streams
     * that must not be pushed to: only the two enabled push streams' come back, oldest first, and the SET
     * that is still backing off does not.
     */
    private void selectsOnlyTheDueSetsOfEnabledPushStreams(SsfStore store) {
        String paused = stream(store, DeliveryMethod.PUSH, StreamStatus.PAUSED);
        String disabled = stream(store, DeliveryMethod.PUSH, StreamStatus.DISABLED);
        String poll = stream(store, DeliveryMethod.POLL, StreamStatus.ENABLED);
        String first = stream(store, DeliveryMethod.PUSH, StreamStatus.ENABLED);
        String second = stream(store, DeliveryMethod.PUSH, StreamStatus.ENABLED);
        due(store, paused, "j-paused-1", 100);
        due(store, paused, "j-paused-2", 101);
        due(store, disabled, "j-disabled", 102);
        due(store, poll, "j-poll", 103);
        due(store, second, "j-second", 150);
        due(store, first, "j-first", 200);
        store.enqueue(new PendingSet("j-backing-off", first, "k", SsfEventTypes.CAEP_SESSION_REVOKED,
                "jws-backing-off", 120, 0, 1, 2000));

        assertEquals(List.of("j-second", "j-first"), jtis(store.dueForPush(1000, 500)));
        assertEquals(List.of("j-second"), jtis(store.dueForPush(1000, 1)), "LIMIT after the join, oldest first");
        assertEquals(List.of("j-paused-1", "j-paused-2"), jtis(store.peek(paused, 10)), "held, not dropped");
        assertEquals(List.of("j-poll"), jtis(store.peek(poll, 10)), "left for the poll endpoint");
    }

    @Test
    @Requirement("SSF §8.1.2.1")
    void theTablesStoreSelectsOnlyTheDueSetsOfEnabledPushStreams() {
        selectsOnlyTheDueSetsOfEnabledPushStreams(new JdbcSsfStore(db));
    }

    @Test
    @Requirement("SSF §8.1.2.1")
    void theLdmStoreSelectsOnlyTheDueSetsOfEnabledPushStreams() {
        selectsOnlyTheDueSetsOfEnabledPushStreams(new LdmSsfStore(db));
    }

    // ─────────────────────────────── the push loop over the store ───────────────────────────────

    /**
     * Deliberately untagged: how a transmitter shares its loop between streams is its own. The loop over
     * the real store, three ticks: the stream that is down costs one attempt and records it (recordAttempt's
     * UPDATE), the stream beside it is delivered to (ack's DELETE), the paused stream is never read; in the
     * next tick the failing stream waits behind its oldest SET's backoff (peek); and when the receiver is
     * back the SETs go oldest first.
     */
    private void aTickOverTheStore(SsfStore store) {
        String down = stream(store, DeliveryMethod.PUSH, StreamStatus.ENABLED);
        String up = stream(store, DeliveryMethod.PUSH, StreamStatus.ENABLED);
        String paused = stream(store, DeliveryMethod.PUSH, StreamStatus.PAUSED);
        due(store, paused, "p-0", 50);
        due(store, down, "d-0", 100);
        due(store, down, "d-1", 101);
        due(store, down, "d-2", 102);
        due(store, up, "u-0", 500);
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .pushRetryMaxAttempts(5).pushRetryBackoffSeconds(5).build();
        List<String> posted = new ArrayList<>();
        boolean[] downIsUp = {false};
        PushDeliveryService loop = new PushDeliveryService(store, cfg, (url, auth, jws) -> {
            posted.add(jws);
            return jws.startsWith("jws-d-") && !downIsUp[0]
                    ? PushDeliveryService.DeliveryResult.retryable(503, "down")
                    : PushDeliveryService.DeliveryResult.delivered();
        });

        assertEquals(1, loop.runOnce(1000));
        assertEquals(List.of("jws-d-0", "jws-u-0"), posted);
        List<PendingSet> queued = store.peek(down, 10);
        assertEquals(List.of("d-0", "d-1", "d-2"), jtis(queued));
        assertEquals(List.of(1, 0, 0), queued.stream().map(PendingSet::deliveryAttempts).toList());
        assertEquals(1005, queued.get(0).nextAttemptAt());
        assertTrue(store.peek(up, 10).isEmpty(), "delivered and acknowledged");

        downIsUp[0] = true;
        assertEquals(0, loop.runOnce(1004), "d-1 and d-2 are due, and wait behind d-0");
        assertEquals(3, loop.runOnce(1005));

        assertEquals(List.of("jws-d-0", "jws-u-0", "jws-d-0", "jws-d-1", "jws-d-2"), posted);
        assertTrue(store.peek(down, 10).isEmpty());
        assertEquals(List.of("p-0"), jtis(store.peek(paused, 10)), "the paused stream was never read for push");
        assertEquals(StreamStatus.ENABLED, store.getStream(down).orElseThrow().status(),
                "one failure is not a dead-letter");
    }

    @Test
    void theLoopOverTheTablesStore() {
        aTickOverTheStore(new JdbcSsfStore(db));
    }

    @Test
    void theLoopOverTheLdmStore() {
        aTickOverTheStore(new LdmSsfStore(db));
    }
}
