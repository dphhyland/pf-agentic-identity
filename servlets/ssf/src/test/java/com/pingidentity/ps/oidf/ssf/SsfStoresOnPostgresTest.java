/*
 * The two database stores' push selection and the push loop over them, against a real Postgres.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * {@link JdbcSsfStore} (its own DDL) and {@link LdmSsfStore} (the model repo's migrations, vendored under
 * {@code src/test/resources/idm/}) against a real PostgreSQL. The other store tests in this module are
 * Mockito tests that pin the SQL as text; this is where it runs. The selection {@code dueForPush} makes
 * since 0.4.0 is a join on the stream's state (the B5 stopgap, S10-0), and a join that only a mock has
 * seen is a claim, not a result (U-0078).
 *
 * <p>The Postgres is a database of this class's own (libs/testkit: {@code OIDF_TEST_JDBC_URL}, CI's service
 * container, else Testcontainers, else skipped - failed under {@code CI=true}), created before the class and dropped
 * after it. The stores' whole contract runs in {@code JdbcSsfStoreOnPostgresTest} and {@code LdmSsfStoreOnPostgresTest};
 * this class is the push selection and the loop over both.
 */
class SsfStoresOnPostgresTest {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    private static DataSource db;

    @BeforeAll
    static void database() throws Exception {
        db = POSTGRES.dataSource();
        Migrations.applyResources(db, SsfStoresOnPostgresTest.class,
                "/idm/0000-base-schema.sql", "/idm/0001-add-shared-signals-ssf.sql");
        new JdbcSsfStore(db).ensureSchema();
    }

    @BeforeEach
    void empty() throws SQLException {
        try (Connection c = db.getConnection(); Statement s = c.createStatement()) {
            s.execute("TRUNCATE ssf_pending_sets, ssf_stream_subjects, ssf_streams");
            s.execute("TRUNCATE idm.entry CASCADE");
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

    // ─────────────────────────────── a burst: SETs issued in one second ───────────────────────────────

    private static PushDeliveryService loop(SsfStore store, List<String> posted, boolean[] receiverUp) {
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .pushRetryMaxAttempts(5).pushRetryBackoffSeconds(5).build();
        return new PushDeliveryService(store, cfg, (url, auth, jws) -> {
            posted.add(jws);
            return receiverUp[0] ? PushDeliveryService.DeliveryResult.delivered()
                    : PushDeliveryService.DeliveryResult.retryable(503, "down");
        });
    }

    /**
     * Deliberately untagged: this asserts the divergence F-0095 records. SSF 1.0 §8.1.2.1 has a transmitter
     * that holds successive events for one Subject Principal transmit them "in the order of time that they
     * were generated"; {@code issuedAt} is in seconds, so a burst goes in {@code jti} order within its second.
     * What the stores do keep is one order for both reads. Ordered by {@code issued_at} alone, Postgres
     * returned a burst in the order the rows lay, and {@code recordAttempt}'s UPDATE moves the row it updates:
     * the retry went to another SET of the burst and the stream was not held behind the one that failed.
     * Generated b, c, a in one second; tried a, and a again; then a, b, c.
     */
    private void aBurstIssuedInOneSecond(SsfStore store) {
        String s = stream(store, DeliveryMethod.PUSH, StreamStatus.ENABLED);
        for (String jti : List.of("burst-b", "burst-c", "burst-a")) {
            due(store, s, jti, 100);
        }
        List<String> posted = new ArrayList<>();
        boolean[] receiverUp = {false};
        PushDeliveryService loop = loop(store, posted, receiverUp);

        assertEquals(0, loop.runOnce(1000));
        assertEquals(0, loop.runOnce(1005));
        assertEquals(List.of("jws-burst-a", "jws-burst-a"), posted, "the SET that failed is the one retried");
        List<PendingSet> queued = store.peek(s, 10);
        assertEquals(List.of("burst-a", "burst-b", "burst-c"), jtis(queued));
        assertEquals(List.of(2, 0, 0), queued.stream().map(PendingSet::deliveryAttempts).toList());

        receiverUp[0] = true;
        assertEquals(0, loop.runOnce(1010), "burst-b and burst-c are due, and wait behind burst-a");
        assertEquals(3, loop.runOnce(1015));
        assertEquals(List.of("jws-burst-a", "jws-burst-a", "jws-burst-a", "jws-burst-b", "jws-burst-c"), posted);
    }

    @Test
    void aBurstOverTheTablesStore() {
        aBurstIssuedInOneSecond(new JdbcSsfStore(db));
    }

    @Test
    void aBurstOverTheLdmStore() {
        aBurstIssuedInOneSecond(new LdmSsfStore(db));
    }

    /**
     * Deliberately untagged, as above. A burst whose receiver refuses every POST dead-letters on one SET's
     * backoff - 5 + 10 + 20 + 40 s, the fifth attempt at 75 s - however many SETs share its second. With the
     * retries moving from SET to SET, five of them took 130 s.
     */
    private void aBurstDeadLettersOnOneSetsBackoff(SsfStore store) {
        String s = stream(store, DeliveryMethod.PUSH, StreamStatus.ENABLED);
        for (int i = 0; i < 5; i++) {
            due(store, s, "dl-" + i, 100);
        }
        PushDeliveryService loop = loop(store, new ArrayList<>(), new boolean[] {false});

        long pausedAt = -1;
        for (long now = 1000; now <= 1200 && pausedAt < 0; now += 5) {
            loop.runOnce(now);
            if (store.getStream(s).orElseThrow().status() == StreamStatus.PAUSED) {
                pausedAt = now;
            }
        }

        assertEquals(1075, pausedAt);
        assertEquals(List.of(5, 0, 0, 0, 0), store.peek(s, 10).stream().map(PendingSet::deliveryAttempts).toList());
    }

    @Test
    void aBurstDeadLettersOnTheTablesStore() {
        aBurstDeadLettersOnOneSetsBackoff(new JdbcSsfStore(db));
    }

    @Test
    void aBurstDeadLettersOnTheLdmStore() {
        aBurstDeadLettersOnOneSetsBackoff(new LdmSsfStore(db));
    }
}
