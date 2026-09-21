/*
 * In-memory store: stream CRUD, subject membership, and pending-SET queue semantics.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class InMemorySsfStoreTest {

    private final InMemorySsfStore store = new InMemorySsfStore();

    private Stream pollStream(String id) {
        return Stream.builder()
                .id(id)
                .audience("https://receiver.example.com")
                .deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED))
                .status(StreamStatus.ENABLED)
                .build();
    }

    @Test
    void streamCrud() {
        store.createStream(pollStream("s1"));
        assertTrue(store.getStream("s1").isPresent());
        assertEquals(1, store.listStreams().size());

        Stream paused = store.getStream("s1").orElseThrow().withStatus(StreamStatus.PAUSED, "test", 1L);
        store.updateStream(paused);
        assertEquals(StreamStatus.PAUSED, store.getStream("s1").orElseThrow().status());

        assertTrue(store.deleteStream("s1"));
        assertFalse(store.getStream("s1").isPresent());
        assertFalse(store.deleteStream("s1"));
    }

    @Test
    void subjectMembership() {
        store.createStream(pollStream("s1"));
        SubjectId alice = SubjectId.email("alice@example.com");
        assertTrue(store.addSubject("s1", alice));
        assertFalse(store.addSubject("s1", alice), "adding twice is a no-op");
        assertTrue(store.hasSubject("s1", alice));
        assertEquals(1, store.listSubjects("s1").size());
        assertTrue(store.removeSubject("s1", alice));
        assertFalse(store.hasSubject("s1", alice));
    }

    @Test
    void pendingQueuePeekAndAck() {
        store.createStream(pollStream("s1"));
        store.enqueue(PendingSet.fresh("j1", "s1", "k", "e", "jws1", 100, 0));
        store.enqueue(PendingSet.fresh("j2", "s1", "k", "e", "jws2", 101, 0));

        List<PendingSet> peeked = store.peek("s1", 10);
        assertEquals(2, peeked.size());
        assertEquals("j1", peeked.get(0).jti(), "oldest first");

        assertEquals(1, store.ack("s1", List.of("j1")));
        assertEquals(1, store.peek("s1", 10).size());
        assertEquals("j2", store.peek("s1", 10).get(0).jti());
    }

    @Test
    void dueForPushRespectsNextAttemptTime() {
        store.createStream(pollStream("s1"));
        store.enqueue(new PendingSet("j1", "s1", "k", "e", "jws", 100, 0, 0, 50));
        store.enqueue(new PendingSet("j2", "s1", "k", "e", "jws", 100, 0, 0, 200));

        List<PendingSet> due = store.dueForPush(100, 10);
        assertEquals(1, due.size());
        assertEquals("j1", due.get(0).jti());
    }

    @Test
    void recordAttemptBumpsCountAndReschedules() {
        store.createStream(pollStream("s1"));
        PendingSet p = PendingSet.fresh("j1", "s1", "k", "e", "jws", 100, 0);
        store.enqueue(p);
        store.recordAttempt(p, 500);
        PendingSet after = store.peek("s1", 1).get(0);
        assertEquals(1, after.deliveryAttempts());
        assertEquals(500, after.nextAttemptAt());
    }

    @Test
    void evictExpiredRemovesOnlyExpired() {
        store.createStream(pollStream("s1"));
        store.enqueue(new PendingSet("live", "s1", "k", "e", "jws", 100, 1000, 0, 0));
        store.enqueue(new PendingSet("dead", "s1", "k", "e", "jws", 100, 200, 0, 0));
        assertEquals(1, store.evictExpired(300));
        assertEquals(1, store.peek("s1", 10).size());
        assertEquals("live", store.peek("s1", 10).get(0).jti());
    }

    // ─────────────────────────────── owner ───────────────────────────────

    @Test
    void aStreamsOwnerIsStoredWithIt() {
        store.createStream(pollStream("s1").toBuilder().ownerClientId("receiver-a").build());

        assertEquals("receiver-a", store.getStream("s1").orElseThrow().ownerClientId());
        assertEquals("receiver-a", store.listStreams().get(0).ownerClientId());
    }

    /** SsfStore#updateStream: whatever the update carries, the stored owner stands. */
    @Test
    void anUpdateCanNeitherMoveNorClearTheOwner() {
        store.createStream(pollStream("s1").toBuilder().ownerClientId("receiver-a").build());

        Stream moved = store.updateStream(pollStream("s1").toBuilder().ownerClientId("receiver-b")
                .status(StreamStatus.PAUSED).build());
        assertEquals("receiver-a", moved.ownerClientId(), "what is returned is what was stored");
        assertEquals("receiver-a", store.getStream("s1").orElseThrow().ownerClientId());
        // control: it is the owner that is held back, not the update. Checked here, against a status the
        // stream did not start with - an update that did nothing at all would leave it ENABLED.
        assertEquals(StreamStatus.PAUSED, store.getStream("s1").orElseThrow().status());

        store.updateStream(pollStream("s1")); // carries no owner at all
        assertEquals("receiver-a", store.getStream("s1").orElseThrow().ownerClientId());
        assertEquals(StreamStatus.ENABLED, store.getStream("s1").orElseThrow().status());
    }

    /** The durable stores refuse this already - the id is their primary key. A create that overwrote would be a second way to write an owner. */
    @Test
    void aCreateCannotOverwriteAStreamAndTakeItsSubjectsAndQueue() {
        store.createStream(pollStream("s1").toBuilder().ownerClientId("receiver-a").build());
        SubjectId alice = SubjectId.email("alice@example.com");
        store.addSubject("s1", alice);

        assertThrows(IllegalArgumentException.class,
                () -> store.createStream(pollStream("s1").toBuilder().ownerClientId("receiver-b").build()));

        assertEquals("receiver-a", store.getStream("s1").orElseThrow().ownerClientId());
        assertTrue(store.hasSubject("s1", alice));
        store.createStream(pollStream("s2").toBuilder().ownerClientId("receiver-b").build()); // control: a free id is fine
    }

    @Test
    void anUpdateOfAStreamThatIsNotThereIsRefusedAndCreatesNothing() {
        assertThrows(IllegalArgumentException.class, () -> store.updateStream(pollStream("never-created")));
        assertTrue(store.listStreams().isEmpty(), "an update must not become a create - least of all one with no owner");

        store.createStream(pollStream("s1")); // control: the same call on a stream that exists is fine
        store.updateStream(pollStream("s1"));
    }

    @Test
    void anUpdateDoesNotGiveAnOwnerToAStreamThatHasNone() {
        store.createStream(pollStream("s1"));

        store.updateStream(pollStream("s1").toBuilder().ownerClientId("receiver-b").build());

        assertEquals(null, store.getStream("s1").orElseThrow().ownerClientId(),
                "an update is not a way to claim an unowned stream");
    }
}
