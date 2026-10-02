/*
 * What every SsfStore does, whatever keeps the streams, subjects and queue.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.signals.SetMinter;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The {@link SsfStore} contract, held against each store: {@link InMemorySsfStore} here, and the two durable
 * stores on PostgreSQL ({@code JdbcSsfStoreOnPostgresTest}, {@code LdmSsfStoreOnPostgresTest}). Stream ids are
 * UUIDs because the {@code ldm} store's stream id is its entry's {@code entry_uuid}. Where the stores differ on
 * purpose - the in-memory store returns the stream as stored from {@code updateStream}, the durable stores the
 * argument - the difference stays in the store's own test and out of here.
 */
abstract class SsfStoreContract {

    /** A new, empty store. Called before each test. */
    protected abstract SsfStore newStore() throws Exception;

    protected SsfStore store;

    /**
     * That a stream read back carries the {@code updatedAt} it was written with. The {@code ldm} store overrides
     * this: the model's entry trigger sets {@code modified_at} to the database's clock on every write (F-0150).
     */
    protected void assertUpdatedAt(long written, Stream read) {
        assertEquals(written, read.updatedAt());
    }

    @BeforeEach
    void freshStore() throws Exception {
        this.store = newStore();
    }

    static String newId() {
        return UUID.randomUUID().toString();
    }

    static Stream pollStream(String id) {
        return Stream.builder()
                .id(id)
                .audience("https://receiver.example.com")
                .deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED))
                .status(StreamStatus.ENABLED)
                .build();
    }

    static Stream pushStream(String id, StreamStatus status) {
        return Stream.builder()
                .id(id)
                .audience("https://receiver.example.com")
                .deliveryMethod(DeliveryMethod.PUSH)
                .pushEndpointUrl("https://receiver.example.com/set")
                .eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED))
                .status(status)
                .build();
    }

    private static List<String> jtis(List<PendingSet> sets) {
        return sets.stream().map(PendingSet::jti).toList();
    }

    // ─────────────────────────────── streams ───────────────────────────────

    @Test
    void streamCrud() {
        String s1 = newId();
        this.store.createStream(pollStream(s1));
        assertTrue(this.store.getStream(s1).isPresent());
        assertEquals(1, this.store.listStreams().size());

        Stream paused = this.store.getStream(s1).orElseThrow().withStatus(StreamStatus.PAUSED, "test", 1L);
        this.store.updateStream(paused);
        assertEquals(StreamStatus.PAUSED, this.store.getStream(s1).orElseThrow().status());

        assertTrue(this.store.deleteStream(s1));
        assertFalse(this.store.getStream(s1).isPresent());
        assertFalse(this.store.deleteStream(s1));
    }

    @Test
    void aStreamComesBackWithEveryFieldItWasStoredWith() {
        String id = newId();
        this.store.createStream(Stream.builder().id(id).audience("https://rp.example.com").ownerClientId("receiver-a")
                .deliveryMethod(DeliveryMethod.PUSH).pushEndpointUrl("https://rp.example.com/events")
                .pushAuthorizationHeader("Bearer push-token")
                .eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED, SsfEventTypes.CAEP_CREDENTIAL_CHANGE))
                .eventsDelivered(List.of(SsfEventTypes.CAEP_SESSION_REVOKED))
                .status(StreamStatus.PAUSED).statusReason("receiver asked").createdAt(1_000).updatedAt(2_000).build());

        Stream read = this.store.getStream(id).orElseThrow();

        assertEquals(id, read.id());
        assertEquals("https://rp.example.com", read.audience());
        assertEquals("receiver-a", read.ownerClientId());
        assertEquals(DeliveryMethod.PUSH, read.deliveryMethod());
        assertEquals("https://rp.example.com/events", read.pushEndpointUrl());
        assertEquals("Bearer push-token", read.pushAuthorizationHeader());
        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED, SsfEventTypes.CAEP_CREDENTIAL_CHANGE), read.eventsRequested());
        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED), read.eventsDelivered());
        assertEquals(StreamStatus.PAUSED, read.status());
        assertEquals("receiver asked", read.statusReason());
        assertEquals(1_000, read.createdAt());
        assertUpdatedAt(2_000, read);
    }

    @Test
    void aStreamNobodyCreatedIsNotThere() {
        assertTrue(this.store.getStream(newId()).isEmpty());
        assertTrue(this.store.listStreams().isEmpty());
        assertFalse(this.store.deleteStream(newId()));
    }

    @Test
    void everyStreamIsListed() {
        String a = newId();
        String b = newId();
        this.store.createStream(pollStream(a));
        this.store.createStream(pushStream(b, StreamStatus.ENABLED));

        assertEquals(Set.of(a, b), new HashSet<>(this.store.listStreams().stream().map(Stream::id).toList()));
    }

    @Test
    void anUpdateReplacesWhatItCarries() {
        String id = newId();
        this.store.createStream(pollStream(id));

        this.store.updateStream(pushStream(id, StreamStatus.DISABLED).toBuilder().audience("https://other.example.com")
                .eventsDelivered(List.of(SsfEventTypes.CAEP_SESSION_REVOKED)).statusReason("operator").updatedAt(5_000).build());

        Stream read = this.store.getStream(id).orElseThrow();
        assertEquals("https://other.example.com", read.audience());
        assertEquals(DeliveryMethod.PUSH, read.deliveryMethod());
        assertEquals("https://receiver.example.com/set", read.pushEndpointUrl());
        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED), read.eventsDelivered());
        assertEquals(StreamStatus.DISABLED, read.status());
        assertEquals("operator", read.statusReason());
        assertUpdatedAt(5_000, read);
    }

    @Test
    void aStreamsOwnerIsStoredWithIt() {
        String id = newId();
        this.store.createStream(pollStream(id).toBuilder().ownerClientId("receiver-a").build());

        assertEquals("receiver-a", this.store.getStream(id).orElseThrow().ownerClientId());
        assertEquals("receiver-a", this.store.listStreams().get(0).ownerClientId());
    }

    /** SsfStore#updateStream: whatever the update carries, the stored owner stands. */
    @Test
    void anUpdateCanNeitherMoveNorClearTheOwner() {
        String id = newId();
        this.store.createStream(pollStream(id).toBuilder().ownerClientId("receiver-a").build());

        this.store.updateStream(pollStream(id).toBuilder().ownerClientId("receiver-b").status(StreamStatus.PAUSED).build());
        assertEquals("receiver-a", this.store.getStream(id).orElseThrow().ownerClientId());
        // control: it is the owner that is held back, not the update. Checked here, against a status the
        // stream did not start with - an update that did nothing at all would leave it ENABLED.
        assertEquals(StreamStatus.PAUSED, this.store.getStream(id).orElseThrow().status());

        this.store.updateStream(pollStream(id)); // carries no owner at all
        assertEquals("receiver-a", this.store.getStream(id).orElseThrow().ownerClientId());
        assertEquals(StreamStatus.ENABLED, this.store.getStream(id).orElseThrow().status());
    }

    /** The id is the durable stores' primary key. A create that overwrote would be a second way to write an owner. */
    @Test
    void aCreateCannotOverwriteAStreamAndTakeItsSubjectsAndQueue() {
        String id = newId();
        this.store.createStream(pollStream(id).toBuilder().ownerClientId("receiver-a").build());
        SubjectId alice = SubjectId.email("alice@example.com");
        this.store.addSubject(id, alice);

        assertThrows(RuntimeException.class,
                () -> this.store.createStream(pollStream(id).toBuilder().ownerClientId("receiver-b").build()));

        assertEquals("receiver-a", this.store.getStream(id).orElseThrow().ownerClientId());
        assertTrue(this.store.hasSubject(id, alice));
        this.store.createStream(pollStream(newId()).toBuilder().ownerClientId("receiver-b").build()); // control: a free id is fine
    }

    @Test
    void anUpdateOfAStreamThatIsNotThereIsRefusedAndCreatesNothing() {
        assertThrows(IllegalArgumentException.class, () -> this.store.updateStream(pollStream(newId())));
        assertTrue(this.store.listStreams().isEmpty(), "an update must not become a create - least of all one with no owner");

        String id = newId();
        this.store.createStream(pollStream(id)); // control: the same call on a stream that exists is fine
        this.store.updateStream(pollStream(id));
    }

    @Test
    void anUpdateDoesNotGiveAnOwnerToAStreamThatHasNone() {
        String id = newId();
        this.store.createStream(pollStream(id));

        this.store.updateStream(pollStream(id).toBuilder().ownerClientId("receiver-b").build());

        assertNull(this.store.getStream(id).orElseThrow().ownerClientId(), "an update is not a way to claim an unowned stream");
    }

    @Test
    void deletingAStreamTakesItsSubjectsAndQueueAndNothingElse() {
        String gone = newId();
        String kept = newId();
        this.store.createStream(pollStream(gone));
        this.store.createStream(pollStream(kept));
        SubjectId alice = SubjectId.email("alice@example.com");
        for (String id : List.of(gone, kept)) {
            this.store.addSubject(id, alice);
            this.store.enqueue(PendingSet.fresh("j-" + id, id, "k", "e", "jws", 100, 0));
        }

        assertTrue(this.store.deleteStream(gone));

        assertTrue(this.store.listSubjects(gone).isEmpty());
        assertTrue(this.store.peek(gone, 10).isEmpty());
        assertTrue(this.store.hasSubject(kept, alice));
        assertEquals(List.of("j-" + kept), jtis(this.store.peek(kept, 10)));
    }

    // ─────────────────────────────── subjects ───────────────────────────────

    @Test
    void subjectMembership() {
        String id = newId();
        this.store.createStream(pollStream(id));
        SubjectId alice = SubjectId.email("alice@example.com");
        assertTrue(this.store.addSubject(id, alice));
        assertFalse(this.store.addSubject(id, alice), "adding twice is a no-op");
        assertTrue(this.store.hasSubject(id, alice));
        assertEquals(1, this.store.listSubjects(id).size());
        assertTrue(this.store.removeSubject(id, alice));
        assertFalse(this.store.hasSubject(id, alice));
        assertFalse(this.store.removeSubject(id, alice), "removing what is not there says so");
    }

    @Test
    void subjectsOfEveryFormatComeBackAsTheyWereAdded() {
        String id = newId();
        this.store.createStream(pollStream(id));
        List<SubjectId> subjects = List.of(SubjectId.email("alice@example.com"), SubjectId.phoneNumber("+61400000000"),
                SubjectId.issSub("https://idp.example.com", "user-1"), SubjectId.opaque("11112222"),
                SubjectId.account("acct:bob@example.com"));
        for (SubjectId subject : subjects) {
            assertTrue(this.store.addSubject(id, subject), subject.canonicalKey());
        }

        assertEquals(new HashSet<>(subjects), new HashSet<>(this.store.listSubjects(id)));
        for (SubjectId subject : subjects) {
            assertTrue(this.store.hasSubject(id, subject), subject.canonicalKey());
        }
    }

    @Test
    void aSubjectBelongsToTheStreamItWasAddedTo() {
        String a = newId();
        String b = newId();
        this.store.createStream(pollStream(a));
        this.store.createStream(pollStream(b));
        SubjectId alice = SubjectId.email("alice@example.com");
        this.store.addSubject(a, alice);

        assertFalse(this.store.hasSubject(b, alice));
        assertTrue(this.store.listSubjects(b).isEmpty());
        assertFalse(this.store.removeSubject(b, alice));
        assertTrue(this.store.hasSubject(a, alice), "a remove on another stream leaves this one alone");
    }

    @Test
    void aSubjectCannotBeAddedToAStreamThatIsNotThere() {
        assertThrows(IllegalArgumentException.class, () -> this.store.addSubject(newId(), SubjectId.email("alice@example.com")));
    }

    // ─────────────────────────────── pending SETs ───────────────────────────────

    @Test
    void pendingQueuePeekAndAck() {
        String id = newId();
        this.store.createStream(pollStream(id));
        this.store.enqueue(PendingSet.fresh("j1", id, "k", "e", "jws1", 100, 0));
        this.store.enqueue(PendingSet.fresh("j2", id, "k", "e", "jws2", 101, 0));

        List<PendingSet> peeked = this.store.peek(id, 10);
        assertEquals(2, peeked.size());
        assertEquals("j1", peeked.get(0).jti(), "oldest first");

        assertEquals(1, this.store.ack(id, List.of("j1")));
        assertEquals(List.of("j2"), jtis(this.store.peek(id, 10)));
    }

    @Test
    void aPendingSetComesBackWithEveryFieldItWasQueuedWith() {
        String id = newId();
        this.store.createStream(pollStream(id));
        this.store.enqueue(new PendingSet("j1", id, "email:alice@example.com", SsfEventTypes.CAEP_SESSION_REVOKED,
                "eyJhbGciOiJFUzI1NiJ9.e30.sig", 100, 9_000, 3, 400));

        PendingSet read = this.store.peek(id, 1).get(0);

        assertEquals("j1", read.jti());
        assertEquals(id, read.streamId());
        assertEquals("email:alice@example.com", read.subjectKey());
        assertEquals(SsfEventTypes.CAEP_SESSION_REVOKED, read.eventType());
        assertEquals("eyJhbGciOiJFUzI1NiJ9.e30.sig", read.setJws());
        assertEquals(100, read.issuedAt());
        assertEquals(9_000, read.expiresAt());
        assertEquals(3, read.deliveryAttempts());
        assertEquals(400, read.nextAttemptAt());
    }

    @Test
    void peekStopsAtItsLimit() {
        String id = newId();
        this.store.createStream(pollStream(id));
        for (int i = 0; i < 5; i++) {
            this.store.enqueue(PendingSet.fresh("j" + i, id, "k", "e", "jws", 100 + i, 0));
        }

        assertEquals(List.of("j0", "j1"), jtis(this.store.peek(id, 2)));
        assertTrue(this.store.peek(id, 0).isEmpty());
        assertTrue(this.store.peek(id, -1).isEmpty(), "a negative limit is none, not everything");
        assertTrue(this.store.peek(newId(), 10).isEmpty());
    }

    @Test
    void anAckRemovesOnlyItsOwnStreamsSets() {
        String a = newId();
        String b = newId();
        this.store.createStream(pollStream(a));
        this.store.createStream(pollStream(b));
        this.store.enqueue(PendingSet.fresh("ja", a, "k", "e", "jws", 100, 0));

        assertEquals(0, this.store.ack(b, List.of("ja")), "another stream's jti is not this stream's to acknowledge");
        assertEquals(0, this.store.ack(a, List.of()));
        assertEquals(0, this.store.ack(a, null));
        assertEquals(0, this.store.ack(a, List.of("never-queued")));
        assertEquals(List.of("ja"), jtis(this.store.peek(a, 10)));
    }

    /**
     * SSF 1.0 §8.1.2.1: enabled, "The Transmitter MUST transmit events over the stream, according to the
     * stream's configured delivery method"; paused and disabled, "The Transmitter MUST NOT transmit events
     * over the stream". The selection is the store's (SsfStore#dueForPush), so it is the store that is
     * asked: a poll stream's SETs are its receiver's to poll for, never the push executor's.
     */
    @Test
    @Requirement("SSF §8.1.2.1")
    void dueForPushSelectsOnlyTheSetsOfEnabledPushStreams() {
        String enabled = newId();
        String paused = newId();
        String disabled = newId();
        String poll = newId();
        this.store.createStream(pushStream(enabled, StreamStatus.ENABLED));
        this.store.createStream(pushStream(paused, StreamStatus.PAUSED));
        this.store.createStream(pushStream(disabled, StreamStatus.DISABLED));
        this.store.createStream(pollStream(poll));
        for (String id : List.of(enabled, paused, disabled, poll)) {
            this.store.enqueue(PendingSet.fresh("j-" + id, id, "k", "e", "jws", 100, 0));
        }

        List<PendingSet> due = this.store.dueForPush(100, 10);

        assertEquals(List.of("j-" + enabled), jtis(due));
        assertEquals(1, this.store.peek(paused, 10).size(), "held, not dropped");
        assertEquals(1, this.store.peek(poll, 10).size(), "left for the poll endpoint");
    }

    /**
     * SETs issued in the same second come back from both reads in one order, by {@code jti}: the push executor
     * holds a stream on {@code peek}'s first SET and posts in {@code dueForPush}'s order, so the two must agree
     * (SsfStore#peek). Ten minted jtis, so the store's own order is all but certain to be another one. The order is
     * String's, which is bytewise for a jti's base64url: a glibc en_US.utf8 database sorts them otherwise (F-0236).
     */
    @Test
    void aSecondsSetsComeBackInJtiOrderFromBothReads() {
        String id = newId();
        this.store.createStream(pushStream(id, StreamStatus.ENABLED));
        List<String> minted = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            String jti = SetMinter.newJti();
            minted.add(jti);
            this.store.enqueue(PendingSet.fresh(jti, id, "k", "e", "jws", 100, 0));
        }
        List<String> sorted = minted.stream().sorted().toList();

        assertEquals(sorted, jtis(this.store.peek(id, 10)));
        assertEquals(sorted, jtis(this.store.dueForPush(100, 10)));
    }

    @Test
    void dueForPushRespectsNextAttemptTimeAndItsLimit() {
        String id = newId();
        this.store.createStream(pushStream(id, StreamStatus.ENABLED));
        this.store.enqueue(new PendingSet("j1", id, "k", "e", "jws", 100, 0, 0, 50));
        this.store.enqueue(new PendingSet("j2", id, "k", "e", "jws", 100, 0, 0, 200));
        this.store.enqueue(new PendingSet("j3", id, "k", "e", "jws", 101, 0, 0, 100));

        assertEquals(List.of("j1", "j3"), jtis(this.store.dueForPush(100, 10)), "due at or before now");
        assertEquals(List.of("j1"), jtis(this.store.dueForPush(100, 1)));
        assertTrue(this.store.dueForPush(100, 0).isEmpty());
        assertEquals(List.of("j1", "j2", "j3"), jtis(this.store.dueForPush(200, 10)));
    }

    @Test
    void recordAttemptBumpsCountAndReschedules() {
        String id = newId();
        this.store.createStream(pollStream(id));
        PendingSet p = PendingSet.fresh("j1", id, "k", "e", "jws", 100, 0);
        this.store.enqueue(p);

        this.store.recordAttempt(p, 500);
        PendingSet after = this.store.peek(id, 1).get(0);
        assertEquals(1, after.deliveryAttempts());
        assertEquals(500, after.nextAttemptAt());

        this.store.recordAttempt(after, 900);
        PendingSet twice = this.store.peek(id, 1).get(0);
        assertEquals(2, twice.deliveryAttempts());
        assertEquals(900, twice.nextAttemptAt());
        assertEquals("jws", twice.setJws(), "the SET itself is untouched");
    }

    @Test
    void evictExpiredRemovesOnlyExpired() {
        String id = newId();
        this.store.createStream(pollStream(id));
        this.store.enqueue(new PendingSet("live", id, "k", "e", "jws", 100, 1000, 0, 0));
        this.store.enqueue(new PendingSet("dead", id, "k", "e", "jws", 100, 200, 0, 0));
        assertEquals(1, this.store.evictExpired(300));
        assertEquals(List.of("live"), jtis(this.store.peek(id, 10)));
    }

    /** An {@code expiresAt} of 0 is no expiry; the edge is inclusive; and eviction reaches every stream. */
    @Test
    void evictionIsAcrossStreamsInclusiveAndNeverTakesASetWithNoExpiry() {
        String a = newId();
        String b = newId();
        this.store.createStream(pollStream(a));
        this.store.createStream(pushStream(b, StreamStatus.PAUSED));
        this.store.enqueue(new PendingSet("forever", a, "k", "e", "jws", 100, 0, 0, 0));
        this.store.enqueue(new PendingSet("at-300", a, "k", "e", "jws", 100, 300, 0, 0));
        this.store.enqueue(new PendingSet("b-200", b, "k", "e", "jws", 100, 200, 0, 0));

        assertEquals(2, this.store.evictExpired(300));
        assertEquals(List.of("forever"), jtis(this.store.peek(a, 10)));
        assertTrue(this.store.peek(b, 10).isEmpty());
        assertEquals(0, this.store.evictExpired(4_000_000_000L), "nothing with no expiry, however late");
    }

    // ─────────────────────────────── optional members (H-SSF-3) ───────────────────────────────

    /** Whether this store keeps the optional members and SCIM records: the ldm store does not until the model has them. */
    protected boolean keepsWhatTheModelLacks() {
        return true;
    }

    @Test
    void theStoreSaysWhetherItKeepsTheOptionalMembersAndScimRecords() {
        assertEquals(keepsWhatTheModelLacks(), this.store.keepsOptionalStreamMembers());
        assertEquals(keepsWhatTheModelLacks(), this.store.keepsScimUsers());
    }

    /** SSF 1.0 §8.1.1's optional members are stored and read back, through a create and through an update. */
    @Test
    @Requirement("SSF §8.1.1")
    void theOptionalMembersAreStoredAndReadBack() {
        String id = newId();
        this.store.createStream(pollStream(id).toBuilder().description("For receiver A \u00e9").minVerificationInterval(30)
                .inactivityTimeout(86_400L).build());
        Stream read = this.store.getStream(id).orElseThrow();
        if (!keepsWhatTheModelLacks()) {
            assertNull(read.description(), "a store that does not keep the members reads the stream back without them");
            assertNull(read.minVerificationInterval());
            assertNull(read.inactivityTimeout());
            assertEquals(pollStream(id).audience(), read.audience(), "and keeps the rest");
            return;
        }
        assertEquals("For receiver A \u00e9", read.description());
        assertEquals(30, read.minVerificationInterval());
        assertEquals(86_400L, read.inactivityTimeout());
        assertEquals(read.description(), this.store.listStreams().get(0).description());

        this.store.updateStream(read.toBuilder().description("changed").minVerificationInterval(5).inactivityTimeout(60L).build());
        Stream changed = this.store.getStream(id).orElseThrow();
        assertEquals("changed", changed.description());
        assertEquals(5, changed.minVerificationInterval());
        assertEquals(60L, changed.inactivityTimeout());

        this.store.updateStream(changed.toBuilder().description(null).minVerificationInterval(null).inactivityTimeout(null).build());
        Stream cleared = this.store.getStream(id).orElseThrow();
        assertNull(cleared.description());
        assertNull(cleared.minVerificationInterval());
        assertNull(cleared.inactivityTimeout());
    }

    @Test
    void aStreamWithoutTheOptionalMembersHasNone() {
        String id = newId();
        this.store.createStream(pollStream(id));
        Stream read = this.store.getStream(id).orElseThrow();
        assertNull(read.description());
        assertNull(read.minVerificationInterval());
        assertNull(read.inactivityTimeout());
    }

    // ─────────────────────────────── SCIM users (H-SSF-4) ───────────────────────────────

    @Test
    void aScimUserIsWrittenReadReplacedListedAndDeleted() {
        SubjectId alice = SubjectId.email("alice@example.com");
        if (!keepsWhatTheModelLacks()) {
            this.store.putScimUser(new ScimUser(alice, "alice", "ext-1", false, List.of(), 100, 200));
            assertTrue(this.store.getScimUser(alice.canonicalKey()).isEmpty(), "a store that keeps no records answers none");
            assertTrue(this.store.listScimUsers().isEmpty());
            assertFalse(this.store.deleteScimUser(alice.canonicalKey()));
            return;
        }
        String a = newId();
        String b = newId();
        this.store.createStream(pollStream(a));
        this.store.addSubject(a, alice);
        assertTrue(this.store.getScimUser(alice.canonicalKey()).isEmpty());
        assertTrue(this.store.listScimUsers().isEmpty());

        this.store.putScimUser(new ScimUser(alice, "alice", "ext-1", true, List.of(), 100, 200));
        ScimUser read = this.store.getScimUser(alice.canonicalKey()).orElseThrow();
        assertEquals(new ScimUser(alice, "alice", "ext-1", true, List.of(), 100, 200), read);

        this.store.putScimUser(new ScimUser(alice, null, null, false, List.of(a, b), 100, 300));
        assertEquals(new ScimUser(alice, null, null, false, List.of(a, b), 100, 300),
                this.store.getScimUser(alice.canonicalKey()).orElseThrow(), "replaced, not added beside");
        assertEquals(1, this.store.listScimUsers().size());

        SubjectId bob = SubjectId.issSub("https://op.example.com", "bob");
        this.store.putScimUser(new ScimUser(bob, "bob", null, true, List.of(), 1, 1));
        assertEquals(Set.of(alice, bob), Set.copyOf(this.store.listScimUsers().stream().map(ScimUser::subject).toList()));

        assertEquals(List.of(alice), this.store.listSubjects(a), "a record is not a membership");
        assertTrue(this.store.deleteScimUser(alice.canonicalKey()));
        assertFalse(this.store.deleteScimUser(alice.canonicalKey()));
        assertTrue(this.store.getScimUser(alice.canonicalKey()).isEmpty());
        assertTrue(this.store.hasSubject(a, alice), "and forgetting one leaves the memberships alone");
        this.store.deleteStream(a);
        assertTrue(this.store.getScimUser(bob.canonicalKey()).isPresent(), "deleting a stream leaves the records alone");
    }
}
