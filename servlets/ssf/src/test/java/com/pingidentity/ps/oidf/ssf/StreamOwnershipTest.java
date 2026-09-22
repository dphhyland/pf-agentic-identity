/*
 * Whose stream it is: a receiver is admitted to the streams it created and to no others.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.ThrowingConsumer;

/**
 * Two receivers hold the same scope. Until streams had owners that made each of them the manager of the
 * other's: the list endpoint handed out every stream id, and every operation took any id it was given.
 *
 * <p>Each refusal here is checked three ways, because a 404 on its own proves very little. It must be the
 * refusal a stream that was never created gets, or the difference tells a receiver which ids are taken.
 * Nothing may have been applied on the way to it. And the same call from the stream's owner must succeed -
 * without that control, a test that sent a request the service would have refused from anyone passes for
 * the wrong reason and goes on passing once the check is gone.
 */
class StreamOwnershipTest {

    private static final AuthContext OWNER = AuthContext.active("receiver-a", Set.of("ssf.manage"));
    private static final AuthContext OTHER = AuthContext.active("receiver-b", Set.of("ssf.manage"));
    private static final String ABSENT = "00000000-0000-4000-8000-00000000dead";
    private static final SubjectId ALICE = SubjectId.email("alice@example.com");

    private InMemorySsfStore store;
    private StreamManagementService svc;

    @BeforeEach
    void setUp() {
        store = new InMemorySsfStore();
        svc = serviceWith(new SsfConfiguration.Builder().issuer("https://op.example.com").build());
    }

    private StreamManagementService serviceWith(SsfConfiguration cfg) {
        return new StreamManagementService(store, new SetMinter("RS256", new TestSigningKeyProvider("k")), cfg);
    }

    private static Map<String, Object> pollBody() {
        return Map.of(
                "delivery", Map.of("method", DeliveryMethod.POLL.urn()),
                "events_requested", List.of(SsfEventTypes.CAEP_SESSION_REVOKED));
    }

    private String streamOf(AuthContext receiver) {
        return (String) svc.createStream(pollBody(), receiver).get("stream_id");
    }

    /** A stream as one stored before streams had owners: written to the store, with none. */
    private String unownedStream(String audience) {
        String id = UUID.randomUUID().toString();
        store.createStream(Stream.builder().id(id).audience(audience).deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED)).status(StreamStatus.ENABLED).build());
        return id;
    }

    /**
     * {@code op} is refused for {@code someoneElses} exactly as it is for an id nobody has: same exception,
     * and the same message once the id each was asked about is taken out of it.
     */
    private static void assertLooksAbsent(String someoneElses, ThrowingConsumer<String> op) {
        StreamManagementService.NotFoundException theirs =
                assertThrows(StreamManagementService.NotFoundException.class, () -> op.accept(someoneElses));
        StreamManagementService.NotFoundException nobodys =
                assertThrows(StreamManagementService.NotFoundException.class, () -> op.accept(ABSENT));
        assertEquals(nobodys.getMessage().replace(ABSENT, "<id>"), theirs.getMessage().replace(someoneElses, "<id>"),
                "a stream that is another receiver's must not be tellable from one that does not exist");
    }

    // ─────────────────────────────── whose it becomes ───────────────────────────────

    @Test
    void aStreamBelongsToTheClientThatCreatedItWhateverAudienceThatClientChose() {
        Map<String, Object> body = new HashMap<>(pollBody());
        body.put("aud", OTHER.clientId()); // a receiver may still pick its own aud, even another client's id

        String id = (String) svc.createStream(body, OWNER).get("stream_id");

        assertEquals(OWNER.clientId(), store.getStream(id).orElseThrow().ownerClientId());
        assertLooksAbsent(id, sid -> svc.getStream(sid, OTHER)); // naming B as the audience gave B nothing
        assertEquals(id, svc.getStream(id, OWNER).get("stream_id"));
    }

    @Test
    @Requirement("SSF §8.1.1.1")
    void aTokenThatNamesNoClientCannotCreateAStream() {
        Map<String, Object> withAudience = new HashMap<>(pollBody());
        withAudience.put("aud", "https://receiver.example.com");

        for (String noClient : new String[] {null, "", "  "}) {
            AuthContext unidentified = AuthContext.active(noClient, Set.of("ssf.manage"));
            assertThrows(StreamManagementService.ForbiddenException.class, () -> svc.createStream(pollBody(), unidentified));
            // an aud of its own does not stand in for a client: the stream would still be nobody's
            assertThrows(StreamManagementService.ForbiddenException.class, () -> svc.createStream(withAudience, unidentified));
        }
        assertThrows(StreamManagementService.ForbiddenException.class, () -> svc.createStream(pollBody(), null));
        assertTrue(store.listStreams().isEmpty(), "a refused create must leave nothing behind, least of all an ownerless stream");

        // control: the same two bodies are fine from a token that does name a client
        svc.createStream(pollBody(), OWNER);
        svc.createStream(withAudience, OWNER);
        assertEquals(2, store.listStreams().size());
    }

    /**
     * A client id is an opaque string and two that differ at all are two clients. Folding case or trimming
     * here would merge them: whoever registers {@code Receiver-A} would be handed {@code receiver-a}'s streams.
     */
    @Test
    void aClientIdThatDiffersOnlyInCaseOrPaddingIsADifferentClient() {
        String id = streamOf(OWNER); // receiver-a

        for (String nearly : new String[] {"Receiver-A", "RECEIVER-A", " receiver-a", "receiver-a ", "receiver-a\t"}) {
            AuthContext lookalike = AuthContext.active(nearly, Set.of("ssf.manage"));
            assertLooksAbsent(id, sid -> svc.getStream(sid, lookalike));
            assertEquals(List.of(), svc.listStreams(lookalike), nearly);
        }

        assertEquals(id, svc.getStream(id, AuthContext.active("receiver-a", Set.of("ssf.manage"))).get("stream_id")); // control
    }

    // ─────────────────────────────── stream configuration ───────────────────────────────

    @Test
    @Requirement("SSF §8.1.1.2")
    void aReceiverIsListedItsOwnStreamsAndNobodyElses() {
        String a1 = streamOf(OWNER);
        String a2 = streamOf(OWNER);
        String b1 = streamOf(OTHER);

        assertEquals(Set.of(a1, a2), idsOf(svc.listStreams(OWNER)));
        assertEquals(Set.of(b1), idsOf(svc.listStreams(OTHER)));
        assertEquals(List.of(), svc.listStreams(AuthContext.active("receiver-c", Set.of("ssf.manage"))),
                "a receiver with no streams gets an empty list, not everyone else's");
    }

    @Test
    @Requirement("SSF §8.1.1.2")
    void anotherReceiversStreamCannotBeRead() {
        String id = streamOf(OWNER);

        assertLooksAbsent(id, sid -> svc.getStream(sid, OTHER));

        assertEquals(id, svc.getStream(id, OWNER).get("stream_id")); // control
    }

    @Test
    @Requirement("SSF §8.1.1.3")
    void anotherReceiversStreamCannotBeUpdated() {
        String id = streamOf(OWNER);
        Map<String, Object> change = Map.of("events_requested", List.of(SsfEventTypes.CAEP_CREDENTIAL_CHANGE));

        assertLooksAbsent(id, sid -> svc.updateStream(sid, change, OTHER));
        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED), store.getStream(id).orElseThrow().eventsRequested(),
                "and the refused update was not applied");

        svc.updateStream(id, change, OWNER); // control: the same change, from the owner
        assertEquals(List.of(SsfEventTypes.CAEP_CREDENTIAL_CHANGE), store.getStream(id).orElseThrow().eventsRequested());
    }

    @Test
    @Requirement("SSF §8.1.1.4")
    void anotherReceiversStreamCannotBeReplaced() {
        String id = streamOf(OWNER);
        Map<String, Object> replacement = Map.of("delivery", Map.of("method", DeliveryMethod.POLL.urn()));

        assertLooksAbsent(id, sid -> svc.replaceStream(sid, replacement, OTHER));
        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED), store.getStream(id).orElseThrow().eventsRequested(),
                "a replacement that leaves events_requested out deletes it - this one must not have");

        svc.replaceStream(id, replacement, OWNER); // control
        assertEquals(List.of(), store.getStream(id).orElseThrow().eventsRequested());
    }

    @Test
    @Requirement("SSF §8.1.1.5")
    void anotherReceiversStreamCannotBeDeleted() {
        String id = streamOf(OWNER);

        assertLooksAbsent(id, sid -> svc.deleteStream(sid, OTHER));
        assertTrue(store.getStream(id).isPresent(), "and it is still there");

        svc.deleteStream(id, OWNER); // control
        assertTrue(store.getStream(id).isEmpty());
    }

    /** Not an ownership case: a stream that goes between the check and the delete is reported as not found. */
    @Test
    void aStreamDeletedFromUnderItsOwnerIsNotFound() {
        SsfStore vanishing = mock(SsfStore.class);
        Stream mine = Stream.builder().id("s1").audience("a").ownerClientId(OWNER.clientId())
                .deliveryMethod(DeliveryMethod.POLL).build();
        when(vanishing.getStream("s1")).thenReturn(Optional.of(mine));
        when(vanishing.deleteStream("s1")).thenReturn(false);
        StreamManagementService overIt = new StreamManagementService(vanishing, new SetMinter("RS256",
                new TestSigningKeyProvider("k")), new SsfConfiguration.Builder().issuer("https://op.example.com").build());

        assertThrows(StreamManagementService.NotFoundException.class, () -> overIt.deleteStream("s1", OWNER));
    }

    // ─────────────────────────────── status ───────────────────────────────

    @Test
    @Requirement("SSF §8.1.2.1")
    void anotherReceiversStreamStatusCannotBeRead() {
        String id = streamOf(OWNER);

        assertLooksAbsent(id, sid -> svc.getStatus(sid, OTHER));

        assertEquals("enabled", svc.getStatus(id, OWNER).get("status")); // control
    }

    @Test
    @Requirement("SSF §8.1.2.2")
    void anotherReceiversStreamCannotBePausedOrDisabled() {
        String id = streamOf(OWNER);

        assertLooksAbsent(id, sid -> svc.setStatus(sid, "disabled", "not yours to disable", OTHER));
        // An invalid status is a 400 to the owner. To anyone else the stream comes first and is not there,
        // or the difference between the two answers says the id is real.
        assertLooksAbsent(id, sid -> svc.setStatus(sid, "no-such-status", null, OTHER));
        assertEquals(StreamStatus.ENABLED, store.getStream(id).orElseThrow().status(), "and it is still delivering");

        assertEquals("paused", svc.setStatus(id, "paused", "mine to pause", OWNER).get("status")); // control
    }

    // ─────────────────────────────── subjects ───────────────────────────────

    @Test
    @Requirement("SSF §8.1.3.2")
    void aSubjectCannotBeAddedToAnotherReceiversStream() {
        String id = streamOf(OWNER);

        assertLooksAbsent(id, sid -> svc.addSubject(sid, ALICE, OTHER));
        assertFalse(store.hasSubject(id, ALICE), "or that receiver starts being sent events about a subject it never asked for");

        svc.addSubject(id, ALICE, OWNER); // control
        assertTrue(store.hasSubject(id, ALICE));
    }

    @Test
    @Requirement("SSF §8.1.3.3")
    void aSubjectCannotBeRemovedFromAnotherReceiversStream() {
        String id = streamOf(OWNER);
        svc.addSubject(id, ALICE, OWNER);

        assertLooksAbsent(id, sid -> svc.removeSubject(sid, ALICE, OTHER));
        assertTrue(store.hasSubject(id, ALICE), "or that receiver silently stops hearing about her");

        svc.removeSubject(id, ALICE, OWNER); // control
        assertFalse(store.hasSubject(id, ALICE));
    }

    // ─────────────────────────────── verification and poll ───────────────────────────────

    @Test
    @Requirement("SSF §8.1.4.2")
    void verificationCannotBeTriggeredOnAnotherReceiversStream() throws Exception {
        String id = streamOf(OWNER);

        assertLooksAbsent(id, sid -> svc.verify(sid, "state", OTHER));
        assertEquals(0, store.peek(id, 10).size(), "and no SET was minted into it");

        svc.verify(id, "state", OWNER); // control
        assertEquals(1, store.peek(id, 10).size());
    }

    /**
     * Deliberately untagged. RFC 8936 §3 says a transmitter "may choose to validate the identity of the SET
     * Recipient", and SSF says only that the management authorization schemes SHOULD also protect a polling
     * endpoint: neither requires a poll to be confined to the stream's own receiver. That is this
     * transmitter's rule, following from the streams being per-receiver, and tagging it with a clause that
     * does not demand it would report the clause as covered by a test of something else.
     */
    @Test
    void anotherReceiverCanNeitherReadNorAcknowledgeAStreamsEvents() throws Exception {
        String id = streamOf(OWNER);
        String jti = svc.verify(id, "state", OWNER);

        assertLooksAbsent(id, sid -> svc.poll(sid, null, 10, true, OTHER));
        // The ack is the dangerous half. Acknowledging deletes, so a poll that was refused its SETs but had
        // its acks honoured would let one receiver destroy another's events without ever seeing them.
        assertLooksAbsent(id, sid -> svc.poll(sid, List.of(jti), 0, true, OTHER));
        assertEquals(1, store.peek(id, 10).size(), "the refused poll acknowledged nothing");

        Map<?, ?> sets = (Map<?, ?>) svc.poll(id, null, 10, true, OWNER).get("sets"); // control: there to be read...
        assertEquals(Set.of(jti), sets.keySet());
        svc.poll(id, List.of(jti), 0, true, OWNER);                                     // ...and to be acknowledged
        assertEquals(0, store.peek(id, 10).size());
    }

    // ─────────────────────────────── the owner is for good ───────────────────────────────

    @Test
    void aStreamIsStillItsOwnersAfterEveryKindOfWriteToIt() {
        String id = streamOf(OWNER);

        svc.updateStream(id, Map.of("events_requested", List.of(SsfEventTypes.CAEP_CREDENTIAL_CHANGE)), OWNER);
        svc.replaceStream(id, Map.of("delivery", Map.of("method", DeliveryMethod.POLL.urn())), OWNER);
        svc.setStatus(id, "paused", null, OWNER);
        // what the push executor does to a stream whose endpoint keeps failing, with no receiver involved
        store.updateStream(store.getStream(id).orElseThrow().withStatus(StreamStatus.PAUSED, "dead-letter", 1L));

        assertEquals(OWNER.clientId(), store.getStream(id).orElseThrow().ownerClientId(),
                "a write that dropped the owner would orphan the stream: its own receiver locked out of it");
        assertEquals(id, svc.getStream(id, OWNER).get("stream_id"));
        assertLooksAbsent(id, sid -> svc.getStream(sid, OTHER));
    }

    // ─────────────────────────────── streams that pre-date ownership ───────────────────────────────

    @Test
    void aStreamWithNoOwnerIsNobodysByDefault() {
        // its aud is exactly the asking client's id: the strongest claim a receiver could make, and not one
        // to honour, because aud is whatever the stream's creator typed
        String id = unownedStream(OTHER.clientId());

        assertLooksAbsent(id, sid -> svc.getStream(sid, OTHER));
        assertLooksAbsent(id, sid -> svc.poll(sid, null, 10, true, OTHER));
        assertLooksAbsent(id, sid -> svc.deleteStream(sid, OTHER));
        assertEquals(List.of(), svc.listStreams(OTHER));

        assertTrue(store.getStream(id).isPresent(), "control: it is there, and was not deleted - it is only that nobody is admitted");
    }

    /**
     * A stream with no owner and a token with no client are both null, and the two must never be compared.
     * This is the case a plain {@code Objects.equals(owner, caller)} gets wrong, in the worst direction:
     * every unowned stream, to the callers least is known about.
     */
    @Test
    void aTokenThatNamesNoClientIsNotAdmittedToAStreamWithNoOwner() {
        String id = unownedStream("https://receiver.example.com");

        for (String noClient : new String[] {null, "", "  "}) {
            AuthContext unidentified = AuthContext.active(noClient, Set.of("ssf.manage"));
            assertLooksAbsent(id, sid -> svc.getStream(sid, unidentified));
            assertLooksAbsent(id, sid -> svc.poll(sid, null, 10, true, unidentified));
            assertEquals(List.of(), svc.listStreams(unidentified));
        }
        assertLooksAbsent(id, sid -> svc.getStream(sid, null));

        // The same holds with an adopter configured, and then there is a control: it is the caller's missing
        // identity that is refused, not the stream that is unreachable.
        StreamManagementService adopting = serviceWith(new SsfConfiguration.Builder().issuer("https://op.example.com")
                .unownedStreamOwner(OWNER.clientId()).build());
        assertThrows(StreamManagementService.NotFoundException.class,
                () -> adopting.getStream(id, AuthContext.active(null, Set.of("ssf.manage"))));
        assertEquals(id, adopting.getStream(id, OWNER).get("stream_id"));
    }

    @Test
    void theClientNamedForUnownedStreamsIsAdmittedToThemAndNobodyElseIs() throws Exception {
        String unowned = unownedStream("https://receiver.example.com");
        String someoneElses = streamOf(OTHER);
        StreamManagementService adopting = serviceWith(new SsfConfiguration.Builder().issuer("https://op.example.com")
                .unownedStreamOwner(OWNER.clientId()).build());

        assertEquals(unowned, adopting.getStream(unowned, OWNER).get("stream_id"));
        assertEquals(Set.of(unowned), idsOf(adopting.listStreams(OWNER)));
        adopting.verify(unowned, "s", OWNER);
        assertEquals(1, ((Map<?, ?>) adopting.poll(unowned, null, 10, true, OWNER).get("sets")).size());

        // naming one client admits one client
        assertThrows(StreamManagementService.NotFoundException.class, () -> adopting.getStream(unowned, OTHER));
        assertEquals(Set.of(someoneElses), idsOf(adopting.listStreams(OTHER)));
        // and it is a claim on streams with no owner, not on anyone's: B's stream stays B's
        assertThrows(StreamManagementService.NotFoundException.class, () -> adopting.getStream(someoneElses, OWNER));
    }

    @Test
    void admittingAClientToUnownedStreamsWritesNothingSoUnsettingItWithdrawsIt() {
        String unowned = unownedStream("https://receiver.example.com");
        StreamManagementService adopting = serviceWith(new SsfConfiguration.Builder().issuer("https://op.example.com")
                .unownedStreamOwner(OWNER.clientId()).build());

        adopting.updateStream(unowned, Map.of("events_requested", List.of(SsfEventTypes.CAEP_CREDENTIAL_CHANGE)), OWNER);
        adopting.setStatus(unowned, "paused", null, OWNER);

        assertEquals(null, store.getStream(unowned).orElseThrow().ownerClientId(), "managing it did not claim it");
        assertLooksAbsent(unowned, sid -> svc.getStream(sid, OWNER)); // svc has no adopter configured
    }

    /** Said at boot, so an operator reads it in a log instead of working it out from a receiver's 404s. */
    @Test
    void streamsWithNoOwnerAreCountedAtBootAndAStoreThatCannotBeAskedDoesNotStopIt() {
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        streamOf(OWNER);
        assertEquals(0, SsfSupport.warnOfUnownedStreams(store, cfg), "control: an owned stream is not counted");

        unownedStream("https://receiver.example.com");
        unownedStream("https://receiver.example.com");
        assertEquals(2, SsfSupport.warnOfUnownedStreams(store, cfg));
        assertEquals(2, SsfSupport.warnOfUnownedStreams(store, new SsfConfiguration.Builder()
                .issuer("https://op.example.com").unownedStreamOwner(OWNER.clientId()).build()), "counted whoever is named for them");

        SsfStore down = mock(SsfStore.class);
        when(down.listStreams()).thenThrow(new IllegalStateException("connection refused"));
        assertEquals(-1, SsfSupport.warnOfUnownedStreams(down, cfg), "a store that is down at boot must not take the transmitter with it");
    }

    private static Set<Object> idsOf(List<Map<String, Object>> streams) {
        return streams.stream().map(s -> s.get("stream_id")).collect(Collectors.toSet());
    }
}
