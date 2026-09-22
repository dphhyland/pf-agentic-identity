/*
 * SCIM provisioning -> stream subjects; deprovision/disable -> remove + RISC account-disabled.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ScimSubjectServiceTest {

    private static final AuthContext RECEIVER = AuthContext.active("receiver-client", Set.of("ssf.manage"));

    private InMemorySsfStore store;
    private ScimSubjectService svc;
    private final SubjectId alice = SubjectId.email("alice@example.com");

    @BeforeEach
    void setUp() {
        store = new InMemorySsfStore();
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        SsfEventEmitter emitter = new SsfEventEmitter(store, new SetMinter("RS256", new TestSigningKeyProvider("k")), cfg);
        svc = new ScimSubjectService(store, emitter, cfg);
    }

    private void stream(String id, String event) {
        stream(id, event, RECEIVER.clientId());
    }

    private void stream(String id, String event, String owner) {
        store.createStream(Stream.builder().id(id).audience("https://r/" + id).ownerClientId(owner).deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(List.of(event)).eventsDelivered(List.of(event)).status(StreamStatus.ENABLED).build());
    }

    private Map<String, Object> aliceUser(Object streams) {
        return Map.of(
                "userName", "alice",
                "emails", List.of(Map.of("value", "alice@example.com", "primary", true)),
                ScimSubjectService.SSF_EXT, Map.of("streams", streams));
    }

    @Test
    void provisioningAssignsSubjectToStreams() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        stream("risc", SsfEventTypes.RISC_ACCOUNT_DISABLED);
        svc.provision(aliceUser(List.of("s1", "risc")), RECEIVER);
        assertTrue(store.hasSubject("s1", alice));
        assertTrue(store.hasSubject("risc", alice));
    }

    @Test
    void disablingDeprovisionsAndEmitsRisc() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        stream("risc", SsfEventTypes.RISC_ACCOUNT_DISABLED);
        svc.provision(aliceUser(List.of("s1", "risc")), RECEIVER);

        // active:false -> deprovision
        svc.provision(Map.of("userName", "alice",
                "emails", List.of(Map.of("value", "alice@example.com", "primary", true)),
                "active", false), RECEIVER);

        // the RISC-subscribing stream received an account-disabled SET before removal
        assertEquals(1, store.peek("risc", 10).size());
        assertEquals(0, store.peek("s1", 10).size(), "s1 doesn't deliver account-disabled");
        // and the subject is gone from every stream
        assertFalse(store.hasSubject("s1", alice));
        assertFalse(store.hasSubject("risc", alice));
    }

    @Test
    void deleteDeprovisionsBySubject() throws Exception {
        stream("risc", SsfEventTypes.RISC_ACCOUNT_DISABLED);
        store.addSubject("risc", alice);
        assertEquals(0, svc.deprovision(alice, RECEIVER), "every stream holding her was the caller's, so none was left alone");
        assertEquals(1, store.peek("risc", 10).size());
        assertFalse(store.hasSubject("risc", alice));
    }

    @Test
    void subjectDerivationPrefersEmailThenUserNameThenExternalId() {
        assertEquals(SubjectId.email("a@b.com"),
                svc.subjectOf(Map.of("emails", List.of(Map.of("value", "a@b.com")))));
        assertEquals(SubjectId.issSub("https://op.example.com", "bob"),
                svc.subjectOf(Map.of("userName", "bob")));
        assertEquals(SubjectId.opaque("ext-1"), svc.subjectOf(Map.of("externalId", "ext-1")));
    }

    @Test
    void provisioningUnknownStreamIs404() {
        assertThrows(StreamManagementService.NotFoundException.class,
                () -> svc.provision(aliceUser(List.of("no-such-stream")), RECEIVER));
    }

    // ─────────────────────────────── whose streams ───────────────────────────────
    //
    // This endpoint takes the same token as the Stream Management API. Scoping that API and not this would
    // leave every refusal there one URL away from being undone.

    private static final AuthContext OTHER = AuthContext.active("receiver-b", Set.of("ssf.manage"));

    @Test
    @Requirement("SSF §8.1.3.2")
    void provisioningCannotAddASubjectToAnotherReceiversStream() {
        stream("theirs", SsfEventTypes.CAEP_SESSION_REVOKED, OTHER.clientId());

        StreamManagementService.NotFoundException theirs = assertThrows(StreamManagementService.NotFoundException.class,
                () -> svc.provision(aliceUser(List.of("theirs")), RECEIVER));
        StreamManagementService.NotFoundException nobodys = assertThrows(StreamManagementService.NotFoundException.class,
                () -> svc.provision(aliceUser(List.of("absent")), RECEIVER));
        assertEquals(nobodys.getMessage().replace("absent", "<id>"), theirs.getMessage().replace("theirs", "<id>"),
                "another receiver's stream must not be tellable from one that does not exist");
        assertFalse(store.hasSubject("theirs", alice));

        assertDoesNotThrow(() -> svc.provision(aliceUser(List.of("theirs")), OTHER)); // control: its owner may
        assertTrue(store.hasSubject("theirs", alice));
    }

    @Test
    void provisioningCannotAddASubjectToAStreamWithNoOwner() {
        stream("unowned", SsfEventTypes.CAEP_SESSION_REVOKED, null);

        assertThrows(StreamManagementService.NotFoundException.class,
                () -> svc.assign(alice, List.of("unowned"), RECEIVER));
        assertThrows(StreamManagementService.NotFoundException.class,
                () -> svc.assign(alice, List.of("unowned"), AuthContext.active(null, Set.of("ssf.manage"))));
        assertFalse(store.hasSubject("unowned", alice));

        // control: the stream is assignable - by the one client named for streams with no owner. So the
        // refusals above are about who was asking, not a stream this fixture made unreachable.
        SsfConfiguration adopting = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .unownedStreamOwner(RECEIVER.clientId()).build();
        ScimSubjectService withAdopter = new ScimSubjectService(store,
                new SsfEventEmitter(store, new SetMinter("RS256", new TestSigningKeyProvider("k")), adopting), adopting);
        withAdopter.assign(alice, List.of("unowned"), RECEIVER);
        assertTrue(store.hasSubject("unowned", alice));
    }

    @Test
    @Requirement("SSF §8.1.3.3")
    void deprovisioningLeavesAnotherReceiversStreamsAlone() throws Exception {
        stream("mine", SsfEventTypes.RISC_ACCOUNT_DISABLED);
        stream("theirs", SsfEventTypes.RISC_ACCOUNT_DISABLED, OTHER.clientId());
        store.addSubject("mine", alice);
        store.addSubject("theirs", alice);

        int leftAlone = svc.deprovision(alice, RECEIVER);

        assertEquals(1, leftAlone, "the stream passed over is counted, so the operator is told what the caller is not");
        assertTrue(store.hasSubject("theirs", alice), "or any receiver can stop every other hearing about a subject");
        assertEquals(0, store.peek("theirs", 10).size(),
                "and must not be told, in the transmitter's name, that an account of the caller's choosing is disabled");
        // control: the caller's own stream got both halves, so the above is ownership and not a deprovision that did nothing
        assertFalse(store.hasSubject("mine", alice));
        assertEquals(1, store.peek("mine", 10).size());
    }

    /**
     * What scoping this endpoint costs, pinned so it cannot become silent: a provisioning client that created
     * no streams used to reach every receiver with a deprovision and now reaches none. Its request still
     * succeeds - it is told nothing about other receivers' streams - but the streams it did not reach are
     * counted (and logged), and only those that actually hold the subject.
     */
    @Test
    void aProvisionerThatOwnsNoStreamsReachesNobodyAndThatIsCounted() throws Exception {
        AuthContext provisioner = AuthContext.active("scim-provisioner", Set.of("ssf.manage"));
        stream("a", SsfEventTypes.RISC_ACCOUNT_DISABLED);
        stream("b", SsfEventTypes.RISC_ACCOUNT_DISABLED, OTHER.clientId());
        stream("without-her", SsfEventTypes.RISC_ACCOUNT_DISABLED, OTHER.clientId());
        store.addSubject("a", alice);
        store.addSubject("b", alice);

        assertEquals(2, svc.deprovision(alice, provisioner), "two streams hold her; the third does not and is not counted");

        assertEquals(0, store.peek("a", 10).size() + store.peek("b", 10).size(), "nobody was signalled");
        assertTrue(store.hasSubject("a", alice) && store.hasSubject("b", alice), "and nobody lost the subject");
    }
}
