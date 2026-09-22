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

    private static final String PROVISIONER_SCOPE = "ssf.provision";
    /** The provisioning client: holds the provisioner scope, owns no streams. */
    private static final AuthContext PROVISIONER = AuthContext.active("scim-provisioner", Set.of(PROVISIONER_SCOPE));
    private static final AuthContext RECEIVER = AuthContext.active("receiver-client", Set.of("ssf.manage"));

    private InMemorySsfStore store;
    private ScimSubjectService svc;
    private final SubjectId alice = SubjectId.email("alice@example.com");

    @BeforeEach
    void setUp() {
        store = new InMemorySsfStore();
        svc = serviceWith(new SsfConfiguration.Builder().issuer("https://op.example.com")
                .provisionerScope(PROVISIONER_SCOPE).build());
    }

    private ScimSubjectService serviceWith(SsfConfiguration cfg) {
        SsfEventEmitter emitter = new SsfEventEmitter(store, new SetMinter("RS256", new TestSigningKeyProvider("k")), cfg);
        return new ScimSubjectService(store, emitter, cfg);
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
        svc.provision(aliceUser(List.of("s1", "risc")), PROVISIONER);
        assertTrue(store.hasSubject("s1", alice));
        assertTrue(store.hasSubject("risc", alice));
    }

    @Test
    void disablingDeprovisionsAndEmitsRisc() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        stream("risc", SsfEventTypes.RISC_ACCOUNT_DISABLED);
        svc.provision(aliceUser(List.of("s1", "risc")), PROVISIONER);

        // active:false -> deprovision
        svc.provision(Map.of("userName", "alice",
                "emails", List.of(Map.of("value", "alice@example.com", "primary", true)),
                "active", false), PROVISIONER);

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
        assertEquals(1, svc.deprovision(alice, PROVISIONER), "the one stream holding her");
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
                () -> svc.provision(aliceUser(List.of("no-such-stream")), PROVISIONER));
    }

    // ─────────────────────────────── whose authority ───────────────────────────────
    //
    // A deprovision has the transmitter sign an account-disabled about a subject the caller names, and a
    // receiving PingFederate revokes grants on that. It is a provisioner's to ask for and never a receiver's.

    private static final AuthContext OTHER = AuthContext.active("receiver-b", Set.of("ssf.manage"));

    @Test
    void aProvisionerActsAcrossEveryReceiversStreams() throws Exception {
        stream("a", SsfEventTypes.RISC_ACCOUNT_DISABLED);
        stream("b", SsfEventTypes.RISC_ACCOUNT_DISABLED, OTHER.clientId());
        stream("unowned", SsfEventTypes.RISC_ACCOUNT_DISABLED, null);
        stream("without-her", SsfEventTypes.RISC_ACCOUNT_DISABLED, OTHER.clientId());

        svc.assign(alice, List.of("a", "b", "unowned"), PROVISIONER);
        assertTrue(store.hasSubject("a", alice) && store.hasSubject("b", alice) && store.hasSubject("unowned", alice));

        assertEquals(3, svc.deprovision(alice, PROVISIONER), "three streams held her; the fourth did not and is not counted");
        assertEquals(3, store.peek("a", 10).size() + store.peek("b", 10).size() + store.peek("unowned", 10).size());
        assertEquals(0, store.peek("without-her", 10).size());
        assertFalse(store.hasSubject("a", alice) || store.hasSubject("b", alice) || store.hasSubject("unowned", alice));
    }

    /**
     * The receiver scope does not provision - not even on the receiver's own stream, which is where the
     * signed account-disabled would land for it to carry elsewhere.
     */
    @Test
    void aReceiverCannotProvisionOrDeprovisionEvenOnItsOwnStream() throws Exception {
        stream("mine", SsfEventTypes.RISC_ACCOUNT_DISABLED);
        store.addSubject("mine", alice);
        AuthContext both = AuthContext.active("receiver-client", Set.of("ssf.manage", PROVISIONER_SCOPE));

        for (AuthContext refused : new AuthContext[] {RECEIVER, AuthContext.inactive(), null,
                AuthContext.active("scim-provisioner", Set.of("SSF.PROVISION"))}) {
            assertThrows(StreamManagementService.ForbiddenException.class, () -> svc.deprovision(alice, refused));
            assertThrows(StreamManagementService.ForbiddenException.class,
                    () -> svc.assign(SubjectId.email("bob@example.com"), List.of("mine"), refused));
            assertThrows(StreamManagementService.ForbiddenException.class,
                    () -> svc.provision(aliceUser(List.of("mine")), refused));
        }
        assertEquals(0, store.peek("mine", 10).size(), "nothing was signed");
        assertTrue(store.hasSubject("mine", alice), "and nothing removed");
        assertFalse(store.hasSubject("mine", SubjectId.email("bob@example.com")), "or added");

        // control: the same calls from a token that does carry the scope go through, so it was the scope
        svc.assign(SubjectId.email("bob@example.com"), List.of("mine"), both);
        assertEquals(1, svc.deprovision(alice, both));
        assertEquals(1, store.peek("mine", 10).size());
    }

    /** Fail closed: with no provisioner scope configured there are no provisioners, whatever a token carries. */
    @Test
    void withNoProvisionerScopeConfiguredNobodyProvisions() throws Exception {
        ScimSubjectService unconfigured = serviceWith(new SsfConfiguration.Builder().issuer("https://op.example.com").build());
        stream("s", SsfEventTypes.RISC_ACCOUNT_DISABLED);
        store.addSubject("s", alice);

        for (AuthContext caller : new AuthContext[] {PROVISIONER, RECEIVER}) {
            assertThrows(StreamManagementService.ForbiddenException.class, () -> unconfigured.deprovision(alice, caller));
            assertThrows(StreamManagementService.ForbiddenException.class, () -> unconfigured.assign(alice, List.of("s"), caller));
        }
        assertEquals(0, store.peek("s", 10).size());

        assertEquals(1, svc.deprovision(alice, PROVISIONER)); // control: configured, the same caller and stream work
    }
}
