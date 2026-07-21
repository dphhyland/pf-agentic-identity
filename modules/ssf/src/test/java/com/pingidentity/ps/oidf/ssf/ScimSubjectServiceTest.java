/*
 * SCIM provisioning -> stream subjects; deprovision/disable -> remove + RISC account-disabled.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ScimSubjectServiceTest {

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
        store.createStream(Stream.builder().id(id).audience("https://r/" + id).deliveryMethod(DeliveryMethod.POLL)
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
        svc.provision(aliceUser(List.of("s1", "risc")));
        assertTrue(store.hasSubject("s1", alice));
        assertTrue(store.hasSubject("risc", alice));
    }

    @Test
    void disablingDeprovisionsAndEmitsRisc() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        stream("risc", SsfEventTypes.RISC_ACCOUNT_DISABLED);
        svc.provision(aliceUser(List.of("s1", "risc")));

        // active:false -> deprovision
        svc.provision(Map.of("userName", "alice",
                "emails", List.of(Map.of("value", "alice@example.com", "primary", true)),
                "active", false));

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
        svc.deprovision(alice);
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
                () -> svc.provision(aliceUser(List.of("no-such-stream"))));
    }
}
