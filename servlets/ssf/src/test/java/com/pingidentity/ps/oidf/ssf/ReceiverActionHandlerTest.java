/*
 * Event -> action mapping: revocation signals revoke grants for the right user key; others are ignored.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.signals.ReceivedSet;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ReceiverActionHandlerTest {

    private ReceivedSet set(String eventType, SubjectId subject) {
        return new ReceivedSet("https://tx", "j1", 100L, subject, Map.of(eventType, Map.of()), "jws");
    }

    @Test
    void sessionRevokedRevokesGrantsForIssSubSubject() {
        List<String> revoked = new ArrayList<>();
        ReceiverActionHandler h = new ReceiverActionHandler(userKey -> {
            revoked.add(userKey);
            return 2;
        });
        h.onSet(set(SsfEventTypes.CAEP_SESSION_REVOKED, SubjectId.issSub("https://tx", "bob")));
        assertEquals(List.of("bob"), revoked, "iss_sub subject maps to its sub");
    }

    @Test
    void accountDisabledRevokesForEmailSubject() {
        List<String> revoked = new ArrayList<>();
        new ReceiverActionHandler(userKey -> {
            revoked.add(userKey);
            return 1;
        }).onSet(set(SsfEventTypes.RISC_ACCOUNT_DISABLED, SubjectId.email("alice@example.com")));
        assertEquals(List.of("alice@example.com"), revoked);
    }

    @Test
    void nonRevocationEventsAndMissingSubjectsAreIgnored() {
        List<String> revoked = new ArrayList<>();
        ReceiverActionHandler h = new ReceiverActionHandler(userKey -> {
            revoked.add(userKey);
            return 0;
        });
        h.onSet(set(SsfEventTypes.VERIFICATION, null));                                  // not a revocation signal
        h.onSet(set(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, SubjectId.opaque("x")));       // informational
        h.onSet(set(SsfEventTypes.CAEP_SESSION_REVOKED, null));                          // no subject
        assertTrue(revoked.isEmpty());
    }

    @Test
    void actionFailureIsContained() {
        ReceiverActionHandler h = new ReceiverActionHandler(userKey -> {
            throw new RuntimeException("PF down");
        });
        h.onSet(set(SsfEventTypes.CAEP_SESSION_REVOKED, SubjectId.opaque("bob"))); // must not throw
    }

    @Test
    void anIssSubFromAnotherIssuerRevokesNothing() {
        List<String> revoked = new ArrayList<>();
        ReceiverActionHandler h = new ReceiverActionHandler(userKey -> {
            revoked.add(userKey);
            return 1;
        }, Set.of("https://pf.example.com"));
        List<Event> events = new ArrayList<>();
        Events.reset();
        Events.configure(events::add);
        try {
            h.onSet(set(SsfEventTypes.CAEP_SESSION_REVOKED, SubjectId.issSub("https://elsewhere", "bob")));
        } finally {
            Events.reset();
        }
        assertTrue(revoked.isEmpty(), "another issuer's sub names nobody here");
        assertEquals(1, events.size(), "the unmapped subject is counted");
        assertEquals("ssf.receiver.subject_unmapped", events.get(0).code());
        assertEquals("unmapped", events.get(0).reason());
        assertEquals(Map.of("handler", "grants", "format", "iss_sub"), events.get(0).fields());
        h.onSet(set(SsfEventTypes.CAEP_SESSION_REVOKED, SubjectId.issSub("https://pf.example.com", "carol")));
        h.onSet(set(SsfEventTypes.CAEP_SESSION_REVOKED, SubjectId.complex(Map.of(
                "user", SubjectId.email("dan@example.com"), "session", SubjectId.opaque("s-1")))));
        assertEquals(List.of("carol", "dan@example.com"), revoked, "this PingFederate's issuer is honoured; complex by user");
    }

    @Test
    void aCredentialChangeRequiredRevokesAndAnUnmappedSubjectRevokesNothing() {
        List<String> revoked = new ArrayList<>();
        ReceiverActionHandler h = new ReceiverActionHandler(userKey -> {
            revoked.add(userKey);
            return 1;
        });
        h.onSet(set(SsfEventTypes.RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED, SubjectId.did("did:example:bob")));
        h.onSet(set(SsfEventTypes.RISC_ACCOUNT_DISABLED, SubjectId.complex(Map.of("device", SubjectId.opaque("d")))));
        assertEquals(List.of("did:example:bob"), revoked);
    }
}
