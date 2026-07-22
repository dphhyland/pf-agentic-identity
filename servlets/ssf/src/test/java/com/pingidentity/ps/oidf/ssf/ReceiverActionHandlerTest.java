/*
 * Event -> action mapping: revocation signals revoke grants for the right user key; others are ignored.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
    void userKeyDerivationPerFormat() {
        assertEquals("bob", ReceiverActionHandler.userKeyOf(SubjectId.issSub("https://x", "bob")));
        assertEquals("a@b.com", ReceiverActionHandler.userKeyOf(SubjectId.email("a@b.com")));
        assertEquals("op-1", ReceiverActionHandler.userKeyOf(SubjectId.opaque("op-1")));
        assertNull(ReceiverActionHandler.userKeyOf(null));
    }
}
