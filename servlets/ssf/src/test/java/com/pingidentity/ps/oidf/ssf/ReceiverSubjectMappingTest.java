/*
 * H-SSF-1: each subject format the receiver takes maps to a user or device here, or is refused with a named reason.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ReceiverSubjectMappingTest {

    private static final Set<String> ISSUERS = Set.of("https://tx.example.com", "https://pf.example.com");

    private static String user(SubjectId subject) {
        SsfSubjects.Mapping m = SsfSubjects.userKey(subject, ISSUERS);
        assertTrue(m.mapped(), () -> subject + ": " + m.refusal());
        assertNull(m.refusal());
        return m.value();
    }

    private static String refusedUser(SubjectId subject) {
        SsfSubjects.Mapping m = SsfSubjects.userKey(subject, ISSUERS);
        assertFalse(m.mapped(), () -> subject + " mapped to " + m.value());
        assertNull(m.value());
        return m.refusal();
    }

    @Test
    @Requirement("RFC9493 §3.2")
    void eachSimpleFormatMapsToItsMember() {
        assertEquals("bob", user(SubjectId.issSub("https://tx.example.com", "bob")));
        assertEquals("carol", user(SubjectId.issSub("https://pf.example.com", "carol")));
        assertEquals("a@b.com", user(SubjectId.email("a@b.com")));
        assertEquals("+61400000000", user(SubjectId.phoneNumber("+61400000000")));
        assertEquals("op-1", user(SubjectId.opaque("op-1")));
        assertEquals("acct:a@b.com", user(SubjectId.account("acct:a@b.com")));
        assertEquals("did:example:123", user(SubjectId.did("did:example:123")));
        assertEquals("urn:uuid:4e851e98", user(SubjectId.uri("urn:uuid:4e851e98")));
    }

    /** RFC 7519 §4.1.2: a subject is "locally unique in the context of the issuer"; another issuer's sub is someone else. */
    @Test
    @Requirement("RFC9493 §3.2.3")
    void anIssSubFromAnIssuerTheReceiverDoesNotHonourMapsToNoOne() {
        assertEquals("the iss_sub subject's iss 'https://elsewhere.example.com' is neither the SET's issuer nor this"
                + " PingFederate's, so its sub names nobody here", refusedUser(SubjectId.issSub("https://elsewhere.example.com", "bob")));
    }

    @Test
    @Requirement("SSF §3.5")
    void aTokenOrAddressFormatNamesNoUser() {
        assertEquals("a jwt_id subject names a token or an address, not a user",
                refusedUser(SubjectId.jwtId("https://idp.example.com", "j")));
        assertEquals("a ip-addresses subject names a token or an address, not a user",
                refusedUser(SubjectId.ipAddresses(List.of("192.0.2.1"))));
        assertEquals("the SET has no subject", refusedUser(null));
    }

    /** RFC 9493 §3.2.8: the receiver picks the identifier it recognises, in its order, not the transmitter's. */
    @Test
    @Requirement("RFC9493 §3.2.8")
    void anAliasesSubjectMapsByTheReceiversPreferenceNotTheListOrder() {
        assertEquals(List.of("iss_sub", "email", "account", "phone_number", "opaque", "did", "uri"), SsfSubjects.USER_PREFERENCE);
        assertEquals("bob", user(SubjectId.aliases(List.of(SubjectId.uri("https://bob.example.com/"),
                SubjectId.opaque("x"),
                SubjectId.issSub("https://tx.example.com", "bob")))));
        assertEquals("bob@example.com", user(SubjectId.aliases(List.of(SubjectId.opaque("x"),
                SubjectId.issSub("https://elsewhere.example.com", "someone"), SubjectId.email("bob@example.com")))));
        String refusal = refusedUser(SubjectId.aliases(List.of(SubjectId.issSub("https://elsewhere.example.com", "b"),
                SubjectId.jwtId("https://idp.example.com", "j"))));
        assertEquals("no identifier of the aliases subject maps to a user (the iss_sub subject's iss"
                + " 'https://elsewhere.example.com' is neither the SET's issuer nor this PingFederate's, so its sub names nobody"
                + " here)", refusal);
        assertEquals("no identifier of the aliases subject maps to a user",
                refusedUser(SubjectId.aliases(List.of(SubjectId.samlAssertionId("https://idp.example.com", "a")))));
    }

    /** SSF 1.0 §3.3: a complex subject maps a user by its user member and a device by its device member. */
    @Test
    @Requirement("SSF §3.3")
    void aComplexSubjectMapsByItsUserAndDeviceMembers() {
        Map<String, SubjectId> members = new LinkedHashMap<>();
        members.put("session", SubjectId.opaque("sess-1"));
        members.put("device", SubjectId.opaque("dev-1"));
        members.put("user", SubjectId.aliases(List.of(SubjectId.email("bob@example.com"))));
        SubjectId complex = SubjectId.complex(members);
        assertEquals("bob@example.com", user(complex));
        assertEquals("dev-1", SsfSubjects.deviceId(complex).value());

        assertEquals("the complex subject has no user member",
                refusedUser(SubjectId.complex(Map.of("device", SubjectId.opaque("dev-1")))));
        assertEquals("the complex subject's user member: the iss_sub subject's iss 'https://elsewhere.example.com' is neither"
                + " the SET's issuer nor this PingFederate's, so its sub names nobody here",
                refusedUser(SubjectId.complex(Map.of("user", SubjectId.issSub("https://elsewhere.example.com", "b")))));
        assertEquals("the complex subject has no device member",
                SsfSubjects.deviceId(SubjectId.complex(Map.of("user", SubjectId.email("b@example.com")))).refusal());
        assertEquals("the complex subject's device member: a email subject does not name a device (only opaque does)",
                SsfSubjects.deviceId(SubjectId.complex(Map.of("device", SubjectId.email("b@example.com")))).refusal());
    }

    @Test
    void aDeviceIsAnOpaqueSubjectOrAnAliasesSubjectsOpaqueIdentifier() {
        assertEquals("dev-1", SsfSubjects.deviceId(SubjectId.opaque("dev-1")).value());
        assertEquals("dev-2", SsfSubjects.deviceId(SubjectId.aliases(List.of(SubjectId.email("b@example.com"),
                SubjectId.opaque("dev-2")))).value());
        assertEquals("no identifier of the aliases subject is opaque, the format a device is named in",
                SsfSubjects.deviceId(SubjectId.aliases(List.of(SubjectId.email("b@example.com")))).refusal());
        assertEquals("a did subject does not name a device (only opaque does)",
                SsfSubjects.deviceId(SubjectId.did("did:example:1")).refusal());
        assertEquals("the SET has no subject", SsfSubjects.deviceId(null).refusal());
    }

    @Test
    void theReceiverTakesFourMoreFormatsThanTheTransmitter() {
        assertEquals(Set.of("iss_sub", "email", "phone_number", "opaque", "account", "did", "uri", "aliases", "complex"),
                SsfSubjects.RECEIVER_FORMATS);
        assertTrue(SsfSubjects.RECEIVER_FORMATS.containsAll(SsfSubjects.FORMATS));
        assertEquals(Set.of("user", "device"), SsfSubjects.ACTED_ON_MEMBERS);
    }
}
