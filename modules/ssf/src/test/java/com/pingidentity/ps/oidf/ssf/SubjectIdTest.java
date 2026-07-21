/*
 * Subject identifier (RFC 9493) factories, parsing, and canonical keys.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

class SubjectIdTest {

    @Test
    void issSubRoundTripsThroughMap() {
        SubjectId subject = SubjectId.issSub("https://op.example.com", "user-1");
        Map<String, Object> map = subject.toMap();
        assertEquals("iss_sub", map.get("format"));
        assertEquals("https://op.example.com", map.get("iss"));
        assertEquals("user-1", map.get("sub"));
        assertEquals(subject, SubjectId.fromMap(map));
    }

    @Test
    void parsesEachSupportedFormat() {
        assertEquals(SubjectId.email("a@b.com"),
                SubjectId.fromMap(Map.of("format", "email", "email", "a@b.com")));
        assertEquals(SubjectId.phoneNumber("+15551234567"),
                SubjectId.fromMap(Map.of("format", "phone_number", "phone_number", "+15551234567")));
        assertEquals(SubjectId.opaque("abc"),
                SubjectId.fromMap(Map.of("format", "opaque", "id", "abc")));
        assertEquals(SubjectId.account("acct:user@example.com"),
                SubjectId.fromMap(Map.of("format", "account", "uri", "acct:user@example.com")));
    }

    @Test
    void rejectsMissingOrUnknownFormat() {
        assertThrows(IllegalArgumentException.class, () -> SubjectId.fromMap(Map.of("iss", "x", "sub", "y")));
        assertThrows(IllegalArgumentException.class,
                () -> SubjectId.fromMap(Map.of("format", "made_up", "x", "y")));
    }

    @Test
    void rejectsMissingRequiredMember() {
        assertThrows(IllegalArgumentException.class,
                () -> SubjectId.fromMap(Map.of("format", "iss_sub", "iss", "only-iss")));
        assertThrows(IllegalArgumentException.class,
                () -> SubjectId.fromMap(Map.of("format", "email")));
    }

    @Test
    void canonicalKeyDistinguishesSubjectsAndFormats() {
        assertEquals(SubjectId.email("a@b.com").canonicalKey(), SubjectId.email("a@b.com").canonicalKey());
        assertNotEquals(SubjectId.email("a@b.com").canonicalKey(), SubjectId.email("c@d.com").canonicalKey());
        assertNotEquals(SubjectId.opaque("a@b.com").canonicalKey(), SubjectId.email("a@b.com").canonicalKey());
    }

    @Test
    void canonicalKeyRoundTrips() {
        for (SubjectId s : new SubjectId[]{
                SubjectId.issSub("https://op.example.com", "user-1"),
                SubjectId.email("a@b.com"),
                SubjectId.phoneNumber("+15551234567"),
                SubjectId.opaque("abc"),
                SubjectId.account("acct:user@example.com")}) {
            assertEquals(s, SubjectId.fromCanonicalKey(s.canonicalKey()));
        }
    }
}
