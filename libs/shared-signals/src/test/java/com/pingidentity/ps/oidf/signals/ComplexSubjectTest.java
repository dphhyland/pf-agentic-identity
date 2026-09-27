/*
 * The SSF 1.0 complex subject, its matching rule, and the subject formats RFC 9493 and SSF 1.0 add to the five.
 */
package com.pingidentity.ps.oidf.signals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

class ComplexSubjectTest {

    private static Map<String, Object> json(String text) throws Exception {
        return JsonUtil.parseJson(text);
    }

    private static SubjectId parse(String text) throws Exception {
        return SubjectId.fromMap(json(text));
    }

    /**
     * SSF 1.0 §3.3: "A Complex Subject Member has a name and a value that is a JSON [RFC7159] object that has a
     * format field, and one or more Simple Subject Members. The name of the format field is "format", and its
     * value is "complex"." The subject is the section's own Figure 2.
     */
    @Test
    @Requirement("SSF §3.3")
    void theSpecificationsComplexSubjectParsesAndRoundTrips() throws Exception {
        SubjectId s = parse("{\"format\": \"complex\", \"user\": {\"format\": \"email\", \"email\": \"bar@example.com\"},"
                + " \"tenant\": {\"format\": \"iss_sub\", \"iss\": \"https://example.com/idp1\", \"sub\": \"1234\"}}");
        assertTrue(s.isComplex());
        assertEquals("complex", s.format());
        assertEquals(SubjectId.email("bar@example.com"), s.member("user"));
        assertEquals(SubjectId.issSub("https://example.com/idp1", "1234"), s.member("tenant"));
        assertNull(s.member("device"));
        assertNull(s.member("format"));
        assertNull(SubjectId.email("bar@example.com").member("user"));
        assertEquals(s, SubjectId.fromMap(s.toMap()));
        assertEquals(s, SubjectId.fromMap(json(JsonUtil.toJson(s.toMap()))));
        assertEquals(s, SubjectId.complex(Map.of("tenant", SubjectId.issSub("https://example.com/idp1", "1234"),
                "user", SubjectId.email("bar@example.com"))));
    }

    /**
     * SSF 1.0 §3.3: "The name of each Simple Subject Member in this value MAY be one of the following: user ...
     * device ... session ... application ... tenant ... org_unit ... group", and "Additional Subject Member names
     * MAY be used in Complex Subjects."
     */
    @Test
    @Requirement("SSF §3.3")
    void everyListedMemberNameAndAnAdditionalOneAreKept() {
        Map<String, SubjectId> members = new LinkedHashMap<>();
        for (String name : SubjectId.COMPLEX_MEMBERS) {
            members.put(name, SubjectId.opaque(name + "-1"));
        }
        members.put("transferee", SubjectId.opaque("t-1"));
        SubjectId s = SubjectId.complex(members);
        for (String name : members.keySet()) {
            assertEquals(members.get(name), s.member(name));
        }
        assertEquals(List.of("user", "device", "session", "application", "tenant", "org_unit", "group"),
                SubjectId.COMPLEX_MEMBERS);
    }

    /**
     * SSF 1.0 §3.3: "one or more Simple Subject Members", and a Simple Subject Member's value "is a "Subject
     * Identifier" as defined in ... [RFC9493]" (§3.2) - so no member is itself complex, and every member is an
     * object.
     */
    @Test
    @Requirement({"SSF §3.3", "SSF §3.2"})
    void aComplexSubjectNeedsMembersThatAreSubjectIdentifiers() {
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"complex\"}"));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.complex(Map.of()));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.complex(null));
        assertThrows(IllegalArgumentException.class,
                () -> parse("{\"format\": \"complex\", \"user\": \"alice@example.com\"}"));
        assertThrows(IllegalArgumentException.class,
                () -> parse("{\"format\": \"complex\", \"user\": {\"format\": \"complex\","
                        + " \"device\": {\"format\": \"opaque\", \"id\": \"d\"}}}"));
        SubjectId inner = SubjectId.complex(Map.of("device", SubjectId.opaque("d")));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.complex(Map.of("user", inner)));
        assertThrows(IllegalArgumentException.class,
                () -> parse("{\"format\": \"complex\", \"user\": {\"email\": \"a@b.com\"}}"));
        assertThrows(IllegalArgumentException.class,
                () -> parse("{\"format\": \"complex\", \"user\": {\"format\": \"made_up\", \"x\": \"y\"}}"));
        assertThrows(IllegalArgumentException.class,
                () -> parse("{\"format\": \"complex\", \"user\": {\"format\": \" \", \"x\": \"y\"}}"));
        assertThrows(IllegalArgumentException.class,
                () -> SubjectId.complex(Map.of("format", SubjectId.opaque("x"))));
        assertThrows(IllegalArgumentException.class,
                () -> SubjectId.complex(Map.of(" ", SubjectId.opaque("x"))));
        Map<String, SubjectId> nullName = new HashMap<>();
        nullName.put(null, SubjectId.opaque("x"));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.complex(nullName));
    }

    /**
     * SSF 1.0 §8.1.3.1: "In the case of Simple Subjects, two subjects match if they are exactly identical. For
     * Complex Subjects, two subjects match if, for all fields in the Complex Subject (i.e. user, group, device,
     * etc.), at least one of the following statements is true: Subject 1's field is not defined; Subject 2's
     * field is not defined; Subject 1's field is identical to Subject 2's field". The three pairs are the
     * section's own examples.
     */
    @Test
    @Requirement("SSF §8.1.3.1")
    void complexSubjectsMatchAsTheSpecificationsExamplesSay() throws Exception {
        SubjectId addedTenant = parse("{\"format\": \"complex\", \"tenant\": {\"format\": \"opaque\","
                + " \"id\": \"example-a38h4792-uw2\"}}");
        SubjectId sentTenantAndUser = parse("{\"format\": \"complex\", \"tenant\": {\"format\": \"opaque\","
                + " \"id\": \"example-a38h4792-uw2\"}, \"user\": {\"format\": \"email\", \"email\": \"jdoe@example.com\"}}");
        assertTrue(addedTenant.matches(sentTenantAndUser));
        assertTrue(sentTenantAndUser.matches(addedTenant));

        SubjectId addedUserAndDevice = parse("{\"format\": \"complex\", \"user\": {\"format\": \"email\","
                + " \"email\": \"jdoe@example.com\"}, \"device\": {\"format\": \"ip-addresses\","
                + " \"ip-addresses\": [\"10.29.37.75\"]}}");
        SubjectId sentUser = parse("{\"format\": \"complex\", \"user\": {\"format\": \"email\","
                + " \"email\": \"jdoe@example.com\"}}");
        assertTrue(addedUserAndDevice.matches(sentUser));

        SubjectId addedGroup = parse("{\"format\": \"complex\", \"user\": {\"format\": \"email\","
                + " \"email\": \"jdoe@example.com\"}, \"group\": {\"format\": \"did\", \"url\": \"did:example:123456\"}}");
        SubjectId sentOtherGroup = parse("{\"format\": \"complex\", \"user\": {\"format\": \"email\","
                + " \"email\": \"jdoe@example.com\"}, \"group\": {\"format\": \"did\", \"url\": \"did:example:9999999\"}}");
        assertFalse(addedGroup.matches(sentOtherGroup));
    }

    @Test
    @Requirement("SSF §8.1.3.1")
    void simpleSubjectsMatchOnlyWhenIdentical() {
        assertTrue(SubjectId.email("a@b.com").matches(SubjectId.email("a@b.com")));
        assertFalse(SubjectId.email("a@b.com").matches(SubjectId.email("A@b.com")));
        SubjectId complex = SubjectId.complex(Map.of("user", SubjectId.email("a@b.com")));
        assertFalse(complex.matches(SubjectId.email("a@b.com")));
        assertFalse(SubjectId.email("a@b.com").matches(complex));
        assertFalse(complex.matches(null));
    }

    /** RFC 9493 §3.2.6: a "url" member "whose value is a DID URL"; §3.2.7: a "uri" member "whose value is a URI". */
    @Test
    @Requirement({"RFC9493 §3.2.6", "RFC9493 §3.2.7"})
    void didAndUriFormats() throws Exception {
        assertEquals(SubjectId.did("did:example:123456/did/url/path?versionId=1"),
                parse("{\"format\": \"did\", \"url\": \"did:example:123456/did/url/path?versionId=1\"}"));
        assertEquals(SubjectId.uri("urn:uuid:4e851e98-83c4-4743-a5da-150ecb53042f"),
                parse("{\"format\": \"uri\", \"uri\": \"urn:uuid:4e851e98-83c4-4743-a5da-150ecb53042f\"}"));
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"did\", \"uri\": \"did:example:1\"}"));
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"uri\", \"uri\": \"\"}"));
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"uri\", \"uri\": 5}"));
    }

    /**
     * RFC 9493 §3.2.8: "The "identifiers" member is REQUIRED and MUST NOT be null or empty", and ""aliases" Subject
     * Identifiers MUST NOT be nested". The subject is the section's Figure 13.
     */
    @Test
    @Requirement("RFC9493 §3.2.8")
    void aliasesHoldOneOrMoreIdentifiersAndDoNotNest() throws Exception {
        SubjectId a = parse("{\"format\": \"aliases\", \"identifiers\": [{\"format\": \"email\", \"email\":"
                + " \"user@example.com\"}, {\"format\": \"phone_number\", \"phone_number\": \"+12065550100\"},"
                + " {\"format\": \"email\", \"email\": \"user+qualifier@example.com\"}]}");
        assertEquals(SubjectId.aliases(List.of(SubjectId.email("user@example.com"),
                SubjectId.phoneNumber("+12065550100"), SubjectId.email("user+qualifier@example.com"))), a);
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"aliases\", \"identifiers\": []}"));
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"aliases\"}"));
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"aliases\", \"identifiers\": [\"x\"]}"));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.aliases(null));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.aliases(List.of(a)));
        assertThrows(IllegalArgumentException.class,
                () -> SubjectId.aliases(List.of(SubjectId.complex(Map.of("user", SubjectId.opaque("u"))))));
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"aliases\", \"identifiers\":"
                + " [{\"format\": \"complex\", \"user\": {\"format\": \"opaque\", \"id\": \"u\"}}]}"));
        SubjectId complexWithAliases = SubjectId.complex(Map.of("user", a));
        assertEquals(a, complexWithAliases.member("user"));
    }

    /** SSF 1.0 §3.5.1-§3.5.3: jwt_id (iss, jti), saml_assertion_id (issuer, assertion_id), ip-addresses. */
    @Test
    @Requirement({"SSF §3.5.1", "SSF §3.5.2", "SSF §3.5.3"})
    void theThreeFormatsSsfAdds() throws Exception {
        assertEquals(SubjectId.jwtId("https://idp.example.com/123456789/", "B70BA622-9515-4353-A866-823539EECBC8"),
                parse("{\"format\": \"jwt_id\", \"iss\": \"https://idp.example.com/123456789/\","
                        + " \"jti\": \"B70BA622-9515-4353-A866-823539EECBC8\"}"));
        assertEquals(SubjectId.samlAssertionId("https://idp.example.com/123456789/", "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"),
                parse("{\"format\": \"saml_assertion_id\", \"issuer\": \"https://idp.example.com/123456789/\","
                        + " \"assertion_id\": \"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\"}"));
        assertEquals(SubjectId.ipAddresses(List.of("10.29.37.75", "2001:0db8:0000:0000:0000:8a2e:0370:7334")),
                parse("{\"format\": \"ip-addresses\", \"ip-addresses\": [\"10.29.37.75\","
                        + " \"2001:0db8:0000:0000:0000:8a2e:0370:7334\"]}"));
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"jwt_id\", \"iss\": \"x\"}"));
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"ip-addresses\"}"));
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"ip-addresses\", \"ip-addresses\": []}"));
        assertThrows(IllegalArgumentException.class, () -> parse("{\"format\": \"ip-addresses\", \"ip-addresses\": [4]}"));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.ipAddresses(null));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.ipAddresses(Arrays.asList("10.0.0.1", " ")));
    }

    @Test
    void anAcceptedSetLimitsTheTopLevelFormatOnly() throws Exception {
        Map<String, Object> complex = json("{\"format\": \"complex\", \"user\": {\"format\": \"did\", \"url\": \"did:ex:1\"}}");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SubjectId.fromMap(complex, Set.of(SubjectId.FORMAT_EMAIL)));
        assertEquals("unsupported subject identifier format: complex", e.getMessage());
        assertEquals(SubjectId.did("did:ex:1"), SubjectId.fromMap(complex, Set.of(SubjectId.FORMAT_COMPLEX)).member("user"));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.fromMap(null));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.fromMap(Map.of("format", " ")));
        assertThrows(IllegalArgumentException.class, () -> SubjectId.fromMap(Map.of("format", 3)));
    }

    /**
     * The five formats stored before 0.5.0 keep their keys; the others key on their members as JSON in name order,
     * so a complex subject's key does not depend on the order its members arrived in.
     */
    @Test
    void canonicalKeysRoundTripAndIgnoreMemberOrder() throws Exception {
        List<SubjectId> all = new ArrayList<>(List.of(
                SubjectId.issSub("https://op.example.com", "user-1"), SubjectId.email("a@b.com"),
                SubjectId.phoneNumber("+15551234567"), SubjectId.opaque("abc"),
                SubjectId.account("acct:user@example.com"), SubjectId.did("did:example:1"),
                SubjectId.uri("https://user.example.com/"), SubjectId.jwtId("https://i", "j"),
                SubjectId.samlAssertionId("https://i", "a"), SubjectId.ipAddresses(List.of("10.0.0.1")),
                SubjectId.aliases(List.of(SubjectId.email("a@b.com"), SubjectId.opaque("abc"))),
                SubjectId.complex(Map.of("user", SubjectId.email("a@b.com"), "device", SubjectId.opaque("d")))));
        for (SubjectId s : all) {
            assertEquals(s, SubjectId.fromCanonicalKey(s.canonicalKey()), s.canonicalKey());
            assertEquals(s.canonicalKey(), s.toString());
        }
        assertEquals("iss_sub:https://op.example.com user-1", all.get(0).canonicalKey());
        assertEquals("did:did:example:1", all.get(5).canonicalKey());
        assertEquals("complex:{\"device\":{\"format\":\"opaque\",\"id\":\"d\"},\"user\":{\"email\":\"a@b.com\",\"format\":\"email\"}}",
                all.get(11).canonicalKey());
        Map<String, SubjectId> reversed = new LinkedHashMap<>();
        reversed.put("user", SubjectId.email("a@b.com"));
        reversed.put("device", SubjectId.opaque("d"));
        Map<String, SubjectId> forward = new LinkedHashMap<>();
        forward.put("device", SubjectId.opaque("d"));
        forward.put("user", SubjectId.email("a@b.com"));
        assertEquals(SubjectId.complex(forward).canonicalKey(), SubjectId.complex(reversed).canonicalKey());
        assertNotEquals(all.get(10).canonicalKey(), SubjectId.aliases(List.of(SubjectId.opaque("abc"),
                SubjectId.email("a@b.com"))).canonicalKey());
    }

    @Test
    void aMalformedCanonicalKeyIsRefused() {
        for (String key : new String[]{null, "no-colon", "iss_sub:no-space", "made_up:x", "complex:not json",
                "complex:[1]", "complex:{\"format\":\"email\",\"email\":\"a@b.com\"}", "aliases:{}"}) {
            assertThrows(IllegalArgumentException.class, () -> SubjectId.fromCanonicalKey(key), String.valueOf(key));
        }
    }
}
