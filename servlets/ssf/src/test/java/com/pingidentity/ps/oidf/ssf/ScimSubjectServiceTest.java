/*
 * SCIM provisioning -> stream subjects; deactivate -> remove + RISC account-disabled; reactivate -> account-enabled.
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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class ScimSubjectServiceTest {

    private static final String PROVISIONER_SCOPE = "ssf.provision";
    /** The provisioning client: holds the provisioner scope, owns no streams. */
    private static final AuthContext PROVISIONER = AuthContext.active("scim-provisioner", Set.of(PROVISIONER_SCOPE));
    private static final AuthContext RECEIVER = AuthContext.active("receiver-client", Set.of("ssf.manage"));
    private static final AuthContext OTHER = AuthContext.active("receiver-b", Set.of("ssf.manage"));
    private static final String ALICE = "email:alice@example.com";

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

    private void stream(String id, String... events) {
        ownedStream(id, RECEIVER.clientId(), events);
    }

    private void ownedStream(String id, String owner, String... events) {
        store.createStream(Stream.builder().id(id).audience("https://r/" + id).ownerClientId(owner).deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(List.of(events)).eventsDelivered(List.of(events)).status(StreamStatus.ENABLED).build());
    }

    /** A stream that hears both RISC account events. */
    private void riscStream(String id) {
        stream(id, SsfEventTypes.RISC_ACCOUNT_DISABLED, SsfEventTypes.RISC_ACCOUNT_ENABLED);
    }

    private static Map<String, Object> user(Object streams, Object active) {
        Map<String, Object> u = new LinkedHashMap<>();
        u.put("userName", "alice");
        u.put("externalId", "ext-alice");
        u.put("emails", List.of(Map.of("value", "alice@example.com", "primary", true)));
        if (streams != null) {
            u.put(ScimSubjectService.SSF_EXT, Map.of("streams", streams));
        }
        if (active != null) {
            u.put("active", active);
        }
        return u;
    }

    private static Map<String, Object> patch(Map<String, Object>... ops) {
        return Map.of("schemas", List.of(ScimSubjectService.PATCH_SCHEMA), "Operations", List.of((Object[]) ops));
    }

    private static Map<String, Object> op(String op, String path, Object value) {
        Map<String, Object> m = new HashMap<>();
        m.put("op", op);
        if (path != null) {
            m.put("path", path);
        }
        m.put("value", value);
        return m;
    }

    /** The event types queued on a stream, in order. */
    private List<String> events(String streamId) throws Exception {
        List<String> out = new ArrayList<>();
        for (PendingSet p : store.peek(streamId, 100)) {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(p.setJws());
            out.addAll(JwtClaims.parse(jws.getUnverifiedPayload()).getClaimValue("events", Map.class).keySet());
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<String> streamsOf(Map<String, Object> resource) {
        return (List<String>) ((Map<String, Object>) resource.get(ScimSubjectService.SSF_EXT)).get("streams");
    }

    private static ScimException scim(int status, String scimType, Executable call) {
        ScimException e = assertThrows(ScimException.class, call);
        assertEquals(status, e.status(), e.getMessage());
        assertEquals(scimType, e.scimType(), e.getMessage());
        return e;
    }

    // ─────────────────────────────── create and read ───────────────────────────────

    @Test
    @Requirement("RFC7644 §3.3")
    void createAssignsTheSubjectAndAnswersTheResource() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        riscStream("risc");
        Map<String, Object> created = svc.create(user(List.of("s1", "risc"), null), PROVISIONER);
        assertTrue(store.hasSubject("s1", alice) && store.hasSubject("risc", alice));
        assertEquals(ALICE, created.get("id"));
        assertEquals("alice", created.get("userName"));
        assertEquals("ext-alice", created.get("externalId"));
        assertEquals(true, created.get("active"));
        assertEquals(List.of("risc", "s1"), streamsOf(created), "in id order");
        assertEquals(List.of(Map.of("value", "alice@example.com", "primary", true)), created.get("emails"));
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) created.get("meta");
        assertEquals("https://op.example.com/ssf/scim/v2/Users/email:alice@example.com", meta.get("location"));
        assertEquals("User", meta.get("resourceType"));
        assertTrue(meta.containsKey("created") && meta.containsKey("lastModified"));
        assertEquals(created, svc.get(ALICE, PROVISIONER));
    }

    /** RFC 7644 §3.3: a duplicate "MUST return HTTP status code 409 (Conflict) with a "scimType" error code of "uniqueness"". */
    @Test
    @Requirement({"RFC7644 §3.3", "RFC7644 §3.12"})
    void creatingAUserThatExistsIs409Uniqueness() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        svc.create(user(List.of("s1"), null), PROVISIONER);
        ScimException e = scim(409, "uniqueness", () -> svc.create(user(List.of("s1"), null), PROVISIONER));
        assertEquals(Map.of("schemas", List.of(ScimException.ERROR_SCHEMA), "scimType", "uniqueness",
                "detail", "a user with id " + ALICE + " already exists", "status", "409"), e.body());
    }

    /** A subject a receiver put on its stream is a user here, and a POST adds to the streams holding it. */
    @Test
    void aSubjectAReceiverAddedIsAnActiveUserAndCreateAddsToItsStreams() throws Exception {
        stream("theirs", SsfEventTypes.CAEP_SESSION_REVOKED);
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        store.addSubject("theirs", alice);
        Map<String, Object> read = svc.get(ALICE, PROVISIONER);
        assertEquals(true, read.get("active"));
        assertEquals(List.of("theirs"), streamsOf(read));
        assertFalse(read.containsKey("userName"));
        assertFalse(((Map<?, ?>) read.get("meta")).containsKey("created"), "no record: no dates");

        assertEquals(Set.of("theirs", "s1"), Set.copyOf(streamsOf(svc.create(user(List.of("s1"), null), PROVISIONER))));
        assertTrue(store.hasSubject("theirs", alice), "a create does not take the subject off a receiver's stream");
    }

    @Test
    @Requirement({"RFC7644 §3.4.1", "RFC7644 §3.12"})
    void anUnknownIdIs404WhateverTheMethod() {
        for (Executable call : new Executable[] {() -> svc.get(ALICE, PROVISIONER), () -> svc.replace(ALICE, user(null, null), PROVISIONER),
                () -> svc.patch(ALICE, patch(op("replace", "active", false)), PROVISIONER), () -> svc.delete(ALICE, PROVISIONER),
                () -> svc.get("not-a-key", PROVISIONER)}) {
            ScimException e = scim(404, null, call);
            assertEquals("404", e.body().get("status"));
            assertFalse(e.body().containsKey("scimType"));
        }
    }

    @Test
    void createNamingAStreamThatDoesNotExistIs400InvalidValueAndChangesNothing() {
        scim(400, "invalidValue", () -> svc.create(user(List.of("no-such-stream"), null), PROVISIONER));
        assertTrue(store.getScimUser(ALICE).isEmpty());
    }

    @Test
    void subjectDerivationPrefersEmailThenUserNameThenExternalId() {
        assertEquals(SubjectId.email("a@b.com"), svc.subjectOf(Map.of("emails", List.of(Map.of("value", "a@b.com")))));
        assertEquals(SubjectId.email("p@b.com"), svc.subjectOf(Map.of("emails", List.of("junk", Map.of("value", "a@b.com"),
                Map.of("value", "p@b.com", "primary", true)))));
        assertEquals(SubjectId.issSub("https://op.example.com", "bob"), svc.subjectOf(Map.of("userName", "bob",
                "emails", List.of(Map.of("type", "work")))));
        assertEquals(SubjectId.opaque("ext-1"), svc.subjectOf(Map.of("externalId", "ext-1")));
        scim(400, "invalidValue", () -> svc.subjectOf(Map.of("userName", " ")));
    }

    @Test
    void activeAndStreamsMustHaveTheirTypes() {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        scim(400, "invalidValue", () -> svc.create(user(List.of("s1"), "yes"), PROVISIONER));
        scim(400, "invalidValue", () -> svc.create(user("s1", null), PROVISIONER));
        scim(400, "invalidValue", () -> svc.create(user(List.of(1), null), PROVISIONER));
    }

    // ─────────────────────────────── deactivation and reactivation ───────────────────────────────

    @Test
    void deactivatingRaisesAccountDisabledTakesTheSubjectOffAndKeepsTheStreamsToRestore() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        riscStream("risc");
        svc.create(user(List.of("s1", "risc"), null), PROVISIONER);

        Map<String, Object> off = svc.replace(ALICE, user(List.of("s1", "risc"), false), PROVISIONER);

        assertEquals(List.of(SsfEventTypes.RISC_ACCOUNT_DISABLED), events("risc"), "heard before the subject came off");
        assertEquals(List.of(), events("s1"), "s1 does not deliver account-disabled");
        assertFalse(store.hasSubject("s1", alice) || store.hasSubject("risc", alice));
        assertEquals(false, off.get("active"));
        assertEquals(List.of("risc", "s1"), streamsOf(off), "an inactive user's streams are the ones it goes back to");
        assertEquals(off, svc.get(ALICE, PROVISIONER), "the user outlives its memberships");

        svc.replace(ALICE, user(List.of("s1", "risc"), false), PROVISIONER);
        assertEquals(1, events("risc").size(), "already inactive: nothing raised again");
    }

    /** RISC 1.0 §2.4: "Account Enabled signals that the account identified by the subject has been enabled." */
    @Test
    @Requirement({"RISC §2.4", "RFC7644 §3.5.2"})
    void reactivatingByPatchRestoresTheStreamsAndRaisesAccountEnabled() throws Exception {
        riscStream("risc");
        stream("gone", SsfEventTypes.RISC_ACCOUNT_ENABLED);
        svc.create(user(List.of("risc", "gone"), null), PROVISIONER);
        svc.patch(ALICE, patch(op("replace", "active", "False")), PROVISIONER);
        store.deleteStream("gone");

        Map<String, Object> on = svc.patch(ALICE, patch(op("replace", "active", true)), PROVISIONER);

        assertEquals(true, on.get("active"));
        assertEquals(List.of("risc"), streamsOf(on), "a stream deleted meanwhile is not restored");
        assertTrue(store.hasSubject("risc", alice));
        List<String> heard = events("risc");
        assertEquals(2, heard.size());
        assertEquals(Set.of(SsfEventTypes.RISC_ACCOUNT_DISABLED, SsfEventTypes.RISC_ACCOUNT_ENABLED), Set.copyOf(heard),
                "account-enabled after the subject is back, so the stream hears it (a second's SETs queue in jti order)");
        assertEquals(List.of(), store.getScimUser(ALICE).orElseThrow().restoreStreams());

        svc.patch(ALICE, patch(op("replace", "active", true)), PROVISIONER);
        assertEquals(2, events("risc").size(), "already active: nothing raised again");

        svc.patch(ALICE, patch(op("replace", "active", false)), PROVISIONER);
        svc.patch(ALICE, patch(op("replace", "userName", "renamed")), PROVISIONER);
        assertEquals(3, events("risc").size(), "a change to an inactive user raises nothing");
        assertEquals(List.of("risc"), store.getScimUser(ALICE).orElseThrow().restoreStreams(), "and keeps what it restores");
    }

    @Test
    @Requirement({"RISC §2.4", "RFC7644 §3.5.1"})
    void reactivatingByPutPutsTheSubjectOnTheStreamsItNames() throws Exception {
        riscStream("risc");
        riscStream("other");
        svc.create(user(List.of("risc"), false), PROVISIONER);
        assertEquals(List.of(), events("risc"), "created inactive: no stream held her, so none heard it");
        assertEquals(List.of("risc"), store.getScimUser(ALICE).orElseThrow().restoreStreams());

        Map<String, Object> on = svc.replace(ALICE, user(List.of("other"), true), PROVISIONER);

        assertEquals(List.of("other"), streamsOf(on));
        assertTrue(store.hasSubject("other", alice) && !store.hasSubject("risc", alice));
        assertEquals(List.of(SsfEventTypes.RISC_ACCOUNT_ENABLED), events("other"));
    }

    /** Before 0.6.0 every active:false raised account-disabled; a subject never seen still does, so nothing is lost. */
    @Test
    void creatingAUserInactiveRaisesAccountDisabled() throws Exception {
        riscStream("risc");
        store.addSubject("risc", alice);
        Map<String, Object> created = svc.create(user(null, false), PROVISIONER);
        assertEquals(false, created.get("active"));
        assertEquals(List.of(SsfEventTypes.RISC_ACCOUNT_DISABLED), events("risc"));
        assertEquals(List.of("risc"), store.getScimUser(ALICE).orElseThrow().restoreStreams());
    }

    @Test
    void deactivatingWithStreamsNamedKeepsThoseToRestore() throws Exception {
        riscStream("a");
        riscStream("b");
        svc.create(user(List.of("a"), null), PROVISIONER);
        svc.replace(ALICE, user(List.of("b"), false), PROVISIONER);
        assertEquals(List.of("b"), store.getScimUser(ALICE).orElseThrow().restoreStreams());
        svc.replace(ALICE, user(List.of("a"), false), PROVISIONER);
        assertEquals(List.of("a"), store.getScimUser(ALICE).orElseThrow().restoreStreams(), "changed while inactive");
        assertFalse(store.hasSubject("a", alice) || store.hasSubject("b", alice));
    }

    // ─────────────────────────────── PUT replaces ───────────────────────────────

    /**
     * RFC 7644 §3.5.1: "HTTP PUT is used to replace a resource's attributes"; an omitted readWrite attribute "MAY be
     * assumed to be not asserted by the client. The service provider MAY assume that any existing values are to be
     * cleared". This endpoint clears them.
     */
    @Test
    @Requirement("RFC7644 §3.5.1")
    void putReplacesAndWhatItLeavesOutIsRemoved() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        stream("s2", SsfEventTypes.CAEP_SESSION_REVOKED);
        svc.create(user(List.of("s1", "s2"), null), PROVISIONER);

        Map<String, Object> onlyEmail = new HashMap<>(Map.of("emails", List.of(Map.of("value", "alice@example.com"))));
        onlyEmail.put(ScimSubjectService.SSF_EXT, Map.of("streams", List.of("s2")));
        Map<String, Object> replaced = svc.replace(ALICE, onlyEmail, PROVISIONER);
        assertEquals(List.of("s2"), streamsOf(replaced));
        assertFalse(store.hasSubject("s1", alice));
        assertFalse(replaced.containsKey("userName") || replaced.containsKey("externalId"), "not sent, so removed");

        Map<String, Object> noExtension = svc.replace(ALICE, Map.of("emails", List.of(Map.of("value", "alice@example.com"))),
                PROVISIONER);
        assertEquals(List.of(), streamsOf(noExtension), "no SSF extension: on no stream");
        assertFalse(store.hasSubject("s2", alice));
        assertEquals(noExtension, svc.get(ALICE, PROVISIONER), "a user on no stream, with its record, still exists");
    }

    @Test
    @Requirement({"RFC7644 §3.5.1", "RFC7644 §3.12"})
    void putMayNotChangeTheSubject() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        svc.create(user(List.of("s1"), null), PROVISIONER);
        scim(400, "mutability", () -> svc.replace(ALICE, Map.of("emails", List.of(Map.of("value", "bob@example.com"))), PROVISIONER));
        scim(400, "invalidValue", () -> svc.replace(ALICE, Map.of(), PROVISIONER));
    }

    // ─────────────────────────────── PATCH ───────────────────────────────

    @Test
    @Requirement("RFC7644 §3.5.2")
    void patchAddsReplacesAndRemovesTheAttributesItKeeps() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        stream("s2", SsfEventTypes.CAEP_SESSION_REVOKED);
        stream("s3", SsfEventTypes.CAEP_SESSION_REVOKED);
        svc.create(user(List.of("s1"), null), PROVISIONER);
        String streams = ScimSubjectService.SSF_EXT + ":streams";

        assertEquals(List.of("s1", "s2"), streamsOf(svc.patch(ALICE, patch(op("add", streams, List.of("s2"))), PROVISIONER)));
        assertEquals(List.of("s3"), streamsOf(svc.patch(ALICE, patch(op("replace", "streams", List.of("s3"))), PROVISIONER)));
        assertEquals(List.of("s1", "s3"), streamsOf(svc.patch(ALICE, patch(op("add", null,
                Map.of(ScimSubjectService.SSF_EXT, Map.of("streams", List.of("s1"))))), PROVISIONER)));
        assertEquals(List.of("s1"), streamsOf(svc.patch(ALICE, patch(op("remove", streams, List.of("s3"))), PROVISIONER)));
        assertEquals(List.of(), streamsOf(svc.patch(ALICE, patch(op("remove", streams, null)), PROVISIONER)));

        Map<String, Object> named = svc.patch(ALICE, patch(op("replace", null, Map.of("userName", "al", "externalId", "x2",
                "displayName", "ignored", ScimSubjectService.SSF_EXT, Map.of("note", "no streams here")))), PROVISIONER);
        assertEquals("al", named.get("userName"));
        assertEquals("x2", named.get("externalId"));
        Map<String, Object> unnamed = svc.patch(ALICE, patch(op("remove", "urn:ietf:params:scim:schemas:core:2.0:User:userName", null),
                op("remove", "externalId", null), op("replace", "name.givenName", "Alice")), PROVISIONER);
        assertFalse(unnamed.containsKey("userName") || unnamed.containsKey("externalId"));
        assertEquals("al2", svc.patch(ALICE, patch(op("add", "userName", "al2")), PROVISIONER).get("userName"));
    }

    @Test
    @Requirement({"RFC7644 §3.5.2", "RFC7644 §3.12"})
    void aPatchThatCannotBeAppliedIs400WithItsScimType() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        svc.create(user(List.of("s1"), null), PROVISIONER);
        scim(400, "invalidSyntax", () -> svc.patch(ALICE, Map.of(), PROVISIONER));
        scim(400, "invalidSyntax", () -> svc.patch(ALICE, Map.of("Operations", List.of("add")), PROVISIONER));
        scim(400, "invalidSyntax", () -> svc.patch(ALICE, patch(op("move", "active", true)), PROVISIONER));
        scim(400, "invalidSyntax", () -> svc.patch(ALICE, patch(new HashMap<>(Map.of("path", "active"))), PROVISIONER));
        scim(400, "noTarget", () -> svc.patch(ALICE, patch(op("remove", null, null)), PROVISIONER));
        scim(400, "invalidValue", () -> svc.patch(ALICE, patch(op("replace", null, "x")), PROVISIONER));
        scim(400, "invalidPath", () -> svc.patch(ALICE, patch(op("replace", "emails[type eq \"work\"].value", "x")), PROVISIONER));
        scim(400, "invalidValue", () -> svc.patch(ALICE, patch(op("remove", "active", null)), PROVISIONER));
        scim(400, "invalidValue", () -> svc.patch(ALICE, patch(op("replace", "active", "maybe")), PROVISIONER));
        scim(400, "invalidValue", () -> svc.patch(ALICE, patch(op("replace", "userName", 7)), PROVISIONER));
        scim(400, "invalidValue", () -> svc.patch(ALICE, patch(op("add", "streams", List.of("no-such-stream"))), PROVISIONER));
        assertEquals(List.of("s1"), streamsOf(svc.get(ALICE, PROVISIONER)), "none of them changed anything");
    }

    // ─────────────────────────────── DELETE ───────────────────────────────

    @Test
    @Requirement("RFC7644 §3.6")
    void deleteDeactivatesAnActiveUserAndForgetsIt() throws Exception {
        riscStream("risc");
        svc.create(user(List.of("risc"), null), PROVISIONER);
        svc.delete(ALICE, PROVISIONER);
        assertEquals(List.of(SsfEventTypes.RISC_ACCOUNT_DISABLED), events("risc"));
        assertFalse(store.hasSubject("risc", alice));
        scim(404, null, () -> svc.get(ALICE, PROVISIONER));

        svc.create(user(List.of("risc"), false), PROVISIONER);
        svc.delete(ALICE, PROVISIONER);
        assertEquals(1, events("risc").size(), "created inactive, it was on no stream to hear it; deleted inactive, nothing more");
        assertTrue(store.getScimUser(ALICE).isEmpty());
    }

    // ─────────────────────────────── query ───────────────────────────────

    private List<Object> ids(String filter) {
        return ids(svc.query(filter, null, null, PROVISIONER));
    }

    @SuppressWarnings("unchecked")
    private static List<Object> ids(Map<String, Object> list) {
        List<Object> out = new ArrayList<>();
        for (Map<String, Object> r : (List<Map<String, Object>>) list.get("Resources")) {
            out.add(r.get("id"));
        }
        return out;
    }

    private void threeUsers() throws Exception {
        stream("s1", SsfEventTypes.CAEP_SESSION_REVOKED);
        ownedStream("s2", OTHER.clientId(), SsfEventTypes.CAEP_SESSION_REVOKED);
        svc.create(user(List.of("s1"), null), PROVISIONER);
        svc.create(Map.of("userName", "Bob", "externalId", "ext-bob", ScimSubjectService.SSF_EXT, Map.of("streams", List.of("s2"))),
                PROVISIONER);
        svc.create(Map.of("externalId", "carol", "active", false), PROVISIONER);
        store.addSubject("s2", SubjectId.phoneNumber("+61400000000"));
    }

    /** RFC 7644 §3.4.2: "A query that does not return any matches SHALL return success (HTTP status code 200) with "totalResults" set to a value of 0." */
    @Test
    @Requirement({"RFC7644 §3.4.2", "RFC7644 §3.4.2.2"})
    void queryAnswersAListResponseOfTheUsersTheFilterMatches() throws Exception {
        threeUsers();
        String bob = "iss_sub:https://op.example.com Bob";
        Map<String, Object> all = svc.query(null, null, null, PROVISIONER);
        assertEquals(List.of(ScimSubjectService.LIST_SCHEMA), all.get("schemas"));
        assertEquals(4, all.get("totalResults"));
        assertEquals(List.of(ALICE, bob, "opaque:carol", "phone_number:+61400000000"), ids(all), "ordered by id");

        assertEquals(List.of(bob), ids("userName eq \"bob\""), "userName ignores case");
        assertEquals(List.of(bob), ids("USERNAME Eq \"BOB\""), "so do attribute names and operators");
        assertEquals(List.of(), ids("externalId eq \"EXT-BOB\""), "externalId does not");
        assertEquals(List.of(ALICE), ids("urn:ietf:params:scim:schemas:core:2.0:User:externalId eq \"ext-alice\""));
        assertEquals(List.of(ALICE), ids("id eq \"" + ALICE + "\""));
        assertEquals(List.of("opaque:carol"), ids("active eq false"));
        assertEquals(List.of(ALICE, bob, "phone_number:+61400000000"), ids("active ne false"));
        assertEquals(List.of(ALICE), ids("emails.value co \"ALICE@\""));
        assertEquals(List.of(ALICE), ids("emails sw \"alice\" and emails ew \".com\""));
        assertEquals(List.of(bob, "phone_number:+61400000000"),
                ids(ScimSubjectService.SSF_EXT + ":streams eq \"s2\""));
        assertEquals(List.of(ALICE, bob), ids("userName pr"));
        assertEquals(List.of("opaque:carol", "phone_number:+61400000000"), ids("userName eq null"));
        assertEquals(List.of(ALICE, bob), ids("userName ne null"));
        assertEquals(List.of(ALICE, "opaque:carol"), ids("(userName eq \"alice\" or externalId eq \"carol\") and not (id eq \"x\")"));
        assertEquals(List.of(bob, "opaque:carol", "phone_number:+61400000000"), ids("not(userName eq \"alice\")"));
        assertEquals(List.of(ALICE, bob, "opaque:carol", "phone_number:+61400000000"), ids("id ne \"x\""));

        Map<String, Object> none = svc.query("userName eq \"nobody\"", null, null, PROVISIONER);
        assertEquals(0, none.get("totalResults"));
        assertEquals(List.of(), none.get("Resources"));
    }

    /** RFC 7644 §3.4.2.4: startIndex is 1-based; "A negative value SHALL be interpreted as "0"" for count. */
    @Test
    @Requirement("RFC7644 §3.4.2.4")
    void queryPagesByStartIndexAndCount() throws Exception {
        threeUsers();
        Map<String, Object> page = svc.query(null, 2, 2, PROVISIONER);
        assertEquals(4, page.get("totalResults"));
        assertEquals(2, page.get("startIndex"));
        assertEquals(2, page.get("itemsPerPage"));
        assertEquals(List.of("iss_sub:https://op.example.com Bob", "opaque:carol"), ids(page));
        assertEquals(List.of(), ids(svc.query(null, 1, -3, PROVISIONER)));
        assertEquals(1, svc.query(null, 0, 1, PROVISIONER).get("startIndex"));
        assertEquals(List.of(), ids(svc.query(null, 9, 5, PROVISIONER)));
        assertEquals(4, ids(svc.query(null, null, 5000, PROVISIONER)).size(), "capped at MAX_PAGE, which is more than four");
    }

    @Test
    @Requirement({"RFC7644 §3.4.2.2", "RFC7644 §3.12"})
    void aFilterOutsideTheSubsetIs400InvalidFilter() {
        for (String bad : List.of("userName gt \"a\"", "emails[type eq \"work\"]", "name.givenName eq \"a\"", "active eq \"true\"",
                "active co true", "userName eq alice", "userName eq \"alice", "userName eq \"a\" extra", "(userName eq \"a\"",
                "not userName eq \"a\"", "userName", "userName eq", "eq \"a\"", ") eq \"a\"", "", " ",
                ScimSubjectService.SSF_EXT + ":subject eq \"x\"", "userName eq \"\\q\"", "userName eq \"\\u12\"",
                "userName eq \"\\uzzzz\"", "userName eq \"a\\", "userName \"eq\" \"a\"", "(" .repeat(20) + "id pr" + ")".repeat(20),
                "id eq \"" + "x".repeat(ScimFilter.MAX_LENGTH) + "\"")) {
            scim(400, "invalidFilter", () -> ScimFilter.parse(bad));
        }
        scim(400, "invalidFilter", () -> svc.query("userName gt \"a\"", null, null, PROVISIONER));
        scim(400, "invalidFilter", () -> ScimFilter.parse(null));
    }

    @Test
    void theFilterReadsJsonEscapesInStrings() {
        ScimFilter f = ScimFilter.parse("userName eq \"a\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\"");
        assertTrue(f.matches(a -> a == ScimFilter.Attribute.USER_NAME ? List.of("a\"\\/\b\f\n\r\tA") : List.of()));
    }

    // ─────────────────────────────── whose authority ───────────────────────────────
    //
    // A deprovision has the transmitter sign an account-disabled about a subject the caller names, and a
    // receiving PingFederate revokes grants on that. It is a provisioner's to ask for and never a receiver's.

    @Test
    void aProvisionerActsAcrossEveryReceiversStreams() throws Exception {
        riscStream("a");
        ownedStream("b", OTHER.clientId(), SsfEventTypes.RISC_ACCOUNT_DISABLED);
        ownedStream("unowned", null, SsfEventTypes.RISC_ACCOUNT_DISABLED);
        ownedStream("without-her", OTHER.clientId(), SsfEventTypes.RISC_ACCOUNT_DISABLED);

        svc.create(user(List.of("a", "b", "unowned"), null), PROVISIONER);
        assertTrue(store.hasSubject("a", alice) && store.hasSubject("b", alice) && store.hasSubject("unowned", alice));

        svc.delete(ALICE, PROVISIONER);
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
        riscStream("mine");
        store.addSubject("mine", alice);
        AuthContext both = AuthContext.active("receiver-client", Set.of("ssf.manage", PROVISIONER_SCOPE));

        for (AuthContext refused : new AuthContext[] {RECEIVER, AuthContext.inactive(), null,
                AuthContext.active("scim-provisioner", Set.of("SSF.PROVISION"))}) {
            for (Executable call : new Executable[] {() -> svc.delete(ALICE, refused), () -> svc.create(user(List.of("mine"), null), refused),
                    () -> svc.replace(ALICE, user(List.of("mine"), false), refused), () -> svc.get(ALICE, refused),
                    () -> svc.patch(ALICE, patch(op("replace", "active", false)), refused), () -> svc.query(null, null, null, refused)}) {
                scim(403, null, call);
            }
        }
        assertEquals(0, store.peek("mine", 10).size(), "nothing was signed");
        assertTrue(store.hasSubject("mine", alice), "and nothing removed");

        // control: the same calls from a token that does carry the scope go through, so it was the scope
        svc.delete(ALICE, both);
        assertEquals(1, store.peek("mine", 10).size());
    }

    /** Fail closed: with no provisioner scope configured there are no provisioners, whatever a token carries. */
    @Test
    void withNoProvisionerScopeConfiguredNobodyProvisions() throws Exception {
        ScimSubjectService unconfigured = serviceWith(new SsfConfiguration.Builder().issuer("https://op.example.com").build());
        riscStream("s");
        store.addSubject("s", alice);

        for (AuthContext caller : new AuthContext[] {PROVISIONER, RECEIVER}) {
            scim(403, null, () -> unconfigured.delete(ALICE, caller));
            scim(403, null, () -> unconfigured.create(user(List.of("s"), null), caller));
        }
        assertEquals(0, store.peek("s", 10).size());

        svc.delete(ALICE, PROVISIONER); // control: configured, the same caller and stream work
        assertEquals(1, store.peek("s", 10).size());
    }

    // ─────────────────────────────── location ───────────────────────────────

    @Test
    void theLocationIsTheIdAsOnePathSegment() {
        assertEquals("email:alice+tag@example.com", ScimSubjectService.pathSegment("email:alice+tag@example.com"));
        assertEquals("iss_sub:https:%2F%2Fop.example.com%20Bob", ScimSubjectService.pathSegment("iss_sub:https://op.example.com Bob"));
        assertEquals("opaque:%C3%A9%3F%23%25", ScimSubjectService.pathSegment("opaque:\u00e9?#%"));
    }

    @Test
    void aRecordMayBeWrittenWithNoStreamsToRestore() {
        ScimUser u = new ScimUser(alice, null, null, true, null, 1, 2);
        assertEquals(List.of(), u.restoreStreams());
        assertEquals(ALICE, u.id());
        assertNull(u.userName());
    }
}
