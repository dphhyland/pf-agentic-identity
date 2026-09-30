/*
 * H-SSF-5 on the emitter: one txn per underlying event, valid CAEP payloads, and the transmitter's own events counted.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.signals.SetMinter;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfEventEmitterEventsTest {

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("k");
    private final List<Event> events = new CopyOnWriteArrayList<>();
    private final SubjectId alice = SubjectId.email("alice@example.com");
    private InMemorySsfStore store;
    private SsfEventEmitter emitter;

    @BeforeEach
    void setUp() {
        Events.reset();
        Events.configure(this.events::add);
        this.store = new InMemorySsfStore();
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        this.emitter = new SsfEventEmitter(this.store, new SetMinter("RS256", this.keys), cfg);
        for (String id : List.of("a", "b")) {
            this.store.createStream(Stream.builder().id(id).audience("https://r/" + id).ownerClientId("rx-" + id)
                    .deliveryMethod(DeliveryMethod.POLL).eventsRequested(SsfEventTypes.ALL).eventsDelivered(SsfEventTypes.ALL)
                    .status(StreamStatus.ENABLED).build());
            this.store.addSubject(id, this.alice);
        }
    }

    @AfterEach
    void release() {
        Events.reset();
    }

    /** The claims of the SET queued for {@code streamId} that carries {@code type} (SETs of one second come in jti order). */
    @SuppressWarnings("unchecked")
    private Map<String, Object> claims(String streamId, String type) throws Exception {
        for (PendingSet p : this.store.peek(streamId, 20)) {
            JsonWebSignature v = new JsonWebSignature();
            v.setCompactSerialization(p.setJws());
            v.setKey(this.keys.publicKey());
            assertTrue(v.verifySignature());
            Map<String, Object> claims = JsonUtil.parseJson(v.getPayload());
            if (((Map<String, Object>) claims.get("events")).containsKey(type)) {
                return claims;
            }
        }
        throw new AssertionError("no SET of " + type + " for " + streamId);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> event(String streamId, String type) throws Exception {
        return (Map<String, Object>) ((Map<String, Object>) claims(streamId, type).get("events")).get(type);
    }

    /**
     * SSF 1.0 §4.1.9: "Transmitters SHOULD set the "txn" claim ... it MUST be unique to the underlying event". One
     * PingFederate event reaching two streams is one underlying event: both SETs carry the same txn, the transaction id
     * given, and the next event another.
     */
    @Test
    @Requirement("SSF §4.1.9")
    void everySetFromOneEventCarriesOneTxn() throws Exception {
        this.emitter.sessionRevoked(this.alice, "logout", "pf-transaction-1");
        assertEquals("pf-transaction-1", claims("a", SsfEventTypes.CAEP_SESSION_REVOKED).get("txn"));
        assertEquals("pf-transaction-1", claims("b", SsfEventTypes.CAEP_SESSION_REVOKED).get("txn"));

        this.emitter.accountDisabled(this.alice, null);
        Object minted = claims("a", SsfEventTypes.RISC_ACCOUNT_DISABLED).get("txn");
        assertNotNull(minted, "no transaction id given: the emitter mints one");
        assertEquals(minted, claims("b", SsfEventTypes.RISC_ACCOUNT_DISABLED).get("txn"));
        assertNotEquals("pf-transaction-1", minted);

        this.emitter.accountEnabled(this.alice);
        assertNotEquals(minted, claims("a", SsfEventTypes.RISC_ACCOUNT_ENABLED).get("txn"), "another event, another txn");
    }

    /** A blank transaction id is none; a SET TTL of 0 queues SETs that never expire; naming a stream narrows the fan-out. */
    @Test
    void aBlankTxnIsMintedAndTheFanOutNarrows() throws Exception {
        SsfEventEmitter noTtl = new SsfEventEmitter(this.store, new SetMinter("RS256", this.keys),
                new SsfConfiguration.Builder().issuer("https://op.example.com").setTtlSeconds(0).build());
        assertEquals(1, noTtl.emit(SsfEventTypes.RISC_ACCOUNT_ENABLED, this.alice, Map.of("event_timestamp", 1L), "b", " ").size());
        assertTrue(this.store.peek("a", 10).isEmpty());
        Object txn = claims("b", SsfEventTypes.RISC_ACCOUNT_ENABLED).get("txn");
        assertTrue(txn instanceof String && !((String) txn).isBlank());
        assertEquals(0L, this.store.peek("b", 10).get(0).expiresAt());
    }

    /** One {@code ssf.set.emitted} per SET queued, so a fan-out to two streams counts twice. */
    @Test
    void eachQueuedSetIsCounted() throws Exception {
        this.emitter.sessionEstablished(this.alice, null);
        List<Event> emitted = this.events.stream().filter(e -> "ssf.set.emitted".equals(e.code())).toList();
        assertEquals(2, emitted.size());
        assertEquals("session-established", emitted.get(0).fields().get("event_type"));
        assertFalse(emitted.get(0).isFailure());
    }

    /** CAEP 1.0 §3.6: session-established's claims are all optional; this one is its event_timestamp. */
    @Test
    @Requirement("CAEP §3.6")
    void sessionEstablishedIsItsTimestamp() throws Exception {
        this.emitter.sessionEstablished(this.alice, "tx");
        assertEquals(List.of("event_timestamp"), List.copyOf(event("a", SsfEventTypes.CAEP_SESSION_ESTABLISHED).keySet()));
    }

    /** RISC 1.0 §2.2: account-purged, "Attributes: none". */
    @Test
    @Requirement("RISC §2.2")
    void accountPurgedHasNoAttributes() throws Exception {
        this.emitter.accountPurged(this.alice, null);
        assertEquals(List.of("event_timestamp"), List.copyOf(event("a", SsfEventTypes.RISC_ACCOUNT_PURGED).keySet()));
    }

    /** CAEP 1.0 §3.3.1: credential_type and change_type each "MUST be one of" the registered strings. */
    @Test
    @Requirement("CAEP §3.3.1")
    void aCredentialChangeCarriesOnlyARegisteredCredentialType() throws Exception {
        this.emitter.credentialChange(this.alice, "fido2-roaming", "create");
        Map<String, Object> payload = event("a", SsfEventTypes.CAEP_CREDENTIAL_CHANGE);
        assertEquals("fido2-roaming", payload.get("credential_type"));
        assertEquals("create", payload.get("change_type"));

        assertThrows(IllegalArgumentException.class, () -> this.emitter.credentialChange(this.alice, "credential", "update"));
        assertThrows(IllegalArgumentException.class, () -> this.emitter.credentialChange(this.alice, null, "update"));
        assertThrows(IllegalArgumentException.class, () -> this.emitter.credentialChange(this.alice, "password", "rotate"));
        assertThrows(IllegalArgumentException.class, () -> this.emitter.credentialChange(this.alice, "password", null));
        assertEquals(1, this.store.peek("a", 10).size(), "nothing was sent as a guess");
        assertTrue(SsfEventEmitter.validCredentialType("x509"));
        assertFalse(SsfEventEmitter.validCredentialType("X509"));
    }

    /**
     * CAEP 1.0 §3.4.1: {@code namespace} "REQUIRED", {@code current_level} "REQUIRED", {@code previous_level}
     * "OPTIONAL", {@code change_direction} if present "MUST be one of" increase or decrease.
     */
    @Test
    @Requirement("CAEP §3.4.1")
    void assuranceLevelChangeIsCaepShaped() throws Exception {
        this.emitter.assuranceLevelChange(this.alice, "NIST-AAL", "nist-aal1", "nist-aal2", "increase", "tx");
        Map<String, Object> payload = event("a", SsfEventTypes.CAEP_ASSURANCE_LEVEL_CHANGE);
        assertEquals("NIST-AAL", payload.get("namespace"));
        assertEquals("nist-aal2", payload.get("current_level"));
        assertEquals("nist-aal1", payload.get("previous_level"));
        assertEquals("increase", payload.get("change_direction"));

        Map<String, Object> bare = SsfEventEmitter.assuranceLevelPayload(1L, "RFC8176", null, "otp", null);
        assertEquals(List.of("event_timestamp", "namespace", "current_level"), List.copyOf(bare.keySet()),
                "no previous level and no direction: neither is written, and never 'unknown'");
        assertThrows(IllegalArgumentException.class, () -> SsfEventEmitter.assuranceLevelPayload(1L, " ", null, "x", null));
        assertThrows(IllegalArgumentException.class, () -> SsfEventEmitter.assuranceLevelPayload(1L, null, null, "x", null));
        assertThrows(IllegalArgumentException.class, () -> SsfEventEmitter.assuranceLevelPayload(1L, "NIST-AAL", null, " ", null));
        assertFalse(SsfEventEmitter.assuranceLevelPayload(1L, "NIST-AAL", " ", "x", null).containsKey("previous_level"));
        assertThrows(IllegalArgumentException.class, () -> SsfEventEmitter.assuranceLevelPayload(1L, "NIST-AAL", null, null, null));
        assertThrows(IllegalArgumentException.class, () -> SsfEventEmitter.assuranceLevelPayload(1L, "NIST-AAL", "a", "b", "unknown"));
        assertEquals("decrease", SsfEventEmitter.assuranceLevelPayload(1L, "NIST-AAL", "2", "1", "decrease").get("change_direction"));
    }
}
