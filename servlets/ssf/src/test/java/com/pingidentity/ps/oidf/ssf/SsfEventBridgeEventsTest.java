/*
 * The bridge counts every PingFederate event that raised no SET, with its reason and its source.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfEventBridgeEventsTest {

    private final List<Event> events = new CopyOnWriteArrayList<>();
    private final SubjectId bob = SubjectId.issSub("https://op.example.com", "bob");

    @BeforeEach
    void setUp() {
        SsfSupport.resetForTests();
        SsfEventBridge.resetRecentForTests();
        Events.reset();
        Events.configure(this.events::add);
    }

    @AfterEach
    void tearDown() {
        SsfEventBridge.useEmitterForTests(null);
        SsfSupport.resetForTests();
        SsfEventBridge.resetRecentForTests();
        Events.reset();
    }

    private List<String> dropped() {
        return this.events.stream().filter(e -> "ssf.set.dropped".equals(e.code()))
                .map(e -> e.fields().get("event_type") + "/" + e.reason() + "/" + e.fields().get("source")).toList();
    }

    @Test
    void anEventRaisedBeforeTheTransmitterStartsIsCountedNotStarted() {
        assertEquals(0, SsfEventBridge.onSessionEstablished(this.bob, "tx", "audit"));
        assertEquals(0, SsfEventBridge.onAccountPurged(this.bob, null, "audit"));
        assertEquals(0, SsfEventBridge.onAccountEnabled(this.bob, null, "audit"));
        assertEquals(0, SsfEventBridge.onAccountDisabled(this.bob, null, "tx", "audit"));
        assertEquals(0, SsfEventBridge.onAssuranceLevelChange(this.bob, "NIST-AAL", "1", "2", "increase"));
        assertEquals(0, SsfEventBridge.onCredentialChange(this.bob, "password", "update"));
        assertEquals(List.of("session-established/not_started/audit", "account-purged/not_started/audit",
                "account-enabled/not_started/audit", "account-disabled/not_started/audit",
                "assurance-level-change/not_started/bridge", "credential-change/not_started/bridge"), dropped());
    }

    /** CAEP 1.0 §3.3.1: a credential this transmitter cannot name from CAEP's list is not sent as a guess. */
    @Test
    void aCredentialCaepDoesNotRegisterIsDroppedNotGuessed() {
        assertEquals(0, SsfEventBridge.onCredentialChange(this.bob, null, "update", "tx", "audit"));
        assertEquals(0, SsfEventBridge.onCredentialChange(this.bob, "credential", "update", "tx", "audit"));
        assertEquals(0, SsfEventBridge.onCredentialChange(null, "credential", "update", "tx", "audit"), "no subject: nothing at all");
        assertEquals(List.of("credential-change/credential_type/audit", "credential-change/credential_type/audit"), dropped());
    }

    @Test
    void aSecondObserverOfTheSameEventIsCountedAsADuplicate() {
        SsfEventBridge.recordEmission("session-revoked", this.bob);
        assertEquals(0, SsfEventBridge.onSessionRevoked(this.bob, "logout", "tx", "logout"));
        assertEquals(List.of("session-revoked/duplicate/logout"), dropped());
    }

    @Test
    void anEmissionThatThrowsIsCountedFailed() {
        SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com").build());
        InMemorySsfStore store = (InMemorySsfStore) SsfSupport.store();
        store.createStream(Stream.builder().id("s").audience("https://r").deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(SsfEventTypes.ALL).eventsDelivered(SsfEventTypes.ALL).status(StreamStatus.ENABLED).build());
        store.addSubject("s", this.bob);
        // PingFederate's signing keys are not there outside PingFederate, so minting throws
        assertEquals(0, SsfEventBridge.onSessionRevoked(this.bob, "logout"));
        assertEquals(List.of("session-revoked/failed/bridge"), dropped());
        assertEquals(0, SsfEventBridge.onAssuranceLevelChange(this.bob, " ", null, "x", null), "a bad payload is a failure too");
        assertEquals(List.of("session-revoked/failed/bridge", "assurance-level-change/failed/bridge"), dropped());
    }

    @Test
    void noStreamHearsItMeansNothingIsQueuedAndNothingDropped() {
        SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com").build());
        assertEquals(0, SsfEventBridge.onSessionEstablished(this.bob, null, "audit"));
        assertEquals(List.of(), dropped());
    }

    /** Every hook through a running emitter: one SET each to the stream that hears the subject, each counted once. */
    @Test
    void everyHookRaisesItsEventThroughTheEmitter() throws Exception {
        InMemorySsfStore store = new InMemorySsfStore();
        store.createStream(Stream.builder().id("s").audience("https://r").deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(SsfEventTypes.ALL).eventsDelivered(SsfEventTypes.ALL).status(StreamStatus.ENABLED).build());
        store.addSubject("s", this.bob);
        SsfEventBridge.useEmitterForTests(new SsfEventEmitter(store,
                new com.pingidentity.ps.oidf.signals.SetMinter("RS256", new TestSigningKeyProvider("k")),
                new SsfConfiguration.Builder().issuer("https://op.example.com").build()));

        assertEquals(1, SsfEventBridge.onSessionRevoked(this.bob, "logout"));
        assertEquals(1, SsfEventBridge.onSessionEstablished(this.bob, "tx", "audit"));
        assertEquals(1, SsfEventBridge.onCredentialChange(this.bob, "password", "update"));
        assertEquals(1, SsfEventBridge.onAssuranceLevelChange(this.bob, "NIST-AAL", "nist-aal1", "nist-aal2", "increase"));
        assertEquals(1, SsfEventBridge.onDeviceComplianceChange(this.bob, "compliant", "not-compliant", "jailbroken"));
        assertEquals(1, SsfEventBridge.onAccountDisabled(this.bob, "hijacking"));
        assertEquals(1, SsfEventBridge.onAccountEnabled(this.bob));
        assertEquals(1, SsfEventBridge.onAccountPurged(this.bob, "tx", "audit"));
        assertEquals(0, SsfEventBridge.onSessionRevoked(this.bob, "again"), "the same event and subject within the window");
        assertEquals(8, store.peek("s", 20).size());
        assertEquals(8, this.events.stream().filter(e -> "ssf.set.emitted".equals(e.code())).count());
        assertEquals(List.of("session-revoked/duplicate/bridge"), dropped());
    }

    @Test
    void theShortNameIsTheLastSegment() {
        assertEquals("session-revoked", SsfEvents.shortName(SsfEventTypes.CAEP_SESSION_REVOKED));
        assertEquals("plain", SsfEvents.shortName("plain"));
        assertEquals(null, SsfEvents.shortName(null));
    }
}
