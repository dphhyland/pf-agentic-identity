/*
 * PingFederate's sink: server.log always, the audit log for audit events, and nothing that can fail a request.
 */
package com.pingidentity.ps.oidf.platform.pf.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.EventCatalogue;
import com.pingidentity.ps.oidf.platform.events.EventCatalogues;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.events.LogSafe;
import com.pingidentity.ps.oidf.platform.events.LoggingSink;
import com.pingidentity.ps.oidf.platform.events.PiiClass;
import com.pingidentity.ps.oidf.platform.events.PiiPolicy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class PfAuditSinkTest {
    /** One component, {@code club}, whose audit protocol is {@code Club}: a join (audit) carrying a member's name. */
    private static final String CLUB = """
            {"component": "club", "module": "libs/club", "description": "A club.", "logger": "com.example.club.event",
             "auditProtocol": "Club",
             "fields": {"member": {"pii": "DIRECT_ID", "description": "The member's name."},
                        "level": {"pii": "OPERATIONAL", "description": "The membership level."}},
             "events": {"club.member.joined": {"description": "A join.", "audit": true, "outcomes": ["success", "failure"],
                        "level": "info", "fields": ["member", "level"], "declaredOnly": false}}}
            """;
    private static final EventCatalogues CATALOGUES = EventCatalogues.of(List.of(EventCatalogue.parse(CLUB)));

    private record Written(Event event, String protocol, String address) {
    }

    private final List<Event> serverLog = new ArrayList<>();
    private final List<Written> audit = new ArrayList<>();

    @AfterEach
    void reset() {
        Events.reset();
        LogSafe.configureMaxValueLength(LogSafe.DEFAULT_MAX_VALUE_LENGTH);
    }

    private PfAuditSink sink(boolean enabled, String address, PiiPolicy policy) {
        return new PfAuditSink(this.serverLog::add, (e, p, a) -> this.audit.add(new Written(e, p, a)), enabled,
                () -> address, () -> CATALOGUES, policy);
    }

    private static Event joined() {
        return Event.builder("club", "club.member.joined").subject("c-1").field("member", "Jane Citizen")
                .field("level", "gold").field("card_number", "4111").audit().build();
    }

    @Test
    void anAuditEventGoesToBothLogsAndAnOrdinaryOneOnlyToTheServerLog() {
        PfAuditSink sink = this.sink(true, "203.0.113.9", PiiPolicy.DEFAULT);

        sink.emit(joined());
        sink.emit(Event.builder("club", "club.member.joined").build());

        assertEquals(2, this.serverLog.size());
        assertEquals(1, this.audit.size());
        Written written = this.audit.get(0);
        assertEquals("203.0.113.9", written.address());
        assertEquals("Club", written.protocol());
        assertEquals(Map.of("member", "Jane Citizen", "level", "gold"), written.event().fields());
        assertEquals(Map.of("member", "Jane Citizen", "level", "gold"), this.serverLog.get(0).fields(),
                "an undeclared field reaches neither log");
        assertTrue(sink.auditEnabled());
    }

    @Test
    void theAuditPolicyIsAppliedToTheAuditRecordOnly() {
        PiiPolicy policy = PiiPolicy.DEFAULT.with(PiiPolicy.Destination.AUDIT_LOG, PiiClass.DIRECT_ID, PiiPolicy.Treatment.DROP);
        this.sink(true, null, policy).emit(joined());

        assertEquals(Map.of("level", "gold"), this.audit.get(0).event().fields());
        assertNull(this.audit.get(0).address());
        assertEquals("Jane Citizen", this.serverLog.get(0).fields().get("member"),
                "the audit log's policy does not reach server.log");
    }

    /** Finding F-0165: a direct identifier - an operator's X-Federation-Actor - never reaches server.log in clear. */
    @Test
    void theProcessPolicyDigestsADirectIdentifierInServerLogAndKeepsItInTheAuditLog() {
        this.sink(true, null, PfAuditSink.PROCESS_POLICY).emit(joined());

        String inServerLog = this.serverLog.get(0).fields().get("member");
        assertTrue(inServerLog.startsWith("sha256:") && !inServerLog.contains("Jane"), inServerLog);
        assertEquals("gold", this.serverLog.get(0).fields().get("level"));
        assertEquals("Jane Citizen", this.audit.get(0).event().fields().get("member"));
        assertEquals(PiiPolicy.Treatment.DIGEST, PfAuditSink.PROCESS_POLICY.treatment(PiiPolicy.Destination.SERVER_LOG,
                PiiClass.DIRECT_ID));
    }

    @Test
    void theCallersAddressIsNetworkDataUnderTheAuditPolicy() {
        PiiPolicy digest = PiiPolicy.DEFAULT.with(PiiPolicy.Destination.AUDIT_LOG, PiiClass.NETWORK, PiiPolicy.Treatment.DIGEST);
        this.sink(true, "203.0.113.9", digest).emit(joined());
        this.sink(true, "203.0.113.9", PiiPolicy.DEFAULT
                .with(PiiPolicy.Destination.SERVER_LOG, PiiClass.NETWORK, PiiPolicy.Treatment.DROP)).emit(joined());

        String digested = this.audit.get(0).address();
        assertTrue(digested.startsWith("sha256:") && !digested.contains("203.0.113.9"), digested);
        assertEquals(digest.treat(PiiPolicy.Destination.AUDIT_LOG, PiiClass.NETWORK, "203.0.113.9"), digested);
        assertEquals("203.0.113.9", this.audit.get(1).address(), "server.log's rule does not reach the ip column");
    }

    @Test
    void oneEventThroughEveryLayerCountsOnce() {
        EventCatalogues fresh = EventCatalogues.of(List.of(EventCatalogue.parse(CLUB)));
        EventCatalogues.install(fresh);
        Events.configure(new PfAuditSink(new LoggingSink(() -> fresh, PiiPolicy.DEFAULT),
                (e, p, a) -> this.audit.add(new Written(e, p, a)), true, () -> null, () -> fresh, PiiPolicy.DEFAULT));

        Events.event("club", "club.member.left").field("member", "Jane Citizen").audit().emit();
        Events.emit(joined());

        assertEquals(1, fresh.uncataloguedEvents(), "Events.emit, the audit sink and the server-log sink: one count");
        assertEquals(2, fresh.droppedFields());
        assertEquals(2, this.audit.size());
    }

    @Test
    void auditCanBeTurnedOffAndAFailingWriterIsSwallowed() {
        new PfAuditSink(this.serverLog::add, (e, p, a) -> {
            throw new AssertionError("must not be called");
        }, false, () -> null, () -> CATALOGUES, PiiPolicy.DEFAULT).emit(joined());
        new PfAuditSink(this.serverLog::add, (e, p, a) -> {
            throw new IllegalStateException("audit service unavailable");
        }, true, () -> null, () -> CATALOGUES, PiiPolicy.DEFAULT).emit(joined());
        new PfAuditSink(this.serverLog::add, (e, p, a) -> {
            throw new NoClassDefFoundError("com/pingidentity/sdk/internal/Service");
        }, true, () -> null).emit(joined());
        assertEquals(3, this.serverLog.size());
        assertThrows(NullPointerException.class, () -> new PfAuditSink(null, (e, p, a) -> { }, true, () -> null));
    }

    @Test
    void theRealWriterNeverBreaksARequestOutsidePingFederate() {
        PfAuditSink sink = new PfAuditSink(this.serverLog::add, PfAuditSink.loggingUtil(), true, () -> "203.0.113.9");
        sink.emit(Event.builder("club", "club.member.joined").subject("s").partner("p").role("TA").requestJti("j")
                .description("d").audit().build());
        assertEquals(1, this.serverLog.size());
        assertSame(PfAuditSink.loggingUtil(), PfAuditSink.loggingUtil());
    }

    @Test
    void theProtocolIsTheComponentsAndTheDefaultWhenItHasNoCatalogue() {
        assertEquals("Club", PfAuditSink.protocolOf(joined(), CATALOGUES));
        assertEquals(PfAuditSink.DEFAULT_PROTOCOL,
                PfAuditSink.protocolOf(Event.builder("other", "x.y").build(), CATALOGUES));
        assertEquals("OpenID Federation", PfAuditSink.DEFAULT_PROTOCOL);
    }

    @Test
    void theRecordIsTheEventsColumnsMadeSafe() {
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2EifQ.c2lnbmF0dXJl";
        Event event = Event.builder("club", "club.member.joined").failure("no_room").subject("s\nforged").partner(jwt)
                .role("TA").requestJti("j-1").field("level", "gold").build();

        PfAuditSink.AuditRecord record = PfAuditSink.record(event, "Club", "203.0.113.9\r");

        assertEquals(new PfAuditSink.AuditRecord("club.member.joined", true, "s_forged", LogSafe.jwtDigest(jwt), "Club", "TA",
                "203.0.113.9_", "j-1", "reason=no_room subject=s_forged partner=" + LogSafe.jwtDigest(jwt)
                + " level=gold request_jti=j-1"), record);
        PfAuditSink.AuditRecord bare = PfAuditSink.record(Event.builder("club", "a.b").build(), "Club", null);
        assertNull(bare.userName());
        assertNull(bare.partnerId());
        assertNull(bare.remoteAddress());
        assertNull(bare.requestJti());
        assertNull(bare.role());
        assertFalse(bare.failure());
    }

    @Test
    void theAuditDescriptionIsTheEventLineWithoutItsHead() {
        Event event = Event.builder("club", "federation.registration.refused").failure("no_policy").subject("https://rp.example")
                .field("type", "explicit").build();
        assertEquals("reason=no_policy subject=https://rp.example type=explicit", PfAuditSink.auditDescription(event));
        assertEquals("", PfAuditSink.auditDescription(Event.builder("club", "a.b.c").build()));
    }

    @Test
    void configureReadsTheAuditSwitchAndTheValueCap() {
        assertFalse(PfAuditSink.configure(Map.of(PfAuditSink.AUDIT_ENV, "false", PfAuditSink.MAX_VALUE_LENGTH_ENV, " 64 ")::get,
                name -> null));
        assertEquals(64, LogSafe.maxValueLength());
        assertTrue(PfAuditSink.configure(Map.of(PfAuditSink.AUDIT_ENV, "false", PfAuditSink.MAX_VALUE_LENGTH_ENV, "lots")::get,
                Map.of(PfAuditSink.AUDIT_PROP, "true")::get), "the system property comes first");
        assertEquals(64, LogSafe.maxValueLength(), "a cap that is not a number keeps the one there was");
        assertFalse(PfAuditSink.configure(Map.of(PfAuditSink.AUDIT_ENV, "false", PfAuditSink.MAX_VALUE_LENGTH_ENV, " ")::get,
                Map.of(PfAuditSink.AUDIT_PROP, " ")::get), "a blank property falls back to the environment");
        assertTrue(PfAuditSink.configure(name -> null, name -> null));
    }

    @Test
    void anAuditSwitchThatIsNeitherTrueNorFalseLeavesAuditOn() {
        assertTrue(PfAuditSink.auditSwitch(null));
        assertTrue(PfAuditSink.auditSwitch(" "));
        assertTrue(PfAuditSink.auditSwitch(" TRUE "));
        assertFalse(PfAuditSink.auditSwitch("False"));
        assertTrue(PfAuditSink.auditSwitch("yes"), "a typo must not be what turns security auditing off");
        assertTrue(PfAuditSink.auditSwitch("off"));
        assertTrue(PfAuditSink.auditSwitch("0"));
    }

    @Test
    void installPutsThisSinkInPlatformsRegistryOnceTheFirstInstallWinning() {
        PfAuditSink.install(Map.of(PfAuditSink.AUDIT_ENV, "false")::get, name -> null, () -> null);
        PfAuditSink installed = assertInstanceOf(PfAuditSink.class, Events.sink());
        assertFalse(installed.auditEnabled());
        PfAuditSink.install(() -> null);
        assertSame(installed, Events.sink(), "the first install wins");
        Events.reset();
        PfAuditSink.install(() -> "203.0.113.9");
        assertTrue(((PfAuditSink) Events.sink()).auditEnabled(), "audit is on unless switched off");
    }
}
