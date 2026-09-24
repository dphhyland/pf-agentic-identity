package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.event.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The PingFederate sink: every event reaches {@code server.log}; audit events also reach the audit
 * writer, with the request's host and address; nothing an audit write does can fail a request.
 */
class PfAuditEventSinkTest {

    @AfterEach
    void reset() {
        FederationEvents.reset();
        PfRequestScope.exit();
        ThreadContext.remove(PfTracking.TRACKING_ID_KEY);
        LogSafe.configureMaxValueLength(LogSafe.DEFAULT_MAX_VALUE_LENGTH);
    }

    private record Written(FederationEvent event, PfRequestScope.Context request) {
    }

    @Test
    void anAuditEventGoesToBothLogsAndAnOrdinaryOneOnlyToTheServerLog() {
        List<FederationEvent> serverLog = new ArrayList<>();
        List<Written> audit = new ArrayList<>();
        PfAuditEventSink sink = new PfAuditEventSink(serverLog::add, (e, r) -> audit.add(new Written(e, r)), true);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServerName()).thenReturn("pf.example");
        when(request.getRemoteAddr()).thenReturn("203.0.113.9");
        PfRequestScope.enter(request);

        sink.emit(FederationEvents.event(FederationEvents.REGISTRATION_CREATED).subject("https://rp.example").audit().build());
        sink.emit(FederationEvents.event(FederationEvents.CHAIN_VALIDATED).build());

        assertEquals(2, serverLog.size());
        assertEquals(1, audit.size());
        assertEquals("pf.example", audit.get(0).request().host());
        assertEquals("203.0.113.9", audit.get(0).request().remoteAddress());
        assertTrue(sink.auditEnabled());
    }

    @Test
    void auditCanBeTurnedOffAndAFailingWriterIsSwallowed() {
        List<FederationEvent> serverLog = new ArrayList<>();
        PfAuditEventSink off = new PfAuditEventSink(serverLog::add, (e, r) -> {
            throw new AssertionError("must not be called");
        }, false);
        off.emit(FederationEvents.event(FederationEvents.CHAIN_REFUSED).failure("signature").audit().build());
        assertEquals(1, serverLog.size());

        PfAuditEventSink failing = new PfAuditEventSink(serverLog::add, (e, r) -> {
            throw new IllegalStateException("audit service unavailable");
        }, true);
        failing.emit(FederationEvents.event(FederationEvents.CHAIN_REFUSED).failure("signature").audit().build());
        PfAuditEventSink linkage = new PfAuditEventSink(serverLog::add, (e, r) -> {
            throw new NoClassDefFoundError("com/pingidentity/sdk/internal/Service");
        }, true);
        linkage.emit(FederationEvents.event(FederationEvents.CHAIN_REFUSED).failure("signature").audit().build());
        assertEquals(3, serverLog.size());
    }

    @Test
    void theRealLoggingUtilWriterNeverBreaksARequestOutsidePingFederate() {
        List<FederationEvent> serverLog = new ArrayList<>();
        PfAuditEventSink sink = new PfAuditEventSink(serverLog::add, new PfAuditEventSink.LoggingUtilAuditWriter(), true);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServerName()).thenReturn("pf.example");
        PfRequestScope.enter(request);

        sink.emit(FederationEvents.event(FederationEvents.HOSTED_ENTITY_REVOKED).subject("https://pf.example/federation/agents/a")
                .partner("https://pf.example").role("TA").requestJti("j").description("revoked").audit().build());

        assertEquals(1, serverLog.size());
    }

    @Test
    void theAuditDescriptionIsTheEventLineWithoutItsHead() {
        FederationEvent event = FederationEvents.event(FederationEvents.REGISTRATION_REFUSED).failure("no_policy")
                .subject("https://rp.example").field("type", "explicit").build();
        assertEquals("reason=no_policy subject=https://rp.example type=explicit", PfAuditEventSink.auditDescription(event));
        assertEquals("", PfAuditEventSink.auditDescription(FederationEvents.event("a.b.c").build()));
    }

    @Test
    void installReadsTheAuditSwitchAndTheValueCapOnce() {
        PfAuditEventSink.install(Map.of(PfAuditEventSink.AUDIT_ENV, "false",
                PfAuditEventSink.MAX_VALUE_LENGTH_ENV, "64")::get, name -> null);
        PfAuditEventSink installed = assertInstanceOf(PfAuditEventSink.class, FederationEvents.sink());
        assertFalse(installed.auditEnabled());
        assertEquals(64, LogSafe.maxValueLength());

        PfAuditEventSink.install(Map.of(PfAuditEventSink.AUDIT_ENV, "true")::get, name -> null);
        assertFalse(((PfAuditEventSink) FederationEvents.sink()).auditEnabled(), "the first install wins");

        FederationEvents.reset();
        PfAuditEventSink.install(Map.of(PfAuditEventSink.MAX_VALUE_LENGTH_ENV, "lots")::get,
                Map.of(PfAuditEventSink.AUDIT_PROP, "true")::get);
        assertTrue(((PfAuditEventSink) FederationEvents.sink()).auditEnabled());
        FederationEvents.reset();
        PfAuditEventSink.install();
        assertTrue(((PfAuditEventSink) FederationEvents.sink()).auditEnabled(), "audit is on unless switched off");
    }

    // ---- tracking and request scope --------------------------------------------------------------

    @Test
    void aDaemonRunGetsItsOwnTrackingIdAndGivesItBack() {
        AtomicReference<String> seen = new AtomicReference<>();
        assertNull(PfTracking.trackingId());

        PfTracking.decorate("oidf-prewarm", () -> seen.set(PfTracking.trackingId())).run();

        assertTrue(seen.get().startsWith("oidf-prewarm-"), seen.get());
        assertNull(PfTracking.trackingId(), "the generated id is removed after the run");

        ThreadContext.put(PfTracking.TRACKING_ID_KEY, "req-1");
        PfTracking.decorate("oidf-sweep", () -> seen.set(PfTracking.trackingId())).run();
        assertTrue(seen.get().startsWith("oidf-sweep-"));
        assertEquals("req-1", PfTracking.trackingId(), "a request's own id is restored");
        assertEquals("req-1", PfTracking.trackingIdOr("x"));
        ThreadContext.remove(PfTracking.TRACKING_ID_KEY);
        assertTrue(PfTracking.trackingIdOr("x").startsWith("x-"));
    }

    @Test
    void theRequestScopeIsPerThreadAndClearedOnExit() {
        PfRequestScope.enter(null);
        assertNull(PfRequestScope.current());
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("198.51.100.1");
        PfRequestScope.enter(request);
        assertEquals("198.51.100.1", PfRequestScope.current().remoteAddress());
        PfRequestScope.exit();
        assertNull(PfRequestScope.current());
    }
}
