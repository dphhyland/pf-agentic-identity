package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.event.LogSafe;
import com.pingidentity.sdk.logging.LoggingUtil;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

/**
 * The PingFederate sink: every event reaches {@code server.log}; audit events also reach the audit
 * writer, with the caller's address; nothing an audit write does can fail a request.
 */
class PfAuditEventSinkTest {

    @AfterEach
    void reset() {
        FederationEvents.reset();
        PfRequestScope.exit(null);
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
        when(request.getRemoteAddr()).thenReturn("203.0.113.9");
        PfRequestScope.enter(request);

        sink.emit(FederationEvents.event(FederationEvents.REGISTRATION_CREATED).subject("https://rp.example").audit().build());
        sink.emit(FederationEvents.event(FederationEvents.CHAIN_VALIDATED).build());

        assertEquals(2, serverLog.size());
        assertEquals(1, audit.size());
        assertEquals("203.0.113.9", audit.get(0).request().remoteAddress());
        assertTrue(sink.auditEnabled());
    }

    @Test
    void anAuditEventOffARequestHasNoAddress() {
        List<Written> audit = new ArrayList<>();
        PfAuditEventSink sink = new PfAuditEventSink(e -> { }, (e, r) -> audit.add(new Written(e, r)), true);

        sink.emit(FederationEvents.event(FederationEvents.REGISTRATION_DISABLED).subject("https://rp.example").audit().build());

        assertNull(audit.get(0).request(), "a daemon's audit record names no caller");
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
        when(request.getRemoteAddr()).thenReturn("203.0.113.9");
        PfRequestScope.enter(request);

        sink.emit(FederationEvents.event(FederationEvents.HOSTED_ENTITY_REVOKED).subject("https://pf.example/federation/agents/a")
                .partner("https://pf.example").role("TA").requestJti("j").description("revoked").audit().build());

        assertEquals(1, serverLog.size());
    }

    /**
     * What the real writer asks of PingFederate's SDK. In PF 13.0 and 13.1 the SDK's {@code setProtocol} writes the
     * {@code ip} column, so the writer never calls it and puts the protocol where PF's own AuditLogger does; the address
     * is the request's; the host is left to PF, which fills it with this node's name.
     */
    @Test
    void theRealWriterFillsIpFromTheRequestAndProtocolWithoutTheSdksSetProtocol() {
        FederationEvent full = FederationEvents.event(FederationEvents.REGISTRATION_REFUSED).failure("invalid_trust_chain")
                .subject("https://rp.example").partner("https://ta.example").role("OP").requestJti("j-1").audit().build();
        FederationEvent bare = FederationEvents.event(FederationEvents.KEY_RETIRED).audit().build();
        Map<String, String> atLog = new HashMap<>();
        try (MockedStatic<LoggingUtil> sdk = mockStatic(LoggingUtil.class)) {
            sdk.when(() -> LoggingUtil.log(anyString())).thenAnswer(call -> {
                atLog.putAll(ThreadContext.getImmutableContext());
                return null;
            });

            new PfAuditEventSink.LoggingUtilAuditWriter().write(full, new PfRequestScope.Context("203.0.113.9"));

            sdk.verify(() -> LoggingUtil.setRemoteAddress("203.0.113.9"));
            sdk.verify(() -> LoggingUtil.setProtocol(anyString()), never());
            sdk.verify(() -> LoggingUtil.setHost(anyString()), never());
            sdk.verify(() -> LoggingUtil.setStatus(LoggingUtil.FAILURE));
            sdk.verify(() -> LoggingUtil.setUserName("https://rp.example"));
            sdk.verify(() -> LoggingUtil.setPartnerId("https://ta.example"));
            sdk.verify(() -> LoggingUtil.setRole("OP"));
            sdk.verify(() -> LoggingUtil.setRequestJti("j-1"));
            sdk.verify(LoggingUtil::cleanup);
            assertEquals(PfAuditEventSink.PROTOCOL, atLog.get("protocol"));

            sdk.clearInvocations();
            new PfAuditEventSink.LoggingUtilAuditWriter().write(bare, null);
            new PfAuditEventSink.LoggingUtilAuditWriter().write(bare, new PfRequestScope.Context(null));

            sdk.verify(() -> LoggingUtil.setRemoteAddress(anyString()), never());
            sdk.verify(() -> LoggingUtil.setStatus(LoggingUtil.SUCCESS), times(2));
            sdk.verify(() -> LoggingUtil.setUserName(anyString()), never());
            sdk.verify(() -> LoggingUtil.setPartnerId(anyString()), never());
            sdk.verify(() -> LoggingUtil.setRole(anyString()), never());
            sdk.verify(() -> LoggingUtil.setRequestJti(anyString()), never());
        } finally {
            // The SDK's cleanup, which empties the protocol column in PingFederate, was mocked.
            ThreadContext.remove("protocol");
        }
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

    @Test
    void anAuditSwitchThatIsNeitherTrueNorFalseLeavesAuditOn() {
        assertTrue(PfAuditEventSink.auditSwitch(null));
        assertTrue(PfAuditEventSink.auditSwitch(" "));
        assertTrue(PfAuditEventSink.auditSwitch(" TRUE "));
        assertFalse(PfAuditEventSink.auditSwitch("False"));
        assertTrue(PfAuditEventSink.auditSwitch("yes"), "a typo must not be what turns security auditing off");
        assertTrue(PfAuditEventSink.auditSwitch("off"));
        assertTrue(PfAuditEventSink.auditSwitch("0"));
    }

    // ---- tracking ----------------------------------------------------------------------------------

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
}
