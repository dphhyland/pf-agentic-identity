/*
 * Our audit record written in the middle of one of PingFederate's requests leaves PingFederate's audit context as it was.
 */
package com.pingidentity.ps.oidf.platform.pf.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.sdk.logging.LoggingUtil;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Plan item H-FED-7, finding F-0049, through the SDK's own {@link LoggingUtil} and PingFederate 13.1.3's
 * {@code AuditLogger} ({@link SdkAuditLoggerForTests}). The context below is the one the rig's token endpoint had on
 * the thread when an OGNL issuance criterion ran (2026-10-01, a client-credentials request; values shortened).
 */
class LoggingUtilAuditWriterTest {
    private static final Map<String, String> TOKEN_REQUEST = new LinkedHashMap<>();

    static {
        TOKEN_REQUEST.put("httprequestid", "rzoIkO7Aq6JJkCmkqHLVfr1cD");
        TOKEN_REQUEST.put("tlsversion", "TLSv1.3");
        TOKEN_REQUEST.put("trackingid", "tid:sxuK51AA1JLzKJqXBYKcmz3Eax4");
        TOKEN_REQUEST.put("transactionid", "vNfglCSjEdXqJn6k29yCj21Fh");
        TOKEN_REQUEST.put("host", "eeb5b27187a5");
        TOKEN_REQUEST.put("status", "inprogress");
        TOKEN_REQUEST.put("pfversion", "13.1");
        TOKEN_REQUEST.put("requeststarttime", "1790783699771");
        TOKEN_REQUEST.put("ip", "192.168.192.1");
        TOKEN_REQUEST.put("event", "OAuth");
        TOKEN_REQUEST.put("protocol", "OAuth20");
        TOKEN_REQUEST.put("connectionid", "conformance-ssf-emitter");
        TOKEN_REQUEST.put("role", "AS");
        TOKEN_REQUEST.put("responsetime", "5");
        TOKEN_REQUEST.put("granttype", "client_credentials");
        TOKEN_REQUEST.put("subject", "conformance-ssf-emitter");
        TOKEN_REQUEST.put("inmsgmap", "client_id=conformance-ssf-emitter,scope=ssf.provision");
    }

    private static Event revoked() {
        return Event.builder("federation", "federation.hosted_entity.revoked").failure("revoked")
                .subject("https://pf.example/federation/agents/a").role("TA").requestJti("j-1").audit().build();
    }

    @BeforeAll
    static void sdk() throws ReflectiveOperationException {
        SdkAuditLoggerForTests.install();
    }

    @BeforeEach
    @AfterEach
    void clean() {
        ThreadContext.clearMap();
        SdkAuditLoggerForTests.LAST_RECORD.clear();
        SdkAuditLoggerForTests.failNextLog = false;
    }

    @Test
    void pingFederatesOwnAuditContextIsExactlyAsItWasAfterOurRecord() {
        ThreadContext.putAll(TOKEN_REQUEST);

        LoggingUtilAuditWriter.INSTANCE.write(revoked(), "OpenID Federation", "203.0.113.9");

        assertEquals(TOKEN_REQUEST, ThreadContext.getImmutableContext(),
                "every column PingFederate had set for its own line is back, and nothing of ours is left");
    }

    @Test
    void ourRecordCarriesItsOwnColumnsAndTheRequestsCorrelationIdsButNoneOfPingFederatesColumns() {
        ThreadContext.putAll(TOKEN_REQUEST);

        LoggingUtilAuditWriter.INSTANCE.write(revoked(), "OpenID Federation", "203.0.113.9");

        Map<String, String> record = SdkAuditLoggerForTests.LAST_RECORD;
        assertEquals("federation.hosted_entity.revoked", record.get("event"));
        assertEquals("failure", record.get("status"));
        assertEquals("203.0.113.9", record.get("ip"));
        assertEquals("OpenID Federation", record.get("protocol"));
        assertEquals("https://pf.example/federation/agents/a", record.get("subject"));
        assertEquals("TA", record.get("role"));
        assertEquals("tid:sxuK51AA1JLzKJqXBYKcmz3Eax4", record.get("trackingid"), "our line sits beside PingFederate's");
        assertEquals("vNfglCSjEdXqJn6k29yCj21Fh", record.get("transactionid"));
        assertNull(record.get("connectionid"), "PingFederate's client is not our record's partner");
        assertNull(record.get("granttype"));
        assertNull(record.get("requeststarttime"));
    }

    @Test
    void theSdksCleanupIsWhatStrippedIt() {
        // Why the writer no longer calls it: PingFederate's AuditLogger.cleanup removes every audit key on the thread.
        ThreadContext.putAll(TOKEN_REQUEST);

        LoggingUtil.cleanup();

        for (String column : new String[] {"event", "subject", "ip", "connectionid", "protocol", "host", "status", "role"}) {
            assertFalse(ThreadContext.containsKey(column), column + " is gone after LoggingUtil.cleanup()");
        }
        assertTrue(ThreadContext.containsKey("trackingid"));
    }

    @Test
    void aRecordThatFailsToWriteStillPutsTheContextBack() {
        ThreadContext.putAll(TOKEN_REQUEST);
        SdkAuditLoggerForTests.failNextLog = true;

        assertThrows(IllegalStateException.class,
                () -> LoggingUtilAuditWriter.INSTANCE.write(revoked(), "OpenID Federation", "203.0.113.9"));

        assertEquals(TOKEN_REQUEST, ThreadContext.getImmutableContext());
    }

    @Test
    void offARequestThreadNothingIsLeftBehind() {
        LoggingUtilAuditWriter.INSTANCE.write(Event.builder("federation", "federation.key.retired").audit().build(),
                "OpenID Federation", null);

        assertEquals("federation.key.retired", SdkAuditLoggerForTests.LAST_RECORD.get("event"));
        assertNull(SdkAuditLoggerForTests.LAST_RECORD.get("ip"));
        assertTrue(ThreadContext.isEmpty(), "as the SDK's cleanup left it");
    }
}
