/*
 * End-to-end through log4j2: attach to a PF-named audit logger, log with ThreadContext fields,
 * and assert the mapped SSF event pops out — plus the don't-hook-an-ancestor guard.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.ssf.AuditEventMapper;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SsfAuditLogSourceTest {

    private static final String IDP_AUDIT = "org.sourceid.websso.profiles.idp.IdpAuditLogger";

    private final List<AuditEventMapper.Mapped> captured = new CopyOnWriteArrayList<>();

    @AfterEach
    void cleanUp() {
        SsfAuditLogSource.detach();
        ThreadContext.clearAll();
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        ctx.getConfiguration().removeLogger(IDP_AUDIT);
        ctx.updateLoggers();
    }

    private LoggerContext contextWithDeclaredAuditLogger() {
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        // declare the PF audit logger the way PF's log4j2.xml does (named, additivity=false)
        LoggerConfig lc = new LoggerConfig(IDP_AUDIT, Level.INFO, false);
        ctx.getConfiguration().addLogger(IDP_AUDIT, lc);
        ctx.updateLoggers();
        return ctx;
    }

    private void audit(String event, String status, String subject) {
        ThreadContext.put("event", event);
        ThreadContext.put("status", status);
        ThreadContext.put("subject", subject);
        // PF logs the formatted line as the message; all data we consume rides the context
        LogManager.getLogger(IDP_AUDIT).info("audit-line");
        ThreadContext.clearAll();
    }

    @Test
    void auditEventsFlowThroughTheRealLoggerToTheMapper() {
        LoggerContext ctx = contextWithDeclaredAuditLogger();
        int n = SsfAuditLogSource.attachTo(ctx,
                SsfAuditLogSource.forTest(new AuditEventMapper(), "https://op.example.com", captured::add));
        assertEquals(1, n);

        audit("SLO", "success", "bob");                  // maps
        audit("SLO", "failure", "bob");                  // failure -> silent
        audit("OAuth", "success", "client-1");           // unmapped event -> silent
        audit("SLO", "success", "");                     // no subject -> silent

        assertEquals(1, captured.size());
        assertEquals(AuditEventMapper.Action.SESSION_REVOKED, captured.get(0).action());
        assertEquals("bob", captured.get(0).subject());
    }

    @Test
    void neverHooksAnAncestorWhenTheAuditLoggerIsNotDeclared() {
        // no PF audit logger declared in this context: getLoggerConfig() falls back to root — must skip
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        int n = SsfAuditLogSource.attachTo(ctx,
                SsfAuditLogSource.forTest(new AuditEventMapper(), "https://op.example.com", captured::add));
        assertEquals(0, n);
        audit("SLO", "success", "bob");
        assertTrue(captured.isEmpty());
    }

    @Test
    void detachStopsDelivery() {
        LoggerContext ctx = contextWithDeclaredAuditLogger();
        SsfAuditLogSource.attachTo(ctx,
                SsfAuditLogSource.forTest(new AuditEventMapper(), "https://op.example.com", captured::add));
        SsfAuditLogSource.detach();
        ctx.updateLoggers();
        audit("SLO", "success", "bob");
        assertTrue(captured.isEmpty());
    }

    @Test
    void reattachReplacesThePreviousInstanceWithoutDoubleDelivery() {
        LoggerContext ctx = contextWithDeclaredAuditLogger();
        SsfAuditLogSource.attachTo(ctx,
                SsfAuditLogSource.forTest(new AuditEventMapper(), "https://op.example.com", captured::add));
        // second attach (re-bootstrap) must not leave two appenders delivering
        SsfAuditLogSource.detach();
        SsfAuditLogSource.attachTo(ctx,
                SsfAuditLogSource.forTest(new AuditEventMapper(), "https://op.example.com", captured::add));
        audit("SLO", "success", "bob");
        assertEquals(1, captured.size());
    }

    @Test
    void appendNeverThrowsOnMalformedEvents() {
        SsfAuditLogSource src = SsfAuditLogSource.forTest(new AuditEventMapper(), "https://op.example.com",
                m -> { throw new IllegalStateException("dispatcher blew up"); });
        LoggerContext ctx = contextWithDeclaredAuditLogger();
        SsfAuditLogSourceTestSupport.append(src, ctx);   // logs through the logger with a throwing dispatcher
        // reaching here without an exception is the assertion: audit logging must never be disturbed
        assertTrue(true);
    }

    /** Small helper so the throwing-dispatcher case still routes through a real logger. */
    static final class SsfAuditLogSourceTestSupport {
        static void append(SsfAuditLogSource src, LoggerContext ctx) {
            SsfAuditLogSource.attachTo(ctx, src);
            ThreadContext.put("event", "SLO");
            ThreadContext.put("status", "success");
            ThreadContext.put("subject", "bob");
            LogManager.getLogger(IDP_AUDIT).info("audit-line");
            ThreadContext.clearAll();
        }
    }
}
