/*
 * H-SSF-5: the audit source follows log4j through a reconfiguration and leaves at undeploy; each record's transactionid
 * is its SETs' txn; what it dispatches reaches the bridge as the audit source.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.ssf.AuditEventMapper;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfSupportTestAccess;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfAuditLogSourceLifecycleTest {

    private static final String IDP_AUDIT = "org.sourceid.websso.profiles.idp.IdpAuditLogger";
    private static final String AS_AUDIT = "org.sourceid.websso.profiles.idp.AsAuditLogger";

    private final List<AuditEventMapper.Mapped> captured = new CopyOnWriteArrayList<>();
    private final List<Event> events = new CopyOnWriteArrayList<>();
    private LoggerContext ctx;

    @BeforeEach
    void setUp() {
        Events.reset();
        Events.configure(this.events::add);
        SsfSupportTestAccess.reset();
        this.ctx = (LoggerContext) LogManager.getContext(false);
        LoggerConfig lc = new LoggerConfig(IDP_AUDIT, Level.INFO, false);
        this.ctx.getConfiguration().addLogger(IDP_AUDIT, lc);
        this.ctx.updateLoggers();
    }

    @AfterEach
    void tearDown() {
        SsfAuditLogSource.detach();
        ThreadContext.clearAll();
        this.ctx.reconfigure(); // back to the test class path's own configuration
        Events.reset();
        SsfSupportTestAccess.reset();
    }

    /** A configuration like PingFederate's log4j2.xml after an edit: the audit loggers declared, additivity off. */
    private static Configuration pfLikeConfiguration(String... loggers) {
        ConfigurationBuilder<BuiltConfiguration> b = ConfigurationBuilderFactory.newConfigurationBuilder();
        b.setConfigurationName("pf-after-edit");
        for (String logger : loggers) {
            b.add(b.newLogger(logger, Level.INFO).addAttribute("additivity", false));
        }
        b.add(b.newRootLogger(Level.WARN));
        return b.build(false);
    }

    private void audit(String logger, String event, String subject, String transactionId) {
        ThreadContext.put("event", event);
        ThreadContext.put("status", "success");
        ThreadContext.put("subject", subject);
        if (transactionId != null) {
            ThreadContext.put("transactionid", transactionId);
        }
        LogManager.getLogger(logger).info("audit-line");
        ThreadContext.clearAll();
    }

    private List<String> auditEvents() {
        return this.events.stream().filter(e -> e.code().startsWith("ssf.audit.source."))
                .map(e -> e.code() + "/" + e.fields().get("trigger") + (e.fields().containsKey("loggers") ? "/" + e.fields().get("loggers") : ""))
                .toList();
    }

    /**
     * PingFederate's log4j2.xml has monitorInterval="30": an edited file replaces the configuration, and the replacement's
     * loggers have no appender of ours. log4j 2.25.4, PingFederate 13.1.3's, fires LoggerContext.PROPERTY_CONFIG from
     * setConfiguration after the swap, and the source attaches to the new loggers.
     */
    @Test
    void theSourceFollowsLog4jThroughAReconfiguration() {
        assertEquals(1, SsfAuditLogSource.attachTo(this.ctx,
                SsfAuditLogSource.forTest(new AuditEventMapper(), "https://op.example.com", this.captured::add)));
        audit(IDP_AUDIT, "SRI_REVOKED", "before", "tx-1");
        assertEquals(1, this.captured.size());

        Configuration before = this.ctx.getConfiguration();
        this.ctx.reconfigure(pfLikeConfiguration(IDP_AUDIT, AS_AUDIT));
        assertNotSame(before, this.ctx.getConfiguration());
        assertEquals(2, SsfAuditLogSource.attachedCount(), "attached to the new configuration's two audit loggers");

        audit(IDP_AUDIT, "SRI_REVOKED", "after", "tx-2");
        audit(AS_AUDIT, "SLO", "as-after", null);
        assertEquals(List.of("before", "after", "as-after"), this.captured.stream().map(AuditEventMapper.Mapped::subject).toList(),
                "still delivering, once each, after the reconfiguration");
        assertEquals(List.of("ssf.audit.source.attached/start/1", "ssf.audit.source.detached/reconfigure",
                "ssf.audit.source.attached/reconfigure/2"), auditEvents());
    }

    @Test
    void aNewConfigurationWithoutTheAuditLoggersLeavesItDetached() {
        SsfAuditLogSource.attachTo(this.ctx, SsfAuditLogSource.forTest(new AuditEventMapper(), "https://op.example.com", this.captured::add));
        this.ctx.reconfigure(pfLikeConfiguration("some.other.Logger"));
        assertEquals(0, SsfAuditLogSource.attachedCount());
        audit(IDP_AUDIT, "SRI_REVOKED", "bob", null);
        assertTrue(this.captured.isEmpty());
    }

    /** At undeploy platform's lifecycle detaches the source and stops listening: a later reconfigure attaches nothing. */
    @Test
    void undeployDetachesAndStopsListening() {
        SsfAuditLogSource.attachTo(this.ctx, SsfAuditLogSource.forTest(new AuditEventMapper(), "https://op.example.com", this.captured::add));
        SsfAuditLogSource.undeploy();
        assertEquals(0, SsfAuditLogSource.attachedCount());
        audit(IDP_AUDIT, "SRI_REVOKED", "bob", null);
        this.ctx.reconfigure(pfLikeConfiguration(IDP_AUDIT));
        assertEquals(0, SsfAuditLogSource.attachedCount(), "no listener left behind");
        audit(IDP_AUDIT, "SRI_REVOKED", "bob", null);
        assertTrue(this.captured.isEmpty());
        assertEquals(List.of("ssf.audit.source.attached/start/1", "ssf.audit.source.detached/undeploy"), auditEvents());
        SsfAuditLogSource.undeploy(); // twice is harmless
    }

    @Test
    void aReconfigurationThatFailsToAttachIsLoggedNotThrown() {
        SsfAuditLogSource.reattach(this.ctx, () -> {
            throw new IllegalStateException("cannot build");
        });
        assertEquals(0, SsfAuditLogSource.attachedCount());
    }

    /** SSF 1.0 §4.1.9: PingFederate's transactionid is unique to the audited event, so it is the txn its SETs carry. */
    @Test
    void theRecordsTransactionIdIsCarried() {
        SsfAuditLogSource.attachTo(this.ctx, SsfAuditLogSource.forTest(new AuditEventMapper(), "https://op.example.com", this.captured::add));
        audit(IDP_AUDIT, "PWD_CHANGE", "bob", "YN862WqxEBANB8BxZkBgxSwlv");
        assertEquals("YN862WqxEBANB8BxZkBgxSwlv", this.captured.get(0).transactionId());
        assertEquals("password", this.captured.get(0).rule().credentialType());
    }

    /** The production dispatch hands every action to the bridge as the audit source (not started here: counted, not sent). */
    @Test
    void theProductionDispatchReachesTheBridgeAsTheAuditSource() {
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .auditEventMap("D=account-disabled,E=account-enabled,U=credential-change").build();
        SsfAuditLogSource.attachTo(this.ctx, SsfAuditLogSource.forConfiguration(cfg));
        for (String event : List.of("SLO", "AUTHN_SESSION_CREATED", "PWD_CHANGE", "ACCOUNT_DELETE", "D", "E", "U")) {
            audit(IDP_AUDIT, event, "subject-" + event, "tx-" + event);
        }
        List<String> dropped = this.events.stream().filter(e -> "ssf.set.dropped".equals(e.code()))
                .map(e -> e.fields().get("event_type") + "/" + e.reason() + "/" + e.fields().get("source")).toList();
        assertEquals(List.of("session-revoked/not_started/audit", "session-established/not_started/audit",
                "credential-change/not_started/audit", "account-purged/not_started/audit", "account-disabled/not_started/audit",
                "account-enabled/not_started/audit", "credential-change/credential_type/audit"), dropped);
    }

    @Test
    void attachFromTheConfigurationFindsTheContextThatDeclaresTheLoggers() {
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        assertEquals(1, SsfAuditLogSource.attach(cfg));
        assertEquals(1, SsfAuditLogSource.attach(cfg), "attaching again replaces the first");
        assertEquals(1, SsfAuditLogSource.attachedCount());
    }
}
