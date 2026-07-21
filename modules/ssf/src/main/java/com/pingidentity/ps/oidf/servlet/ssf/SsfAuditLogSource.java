/*
 * SSF event source: a log4j2 appender attached to PingFederate's security-audit loggers.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.AuditEventMapper;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfEventBridge;
import com.pingidentity.ps.oidf.ssf.SubjectId;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.util.ReadOnlyStringMap;

/**
 * Consumes PingFederate's <em>native</em> audit events as an SSF signal source. PF writes its security
 * audit stream through five dedicated log4j2 loggers (IdP/SP/AS/STS/client-registration — the ones behind
 * {@code audit.log}), and every audit record carries its fields in the log event's context data:
 * {@code event}, {@code subject}, {@code status}, and the session correlators. This appender attaches to
 * those loggers <strong>programmatically at SSF boot</strong> — no {@code log4j2.xml} edit — and feeds each
 * record through {@link AuditEventMapper}; mapped events become CAEP/RISC SETs via {@link SsfEventBridge}.
 *
 * <p>This widens coverage beyond the endpoint filters: any logout path PF audits (front-channel SLO,
 * admin/API-driven session revocation) signals, not just {@code /idp/init_logout.openid}. Overlap with
 * {@code LogoutEventFilter} is safe — the bridge suppresses duplicate (type, subject) emissions within a
 * short window.
 *
 * <p>Fail-soft in both directions: {@link #append} never throws (a signalling bug must never disturb PF's
 * audit logging), and {@link #attach} catches everything and reports what it could hook. The PF loggers are
 * declared {@code additivity=false}, so attaching to the named {@link LoggerConfig}s is the only correct
 * interception point; if a logger isn't declared in the active context (name falls back to an ancestor
 * config), it is skipped rather than hooking an unrelated logger.
 */
public final class SsfAuditLogSource extends AbstractAppender {

    /** PF's security-audit logger names (see the comments in PF's {@code conf/log4j2.xml}). */
    static final String[] AUDIT_LOGGERS = {
        "org.sourceid.websso.profiles.idp.IdpAuditLogger",
        "org.sourceid.websso.profiles.sp.SpAuditLogger",
        "org.sourceid.websso.profiles.idp.AsAuditLogger",
        "org.sourceid.wstrust.log.STSAuditLogger",
        "org.sourceid.websso.profiles.idp.ClientRegistrationAuditLogger",
    };
    private static final String APPENDER_NAME = "SsfAuditEventSource";

    private static final org.apache.commons.logging.Log LOG =
            org.apache.commons.logging.LogFactory.getLog(SsfAuditLogSource.class);

    private static SsfAuditLogSource attached;
    private static List<LoggerConfig> attachedTo = List.of();

    private final AuditEventMapper mapper;
    private final String issuer;
    private final Consumer<AuditEventMapper.Mapped> dispatcher;

    private SsfAuditLogSource(AuditEventMapper mapper, String issuer,
            Consumer<AuditEventMapper.Mapped> dispatcher) {
        super(APPENDER_NAME, null, null, true, Property.EMPTY_ARRAY);
        this.mapper = mapper;
        this.issuer = issuer;
        this.dispatcher = dispatcher != null ? dispatcher : this::dispatch;
    }

    /** Production wiring: mapper + issuer from config, dispatch into the bridge. */
    static SsfAuditLogSource forConfiguration(SsfConfiguration cfg) {
        return new SsfAuditLogSource(new AuditEventMapper(cfg.auditEventMap()), cfg.issuer(), null);
    }

    /** Test seam: capture mapped events instead of emitting. */
    static SsfAuditLogSource forTest(AuditEventMapper mapper, String issuer,
            Consumer<AuditEventMapper.Mapped> capture) {
        return new SsfAuditLogSource(mapper, issuer, capture);
    }

    @Override
    public void append(LogEvent event) {
        try {
            ReadOnlyStringMap ctx = event.getContextData();
            if (ctx == null) {
                return;
            }
            this.mapper.map(ctx.getValue("event"), ctx.getValue("status"), ctx.getValue("subject"))
                    .ifPresent(this.dispatcher);
        } catch (Throwable t) {
            // never disturb PF's audit pipeline; suppress and count on the bridge's own logging
            LOG.debug((Object) ("SSF audit source: event dropped: " + t));
        }
    }

    private void dispatch(AuditEventMapper.Mapped m) {
        SubjectId subject = SubjectId.issSub(this.issuer, m.subject());
        String reason = "PF audit " + m.auditEvent();
        switch (m.action()) {
            case SESSION_REVOKED -> SsfEventBridge.onSessionRevoked(subject, reason);
            case CREDENTIAL_CHANGE -> SsfEventBridge.onCredentialChange(subject, "credential", "update");
            case ACCOUNT_DISABLED -> SsfEventBridge.onAccountDisabled(subject, reason);
            case ACCOUNT_ENABLED -> SsfEventBridge.onAccountEnabled(subject);
        }
    }

    // ─────────────────────────── attachment ───────────────────────────

    /**
     * Attach to PF's audit loggers in the log4j2 context that actually declares them. Idempotent
     * (re-attach replaces the previous instance). Returns the number of loggers hooked (0 = none found,
     * e.g. outside a PF runtime).
     */
    public static synchronized int attach(SsfConfiguration cfg) {
        detach();
        try {
            LoggerContext ctx = findAuditContext();
            if (ctx == null) {
                LOG.info((Object) "SSF audit source: no log4j2 context declares the PF audit loggers; "
                        + "audit-driven events disabled");
                return 0;
            }
            return attachTo(ctx, forConfiguration(cfg));
        } catch (Throwable t) {
            LOG.warn((Object) ("SSF audit source: attach failed (audit-driven events disabled): " + t));
            return 0;
        }
    }

    /** Hook the given appender into every audit logger declared in {@code ctx}. */
    static synchronized int attachTo(LoggerContext ctx, SsfAuditLogSource source) {
        Configuration conf = ctx.getConfiguration();
        List<LoggerConfig> hooked = new ArrayList<>();
        source.start();
        for (String name : AUDIT_LOGGERS) {
            LoggerConfig lc = conf.getLoggerConfig(name);
            if (!name.equals(lc.getName())) {
                continue; // logger not declared here — don't hook an ancestor (e.g. root)
            }
            lc.addAppender(source, Level.INFO, null);
            hooked.add(lc);
        }
        ctx.updateLoggers();
        if (hooked.isEmpty()) {
            source.stop();
        } else {
            attached = source;
            attachedTo = List.copyOf(hooked);
            LOG.info((Object) ("SSF audit source: attached to " + hooked.size() + " PF audit logger(s); "
                    + "mapping " + source.mapper.vocabulary().keySet()));
        }
        return hooked.size();
    }

    /** Remove a previously attached instance (re-bootstrap, tests). */
    public static synchronized void detach() {
        if (attached == null) {
            return;
        }
        for (LoggerConfig lc : attachedTo) {
            lc.removeAppender(APPENDER_NAME);
        }
        attached.stop();
        attached = null;
        attachedTo = List.of();
    }

    /**
     * The PF audit loggers live in the log4j2 context of the <em>server</em> classloader (log4j-core ships
     * in PF's server lib), while this class loads from the webapp. Walk our classloader chain and pick the
     * first context whose configuration declares one of the audit loggers.
     */
    private static LoggerContext findAuditContext() {
        List<ClassLoader> candidates = new ArrayList<>();
        for (ClassLoader cl = SsfAuditLogSource.class.getClassLoader(); cl != null; cl = cl.getParent()) {
            candidates.add(cl);
        }
        candidates.add(Thread.currentThread().getContextClassLoader());
        for (ClassLoader cl : candidates) {
            if (LogManager.getContext(cl, false) instanceof LoggerContext ctx && declaresAuditLogger(ctx)) {
                return ctx;
            }
        }
        // last resort: the caller-classloader context (covers single-classloader deployments and tests)
        return LogManager.getContext(false) instanceof LoggerContext ctx && declaresAuditLogger(ctx)
                ? ctx : null;
    }

    private static boolean declaresAuditLogger(LoggerContext ctx) {
        Configuration conf = ctx.getConfiguration();
        for (String name : AUDIT_LOGGERS) {
            if (name.equals(conf.getLoggerConfig(name).getName())) {
                return true;
            }
        }
        return false;
    }
}
