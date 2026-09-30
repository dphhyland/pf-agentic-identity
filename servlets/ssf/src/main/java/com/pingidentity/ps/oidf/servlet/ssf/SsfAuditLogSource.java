/*
 * SSF event source: a log4j2 appender attached to PingFederate's security-audit loggers.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import com.pingidentity.ps.oidf.ssf.AuditEventMapper;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfEventBridge;
import com.pingidentity.ps.oidf.ssf.SsfEvents;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;
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
 * {@code event}, {@code subject}, {@code status}, {@code transactionid}, and the session correlators. This appender
 * attaches to those loggers <strong>programmatically at SSF boot</strong> — no {@code log4j2.xml} edit — and feeds each
 * record through {@link AuditEventMapper}; mapped events become CAEP/RISC SETs via {@link SsfEventBridge}, each
 * carrying the record's {@code transactionid} as its {@code txn}.
 *
 * <p>This widens coverage beyond the endpoint filters: any session end, password change or account deletion PF audits
 * with a subject signals (the vocabulary is {@link AuditEventMapper#DEFAULTS}). Overlap with
 * {@code LogoutEventFilter} is safe — the bridge suppresses duplicate (type, subject) emissions within a
 * short window.
 *
 * <p><b>Reconfiguration and undeploy</b> (plan item H-SSF-5). PingFederate's {@code log4j2.xml} sets
 * {@code monitorInterval="30"}, and a changed file replaces the whole configuration: new {@link LoggerConfig}s,
 * without this appender. So {@link #attachTo} also listens on the {@link LoggerContext} for
 * {@link LoggerContext#PROPERTY_CONFIG}, which log4j 2.25.4 (PingFederate 13.1.3's) fires from
 * {@code setConfiguration} after the new configuration is started and the old one stopped, and attaches a fresh
 * instance to the new configuration's loggers. The webapp's platform lifecycle detaches it, listener included, when
 * PingFederate undeploys the webapp, so no appender from an unloaded webapp is left in the server's log4j context.
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
        // PingFederate's audit hook for extensions: the OpenID Federation events (registration expired,
        // hosted entity revoked, ...) arrive here. auditEventMap maps none of them by default, so hooking
        // it changes nothing until an operator maps one to a CAEP event.
        "com.pingidentity.sdk.logging.LoggingUtil",
    };
    private static final String APPENDER_NAME = "SsfAuditEventSource";

    /** The {@code trigger} of an attach or detach event. */
    static final String START = "start";
    static final String RECONFIGURE = "reconfigure";
    static final String UNDEPLOY = "undeploy";
    static final String RESTART = "restart";

    /** What the audit source is to the bridge's {@code ssf.set.dropped} events. */
    static final String SOURCE = "audit";

    private static final org.apache.commons.logging.Log LOG =
            org.apache.commons.logging.LogFactory.getLog(SsfAuditLogSource.class);

    private static SsfAuditLogSource attached;
    private static List<LoggerConfig> attachedTo = List.of();
    private static LoggerContext listenedTo;
    private static PropertyChangeListener listener;
    /** The configuration the source is hooked into: log4j also fires PROPERTY_CONFIG for updateLoggers on it. */
    private static volatile Configuration hookedInto;
    private static boolean lifecycleRegistered;

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

    /** A new instance like this one, for a configuration log4j swapped in (an appender belongs to one configuration). */
    private SsfAuditLogSource copy() {
        return new SsfAuditLogSource(this.mapper, this.issuer, this.dispatcher);
    }

    @Override
    public void append(LogEvent event) {
        try {
            ReadOnlyStringMap ctx = event.getContextData();
            if (ctx == null) {
                return;
            }
            this.mapper.map(ctx.getValue("event"), ctx.getValue("status"), ctx.getValue("subject"),
                    ctx.getValue("transactionid")).ifPresent(this.dispatcher);
        } catch (Throwable t) {
            // never disturb PF's audit pipeline; suppress and count on the bridge's own logging
            LOG.debug((Object) ("SSF audit source: event dropped: " + t));
        }
    }

    private void dispatch(AuditEventMapper.Mapped m) {
        SubjectId subject = SubjectId.issSub(this.issuer, m.subject());
        String txn = m.transactionId();
        switch (m.action()) {
            case SESSION_REVOKED -> SsfEventBridge.onSessionRevoked(subject, "PF audit " + m.auditEvent(), txn, SOURCE);
            case SESSION_ESTABLISHED -> SsfEventBridge.onSessionEstablished(subject, txn, SOURCE);
            case CREDENTIAL_CHANGE -> SsfEventBridge.onCredentialChange(subject, m.rule().credentialType(),
                    m.rule().changeType(), txn, SOURCE);
            // RISC 1.0 §2.3's reason is hijacking or bulk-account; an audit record says neither, so none is sent.
            case ACCOUNT_DISABLED -> SsfEventBridge.onAccountDisabled(subject, null, txn, SOURCE);
            case ACCOUNT_ENABLED -> SsfEventBridge.onAccountEnabled(subject, txn, SOURCE);
            case ACCOUNT_PURGED -> SsfEventBridge.onAccountPurged(subject, txn, SOURCE);
        }
    }

    // ─────────────────────────── attachment ───────────────────────────

    /**
     * Attach to PF's audit loggers in the log4j2 context that actually declares them. Idempotent
     * (re-attach replaces the previous instance). Returns the number of loggers hooked (0 = none found,
     * e.g. outside a PF runtime).
     */
    public static synchronized int attach(SsfConfiguration cfg) {
        detach(RESTART);
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

    /**
     * Hook the given appender into every audit logger declared in {@code ctx}, and follow {@code ctx} through a
     * reconfiguration: each new configuration gets a copy of {@code source}.
     */
    static synchronized int attachTo(LoggerContext ctx, SsfAuditLogSource source) {
        return attachTo(ctx, source, START);
    }

    private static synchronized int attachTo(LoggerContext ctx, SsfAuditLogSource source, String trigger) {
        int hooked = hook(ctx, source, trigger);
        if (hooked > 0) {
            follow(ctx, source::copy);
            registerForUndeploy();
        }
        return hooked;
    }

    private static int hook(LoggerContext ctx, SsfAuditLogSource source, String trigger) {
        Configuration conf = ctx.getConfiguration();
        hookedInto = conf; // before updateLoggers, which fires PROPERTY_CONFIG for this same configuration
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
            LOG.info((Object) ("SSF audit source: attached to " + hooked.size() + " PF audit logger(s) (" + trigger
                    + "); mapping " + source.mapper.vocabulary().keySet()));
            SsfEvents.auditAttached(hooked.size(), trigger);
        }
        return hooked.size();
    }

    /** Listens on {@code ctx} for a replaced configuration, and attaches a new instance to it. */
    private static void follow(LoggerContext ctx, Supplier<SsfAuditLogSource> fresh) {
        unfollow();
        PropertyChangeListener l = new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (LoggerContext.PROPERTY_CONFIG.equals(evt.getPropertyName()) && evt.getNewValue() != hookedInto) {
                    reattach(ctx, fresh);
                }
            }
        };
        ctx.addPropertyChangeListener(l);
        listenedTo = ctx;
        listener = l;
    }

    /** log4j replaced {@code ctx}'s configuration: drop the old hooks and hook the new configuration's loggers. */
    static synchronized void reattach(LoggerContext ctx, Supplier<SsfAuditLogSource> fresh) {
        try {
            unhook(RECONFIGURE);
            if (hook(ctx, fresh.get(), RECONFIGURE) == 0) {
                LOG.warn((Object) "SSF audit source: log4j's new configuration declares none of PingFederate's audit"
                        + " loggers; audit-driven events stop until SSF starts again");
            }
        } catch (Throwable t) {
            LOG.warn((Object) ("SSF audit source: could not attach to log4j's new configuration (audit-driven events"
                    + " stop until SSF starts again): " + t));
        }
    }

    private static void unfollow() {
        if (listenedTo != null && listener != null) {
            listenedTo.removePropertyChangeListener(listener);
        }
        listenedTo = null;
        listener = null;
    }

    /** At the webapp's shutdown, platform's lifecycle detaches the source and stops listening, once per loader. */
    private static void registerForUndeploy() {
        if (!lifecycleRegistered) {
            lifecycleRegistered = true;
            Lifecycle.current().register("SSF audit source", SsfAuditLogSource::undeploy);
        }
    }

    /** What the lifecycle runs at the webapp's shutdown: detach, and stop listening for reconfiguration. */
    static void undeploy() {
        detach(UNDEPLOY);
    }

    /** Remove a previously attached instance (re-bootstrap, tests). */
    public static synchronized void detach() {
        detach(RESTART);
    }

    /** Remove the attached instance and stop listening for reconfiguration, for {@code trigger}. */
    static synchronized void detach(String trigger) {
        unfollow();
        unhook(trigger);
    }

    private static void unhook(String trigger) {
        if (attached == null) {
            return;
        }
        for (LoggerConfig lc : attachedTo) {
            lc.removeAppender(APPENDER_NAME);
        }
        attached.stop();
        attached = null;
        attachedTo = List.of();
        SsfEvents.auditDetached(trigger);
    }

    /** How many loggers the source is attached to now (tests, and the rig check). */
    static synchronized int attachedCount() {
        return attached == null ? 0 : attachedTo.size();
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
