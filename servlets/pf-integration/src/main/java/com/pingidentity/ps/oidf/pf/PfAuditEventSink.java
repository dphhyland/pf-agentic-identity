/*
 * Federation events into PingFederate's own logs: server.log always, audit.log for audit events.
 */
package com.pingidentity.ps.oidf.pf;

import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEventSink;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.event.LogSafe;
import com.pingidentity.ps.oidf.federation.event.LoggingEventSink;
import com.pingidentity.sdk.logging.LoggingUtil;
import java.util.Objects;
import java.util.function.Function;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.logging.log4j.ThreadContext;

/**
 * The PingFederate sink for {@link FederationEvent}s.
 *
 * <p>Every event is written to {@code server.log} by a {@link LoggingEventSink}. An event marked
 * {@linkplain FederationEvent#audit() audit} is also written to PF's security audit log through the SDK's
 * {@link LoggingUtil} - the hook PingFederate provides for extensions, whose logger is one of the loggers
 * PF's shipped {@code log4j2.xml} routes to {@code audit.log} (and, when an operator switches it, to the JSON,
 * database or Splunk variants of that log). The audit record fills PF's own columns: {@code event} (the
 * event code), {@code status} ({@code success}/{@code failure}), {@code subject}, {@code connectionid}
 * (the partner: the trust anchor or attester), {@code protocol} ({@code OpenID Federation}), {@code role},
 * {@code ip} (the caller's address, from the {@link PfRequestScope} the event was emitted in) and a description
 * that carries the event's reason and fields. PingFederate fills {@code host} itself, with this node's name, as it
 * does for its own records.
 *
 * <p>Nothing here can fail a request: an audit write that throws is noted at DEBUG and dropped. Setting
 * {@code OIDF_EVENTS_AUDIT=false} keeps events in {@code server.log} only.
 */
public final class PfAuditEventSink implements FederationEventSink {
    public static final String AUDIT_ENV = "OIDF_EVENTS_AUDIT";
    public static final String AUDIT_PROP = "oidf.events.audit";
    public static final String MAX_VALUE_LENGTH_ENV = "OIDF_EVENTS_MAX_VALUE_LENGTH";
    public static final String PROTOCOL = "OpenID Federation";

    private static final Log LOGGER = LogFactory.getLog(PfAuditEventSink.class);

    /** Writes one audit record; the production one is {@link LoggingUtilAuditWriter}. */
    @FunctionalInterface
    public interface AuditWriter {
        void write(FederationEvent event, PfRequestScope.Context request);
    }

    private final FederationEventSink serverLog;
    private final AuditWriter auditWriter;
    private final boolean auditEnabled;

    public PfAuditEventSink(FederationEventSink serverLog, AuditWriter auditWriter, boolean auditEnabled) {
        this.serverLog = Objects.requireNonNull(serverLog, "serverLog");
        this.auditWriter = Objects.requireNonNull(auditWriter, "auditWriter");
        this.auditEnabled = auditEnabled;
    }

    /**
     * Installs the PF sink for this classloader if nothing has been installed yet. Called from the {@code init} of
     * every servlet and filter that emits events and from the OGNL helpers' static initialiser; the first call wins.
     */
    public static void install() {
        install(System::getenv, System::getProperty);
    }

    static void install(Function<String, String> env, Function<String, String> props) {
        if (FederationEvents.isConfigured()) {
            return;
        }
        String audit = props.apply(AUDIT_PROP);
        if (audit == null || audit.isBlank()) {
            audit = env.apply(AUDIT_ENV);
        }
        String maxLength = env.apply(MAX_VALUE_LENGTH_ENV);
        if (maxLength != null && !maxLength.isBlank()) {
            try {
                LogSafe.configureMaxValueLength(Integer.parseInt(maxLength.trim()));
            } catch (NumberFormatException e) {
                LOGGER.warn(MAX_VALUE_LENGTH_ENV + " is not a number; keeping " + LogSafe.maxValueLength());
            }
        }
        boolean auditEnabled = auditSwitch(audit);
        FederationEvents.configure(new PfAuditEventSink(new LoggingEventSink(), new LoggingUtilAuditWriter(), auditEnabled));
    }

    /**
     * {@code OIDF_EVENTS_AUDIT}: on unless it says {@code false}. A value that is neither {@code true} nor {@code false}
     * leaves audit on and says so - a typo must not be what turns security auditing off.
     */
    static boolean auditSwitch(String value) {
        if (value == null || value.isBlank() || "true".equalsIgnoreCase(value.trim())) {
            return true;
        }
        if ("false".equalsIgnoreCase(value.trim())) {
            return false;
        }
        LOGGER.warn(AUDIT_ENV + " is neither true nor false; federation events still go to PingFederate's audit log");
        return true;
    }

    @Override
    public void emit(FederationEvent event) {
        this.serverLog.emit(event);
        if (!event.audit() || !this.auditEnabled) {
            return;
        }
        try {
            this.auditWriter.write(event, PfRequestScope.current());
        } catch (RuntimeException | LinkageError e) {
            // Outside a running PingFederate the SDK's audit service does not exist; inside one, an audit
            // failure is PF's to report. Either way the request the event describes carries on.
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("audit write skipped for " + event.code() + ": " + e.getClass().getSimpleName());
            }
        }
    }

    public boolean auditEnabled() {
        return this.auditEnabled;
    }

    /** The audit description: the event line without its leading {@code event=} and {@code outcome=}. */
    static String auditDescription(FederationEvent event) {
        String line = LoggingEventSink.format(event);
        int cut = line.indexOf(" outcome=");
        if (cut < 0) {
            return line;
        }
        int next = line.indexOf(' ', cut + 1);
        return next < 0 ? "" : line.substring(next + 1);
    }

    /**
     * Writes through {@link LoggingUtil}: PingFederate's audit hook for extensions. Its {@code init} fills what PF fills
     * for its own records, {@code host} among them, and its {@code cleanup} empties every audit column again.
     */
    static final class LoggingUtilAuditWriter implements AuditWriter {
        /** The ThreadContext key of the audit log's {@code protocol} column, as PF's own AuditLogger writes it. */
        private static final String PROTOCOL_KEY = "protocol";

        @Override
        public void write(FederationEvent event, PfRequestScope.Context request) {
            LoggingUtil.init();
            try {
                LoggingUtil.setEvent(event.code());
                LoggingUtil.setStatus(event.isFailure() ? LoggingUtil.FAILURE : LoggingUtil.SUCCESS);
                if (event.subject() != null) {
                    LoggingUtil.setUserName(LogSafe.value(event.subject()));
                }
                if (event.partner() != null) {
                    LoggingUtil.setPartnerId(LogSafe.value(event.partner()));
                }
                // Not LoggingUtil.setProtocol: in PingFederate 13.0 and 13.1 the SDK implements it by writing the ip
                // column. This is the key PF's own AuditLogger.setProtocol writes, and cleanup empties it.
                ThreadContext.put(PROTOCOL_KEY, PROTOCOL);
                if (event.role() != null) {
                    LoggingUtil.setRole(event.role());
                }
                if (request != null && request.remoteAddress() != null) {
                    LoggingUtil.setRemoteAddress(LogSafe.value(request.remoteAddress()));
                }
                if (event.requestJti() != null) {
                    LoggingUtil.setRequestJti(LogSafe.value(event.requestJti()));
                }
                LoggingUtil.setDescription(auditDescription(event));
                LoggingUtil.log(event.code());
            } finally {
                LoggingUtil.cleanup();
            }
        }
    }
}
