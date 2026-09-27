/*
 * Events into PingFederate's own logs: server.log always, the security audit log for audit events.
 */
package com.pingidentity.ps.oidf.platform.pf.audit;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.EventCatalogue;
import com.pingidentity.ps.oidf.platform.events.EventCatalogues;
import com.pingidentity.ps.oidf.platform.events.EventSink;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.events.LogSafe;
import com.pingidentity.ps.oidf.platform.events.LoggingSink;
import com.pingidentity.ps.oidf.platform.events.PiiPolicy;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * The PingFederate sink for {@link Event}s (plan item O-1).
 *
 * <p>Every event is written to {@code server.log} by the server-log sink it is given (a {@link LoggingSink}). An
 * event marked {@linkplain Event#audit() audit} is also written to PingFederate's security audit log through the
 * SDK's {@code LoggingUtil} ({@link LoggingUtilAuditWriter}) - the hook PingFederate provides for extensions, whose
 * logger is one of the loggers PingFederate's shipped {@code log4j2.xml} routes to {@code audit.log} (and, when an
 * operator switches it, to the JSON, database or Splunk variants of that log). The record fills PingFederate's
 * own columns: {@code event} (the code), {@code status} ({@code success}/{@code failure}), {@code subject},
 * {@code connectionid} (the partner), {@code protocol} (the event's component's {@code auditProtocol} from its
 * catalogue - {@code OpenID Federation} for federation's, {@link #DEFAULT_PROTOCOL} when the component has no
 * catalogue), {@code role}, {@code ip} (the caller's address, from the supplier this sink is given) and a
 * description that carries the event's reason and fields. PingFederate fills {@code host} itself, with this node's
 * name, as it does for its own records.
 *
 * <p>Before either write the event is admitted by its catalogue ({@link EventCatalogues#admit}: a field its code
 * does not declare is dropped and counted); the audit record is then passed through the {@link PiiPolicy} for
 * {@link PiiPolicy.Destination#AUDIT_LOG}, and the server-log sink applies the policy for server.log.
 *
 * <p>Nothing here can fail a request: an audit write that throws is noted at DEBUG and dropped.
 * {@code OIDF_EVENTS_AUDIT=false} keeps events in {@code server.log} only.
 */
public final class PfAuditSink implements EventSink {
    public static final String AUDIT_ENV = "OIDF_EVENTS_AUDIT";
    public static final String AUDIT_PROP = "oidf.events.audit";
    public static final String MAX_VALUE_LENGTH_ENV = "OIDF_EVENTS_MAX_VALUE_LENGTH";

    /** The audit log's {@code protocol} column for an event whose component has no catalogue. */
    public static final String DEFAULT_PROTOCOL = "OpenID Federation";

    private static final PlatformLog LOG = PlatformLog.get(PfAuditSink.class);

    /** Writes one audit record; the production one is {@link #loggingUtil()}. */
    @FunctionalInterface
    public interface AuditWriter {
        /** Writes {@code event}, whose {@code protocol} column is given, for the caller at {@code remoteAddress} (or none). */
        void write(Event event, String protocol, String remoteAddress);
    }

    private final EventSink serverLog;
    private final AuditWriter auditWriter;
    private final boolean auditEnabled;
    private final Supplier<String> remoteAddress;
    private final Supplier<EventCatalogues> catalogues;
    private final PiiPolicy policy;

    /** With this loader's catalogues and {@link PiiPolicy#DEFAULT}. */
    public PfAuditSink(EventSink serverLog, AuditWriter auditWriter, boolean auditEnabled, Supplier<String> remoteAddress) {
        this(serverLog, auditWriter, auditEnabled, remoteAddress, EventCatalogues::current, PiiPolicy.DEFAULT);
    }

    public PfAuditSink(EventSink serverLog, AuditWriter auditWriter, boolean auditEnabled, Supplier<String> remoteAddress,
                       Supplier<EventCatalogues> catalogues, PiiPolicy policy) {
        this.serverLog = Objects.requireNonNull(serverLog, "serverLog");
        this.auditWriter = Objects.requireNonNull(auditWriter, "auditWriter");
        this.auditEnabled = auditEnabled;
        this.remoteAddress = Objects.requireNonNull(remoteAddress, "remoteAddress");
        this.catalogues = Objects.requireNonNull(catalogues, "catalogues");
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    /** The production audit writer, through PingFederate's {@code LoggingUtil}. */
    public static AuditWriter loggingUtil() {
        return LoggingUtilAuditWriter.INSTANCE;
    }

    /**
     * Installs this sink, over a {@link LoggingSink} and {@link #loggingUtil()}, as this loader's
     * {@linkplain Events event sink}, unless one is installed already; reads {@code OIDF_EVENTS_AUDIT} and
     * {@code OIDF_EVENTS_MAX_VALUE_LENGTH} once. {@code remoteAddress} answers the caller's address on the current
     * thread, or {@code null}.
     */
    public static void install(Supplier<String> remoteAddress) {
        install(System::getenv, System::getProperty, remoteAddress);
    }

    static void install(Function<String, String> env, Function<String, String> props, Supplier<String> remoteAddress) {
        if (Events.isConfigured()) {
            return;
        }
        boolean auditEnabled = configure(env, props);
        Events.configure(new PfAuditSink(new LoggingSink(), loggingUtil(), auditEnabled, remoteAddress));
    }

    /**
     * Reads the two settings: sets {@link LogSafe}'s value cap from {@code OIDF_EVENTS_MAX_VALUE_LENGTH} (the
     * environment only; a value that is not a number is warned about and the cap kept) and answers whether audit
     * is on, from the {@code oidf.events.audit} system property, else {@code OIDF_EVENTS_AUDIT}.
     */
    public static boolean configure(Function<String, String> env, Function<String, String> props) {
        String audit = props.apply(AUDIT_PROP);
        if (audit == null || audit.isBlank()) {
            audit = env.apply(AUDIT_ENV);
        }
        String maxLength = env.apply(MAX_VALUE_LENGTH_ENV);
        if (maxLength != null && !maxLength.isBlank()) {
            try {
                LogSafe.configureMaxValueLength(Integer.parseInt(maxLength.trim()));
            } catch (NumberFormatException e) {
                LOG.warn(MAX_VALUE_LENGTH_ENV + " is not a number; keeping " + LogSafe.maxValueLength());
            }
        }
        return auditSwitch(audit);
    }

    /**
     * {@code OIDF_EVENTS_AUDIT}: on unless it says {@code false}. A value that is neither {@code true} nor
     * {@code false} leaves audit on and says so - a typo must not be what turns security auditing off.
     */
    public static boolean auditSwitch(String value) {
        if (value == null || value.isBlank() || "true".equalsIgnoreCase(value.trim())) {
            return true;
        }
        if ("false".equalsIgnoreCase(value.trim())) {
            return false;
        }
        LOG.warn(AUDIT_ENV + " is neither true nor false; federation events still go to PingFederate's audit log");
        return true;
    }

    @Override
    public void emit(Event event) {
        EventCatalogues known = this.catalogues.get();
        Event admitted = known.admit(event);
        this.serverLog.emit(admitted);
        if (!admitted.audit() || !this.auditEnabled) {
            return;
        }
        try {
            Event written = this.policy.apply(admitted, PiiPolicy.Destination.AUDIT_LOG, known);
            this.auditWriter.write(written, protocolOf(written, known), this.remoteAddress.get());
        } catch (RuntimeException | LinkageError e) {
            // Outside a running PingFederate the SDK's audit service does not exist; inside one, an audit
            // failure is PingFederate's to report. Either way the request the event describes carries on.
            if (LOG.isDebugEnabled()) {
                LOG.debug("audit write skipped for " + LogSafe.value(event.code()) + ": " + e.getClass().getSimpleName());
            }
        }
    }

    public boolean auditEnabled() {
        return this.auditEnabled;
    }

    /** The audit log's {@code protocol} column for {@code event}: its component's, else {@link #DEFAULT_PROTOCOL}. */
    public static String protocolOf(Event event, EventCatalogues catalogues) {
        return catalogues.component(event.component()).map(EventCatalogue::auditProtocol).orElse(DEFAULT_PROTOCOL);
    }

    /** The audit description: the event line without its leading {@code event=} and {@code outcome=}. */
    public static String auditDescription(Event event) {
        String line = LoggingSink.format(event);
        int cut = line.indexOf(" outcome=");
        if (cut < 0) {
            return line;
        }
        int next = line.indexOf(' ', cut + 1);
        return next < 0 ? "" : line.substring(next + 1);
    }

    /**
     * The columns of one audit record, as {@link LoggingUtilAuditWriter} writes them. The subject, partner, address
     * and request {@code jti} go through {@link LogSafe}; the code and the role are the code's own constants.
     */
    public record AuditRecord(String event, boolean failure, String userName, String partnerId, String protocol,
                              String role, String remoteAddress, String requestJti, String description) {
    }

    /** The record {@code event} is written as. */
    public static AuditRecord record(Event event, String protocol, String remoteAddress) {
        return new AuditRecord(event.code(), event.isFailure(), LogSafe.value(event.subject()),
                LogSafe.value(event.partner()), protocol, event.role(), LogSafe.value(remoteAddress),
                LogSafe.value(event.requestJti()), auditDescription(event));
    }
}
