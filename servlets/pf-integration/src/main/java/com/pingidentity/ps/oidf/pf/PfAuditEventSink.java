/*
 * Federation events into PingFederate's own logs - a delegating shim over platform-pf's PfAuditSink.
 */
package com.pingidentity.ps.oidf.pf;

import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEventSink;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.event.LoggingEventSink;
import com.pingidentity.ps.oidf.platform.events.EventCatalogues;
import com.pingidentity.ps.oidf.platform.pf.audit.PfAuditSink;
import java.util.Objects;
import java.util.function.Function;

/**
 * The PingFederate sink for {@link FederationEvent}s, kept so that every servlet and filter that calls
 * {@link #install()} compiles unchanged. The logic is {@link PfAuditSink}'s, in platform-pf (plan item O-1): every
 * event is written to {@code server.log}; an event marked audit is also written to PingFederate's security audit
 * log through the SDK's {@code LoggingUtil}, with the caller's address from the {@link PfRequestScope} the event was
 * emitted in and the {@code protocol} column its component's catalogue names ({@code OpenID Federation} for the
 * federation events). {@code OIDF_EVENTS_AUDIT=false} keeps events in {@code server.log} only.
 *
 * @deprecated Install {@link PfAuditSink#install(java.util.function.Supplier)} instead. Kept while the servlets still
 *     install this shim (plan item H-FED-10, checked 2026-10-01); removed at 1.0.0.
 */
@Deprecated(since = "0.5.0", forRemoval = true)
@SuppressWarnings("removal")
public final class PfAuditEventSink implements FederationEventSink {
    // Written out rather than taken from PfAuditSink so that ConfigurationDocumentedTest, which reads this module's
    // string literals, still finds the two settings; PfAuditEventSinkTest holds them equal to PfAuditSink's.
    public static final String AUDIT_ENV = "OIDF_EVENTS_AUDIT";
    public static final String AUDIT_PROP = "oidf.events.audit";
    public static final String MAX_VALUE_LENGTH_ENV = "OIDF_EVENTS_MAX_VALUE_LENGTH";
    public static final String PROTOCOL = "OpenID Federation";

    /** Writes one audit record; the production one is {@link LoggingUtilAuditWriter}. */
    @FunctionalInterface
    public interface AuditWriter {
        void write(FederationEvent event, PfRequestScope.Context request);
    }

    private final PfAuditSink delegate;

    public PfAuditEventSink(FederationEventSink serverLog, AuditWriter auditWriter, boolean auditEnabled) {
        Objects.requireNonNull(serverLog, "serverLog");
        Objects.requireNonNull(auditWriter, "auditWriter");
        this.delegate = new PfAuditSink(event -> serverLog.emit(FederationEvent.from(event)),
                (event, protocol, address) -> auditWriter.write(FederationEvent.from(event), PfRequestScope.current()),
                auditEnabled, PfAuditEventSink::remoteAddress);
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
        boolean auditEnabled = PfAuditSink.configure(env, props);
        FederationEvents.configure(new PfAuditEventSink(new LoggingEventSink(), new LoggingUtilAuditWriter(), auditEnabled));
    }

    /** See {@link PfAuditSink#auditSwitch}. */
    static boolean auditSwitch(String value) {
        return PfAuditSink.auditSwitch(value);
    }

    /** The caller's address on this thread, from its request scope, or {@code null}. */
    static String remoteAddress() {
        PfRequestScope.Context request = PfRequestScope.current();
        return request == null ? null : request.remoteAddress();
    }

    @Override
    public void emit(FederationEvent event) {
        this.delegate.emit(event.toEvent());
    }

    public boolean auditEnabled() {
        return this.delegate.auditEnabled();
    }

    /** The audit description: the event line without its leading {@code event=} and {@code outcome=}. */
    static String auditDescription(FederationEvent event) {
        return PfAuditSink.auditDescription(event.toEvent());
    }

    /** Writes through PingFederate's {@code LoggingUtil}, as {@link PfAuditSink#loggingUtil()} does. */
    static final class LoggingUtilAuditWriter implements AuditWriter {
        @Override
        public void write(FederationEvent event, PfRequestScope.Context request) {
            PfAuditSink.loggingUtil().write(event.toEvent(),
                    PfAuditSink.protocolOf(event.toEvent(), EventCatalogues.current()),
                    request == null ? null : request.remoteAddress());
        }
    }
}
