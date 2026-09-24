/*
 * The default event sink: one line per event in the server log.
 */
package com.pingidentity.ps.oidf.federation.event;

import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Writes each event as one line through commons-logging, which PingFederate routes to log4j2 and so to
 * {@code server.log} (where PF's own pattern adds the timestamp and its {@code trackingid}):
 *
 * <pre>event=federation.registration.created outcome=success subject=https://rp.example partner=https://ta.example type=automatic desc="registered from trust chain"</pre>
 *
 * <p>The logger is {@code com.pingidentity.ps.oidf.federation.event.<category>}, so an operator can raise
 * or lower one family ({@code ...event.fetch} is chatty) without touching the rest. A failure that
 * belongs in the audit log is written at WARN, fetches at DEBUG, everything else at INFO. Every value
 * goes through {@link LogSafe}.
 */
public final class LoggingEventSink implements FederationEventSink {
    public static final String LOGGER_PREFIX = "com.pingidentity.ps.oidf.federation.event.";

    @Override
    public void emit(FederationEvent event) {
        try {
            Log log = LogFactory.getLog(LOGGER_PREFIX + event.category());
            if ("fetch".equals(event.category())) {
                if (log.isDebugEnabled()) {
                    log.debug(format(event));
                }
            } else if (event.isFailure() && event.audit()) {
                log.warn(format(event));
            } else if (log.isInfoEnabled()) {
                log.info(format(event));
            }
        } catch (RuntimeException ignored) {
            // Recording an event never fails the request it describes.
        }
    }

    /** The line this sink writes for {@code event}. */
    public static String format(FederationEvent event) {
        StringBuilder line = new StringBuilder(160);
        line.append("event=").append(LogSafe.quoted(event.code()));
        line.append(" outcome=").append(event.outcome().code());
        if (event.reason() != null) {
            line.append(" reason=").append(LogSafe.quoted(event.reason()));
        }
        if (event.subject() != null) {
            line.append(" subject=").append(LogSafe.quoted(event.subject()));
        }
        if (event.partner() != null) {
            line.append(" partner=").append(LogSafe.quoted(event.partner()));
        }
        for (Map.Entry<String, String> field : event.fields().entrySet()) {
            line.append(' ').append(LogSafe.value(field.getKey()).replace(' ', '_').replace('=', '_'))
                    .append('=').append(LogSafe.quoted(field.getValue()));
        }
        if (event.requestJti() != null) {
            line.append(" request_jti=").append(LogSafe.quoted(event.requestJti()));
        }
        if (event.description() != null) {
            line.append(" desc=").append(LogSafe.quoted(event.description()));
        }
        return line.toString();
    }
}
