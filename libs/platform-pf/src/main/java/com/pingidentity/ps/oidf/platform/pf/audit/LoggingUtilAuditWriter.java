/*
 * One audit record through PingFederate's LoggingUtil.
 */
package com.pingidentity.ps.oidf.platform.pf.audit;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.sdk.logging.LoggingUtil;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.ThreadContext;

/**
 * Writes through {@link LoggingUtil}: PingFederate's audit hook for extensions. Its {@code init} fills what
 * PingFederate fills for its own records, {@code host} among them, and the setters fill the rest of the columns.
 *
 * <p><b>PingFederate's own audit context is saved and put back, never cleaned up</b> (plan item H-FED-7, finding
 * F-0049). The audit columns are keys in the log4j {@code ThreadContext}, and a write can happen in the middle of one
 * of PingFederate's own requests - an OGNL issuance criterion runs inside the token endpoint. {@code LoggingUtil.cleanup}
 * removes every audit key ({@code AuditLogger.cleanup} in 13.1.3 walks all of {@code AuditLogger.MDC_KEY}), so a
 * {@code cleanup} after our record emptied the columns PingFederate had already set for its own. Seen on the rig on
 * 2026-10-01 (PingFederate 13.1.3, a client-credentials token request with one of our events written from the
 * access-token mapping's criterion): PingFederate's {@code success} line for that request lost {@code event},
 * {@code subject}, {@code ip}, {@code connectionid}, {@code protocol}, {@code host} and its response time. So the
 * writer copies the whole {@code ThreadContext} before it writes, starts the record from the request's correlation
 * keys alone ({@link #KEPT}, so no column of PingFederate's is taken for ours), and afterwards puts back exactly what
 * was there. Off a request thread there is nothing of PingFederate's to keep, and putting back what was there leaves
 * the thread as {@code cleanup} did.
 */
final class LoggingUtilAuditWriter implements PfAuditSink.AuditWriter {
    static final LoggingUtilAuditWriter INSTANCE = new LoggingUtilAuditWriter();

    /** The ThreadContext key of the audit log's {@code protocol} column, as PingFederate's own AuditLogger writes it. */
    static final String PROTOCOL_KEY = "protocol";

    /**
     * The keys our record keeps from the thread: the request's correlation ids, which PingFederate's log patterns print
     * ({@code trackingid}, {@code transactionid}) and its request filter sets ({@code httprequestid}), so that our line
     * sits beside PingFederate's own for the same request. Every other key is PingFederate's column, not ours.
     */
    static final Set<String> KEPT = Set.of("trackingid", "transactionid", "httprequestid");

    private LoggingUtilAuditWriter() {
    }

    @Override
    public void write(Event event, String protocol, String remoteAddress) {
        PfAuditSink.AuditRecord record = PfAuditSink.record(event, protocol, remoteAddress);
        Map<String, String> saved = ThreadContext.getContext();
        try {
            startClean(saved);
            LoggingUtil.init();
            LoggingUtil.setEvent(record.event());
            LoggingUtil.setStatus(record.failure() ? LoggingUtil.FAILURE : LoggingUtil.SUCCESS);
            if (record.userName() != null) {
                LoggingUtil.setUserName(record.userName());
            }
            if (record.partnerId() != null) {
                LoggingUtil.setPartnerId(record.partnerId());
            }
            // Not LoggingUtil.setProtocol: in PingFederate 13.0 and 13.1 the SDK implements it by writing the ip
            // column. This is the key PingFederate's own AuditLogger.setProtocol writes.
            ThreadContext.put(PROTOCOL_KEY, record.protocol());
            if (record.role() != null) {
                LoggingUtil.setRole(record.role());
            }
            if (record.remoteAddress() != null) {
                LoggingUtil.setRemoteAddress(record.remoteAddress());
            }
            if (record.requestJti() != null) {
                LoggingUtil.setRequestJti(record.requestJti());
            }
            LoggingUtil.setDescription(record.description());
            LoggingUtil.log(record.event());
        } finally {
            restore(saved);
        }
    }

    /** Leaves only {@link #KEPT} of {@code saved} on the thread, so the record starts with none of PingFederate's columns. */
    static void startClean(Map<String, String> saved) {
        for (String key : saved.keySet()) {
            if (!KEPT.contains(key)) {
                ThreadContext.remove(key);
            }
        }
    }

    /** Puts the thread's context back to {@code saved}: every key the record set is gone, every key it removed is back. */
    static void restore(Map<String, String> saved) {
        ThreadContext.clearMap();
        if (!saved.isEmpty()) {
            ThreadContext.putAll(saved);
        }
    }
}
