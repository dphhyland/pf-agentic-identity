/*
 * One audit record through PingFederate's LoggingUtil.
 */
package com.pingidentity.ps.oidf.platform.pf.audit;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.sdk.logging.LoggingUtil;
import org.apache.logging.log4j.ThreadContext;

/**
 * Writes through {@link LoggingUtil}: PingFederate's audit hook for extensions. Its {@code init} fills what
 * PingFederate fills for its own records, {@code host} among them, and its {@code cleanup} empties every audit
 * column again. The calls and their order are the ones {@code PfAuditEventSink} made before O-1 moved them here;
 * whether {@code cleanup} also strips PingFederate's own audit context is finding F-0049 (H-FED-7, Phase 3).
 */
final class LoggingUtilAuditWriter implements PfAuditSink.AuditWriter {
    static final LoggingUtilAuditWriter INSTANCE = new LoggingUtilAuditWriter();

    /** The ThreadContext key of the audit log's {@code protocol} column, as PingFederate's own AuditLogger writes it. */
    static final String PROTOCOL_KEY = "protocol";

    private LoggingUtilAuditWriter() {
    }

    @Override
    public void write(Event event, String protocol, String remoteAddress) {
        PfAuditSink.AuditRecord record = PfAuditSink.record(event, protocol, remoteAddress);
        LoggingUtil.init();
        try {
            LoggingUtil.setEvent(record.event());
            LoggingUtil.setStatus(record.failure() ? LoggingUtil.FAILURE : LoggingUtil.SUCCESS);
            if (record.userName() != null) {
                LoggingUtil.setUserName(record.userName());
            }
            if (record.partnerId() != null) {
                LoggingUtil.setPartnerId(record.partnerId());
            }
            // Not LoggingUtil.setProtocol: in PingFederate 13.0 and 13.1 the SDK implements it by writing the ip
            // column. This is the key PingFederate's own AuditLogger.setProtocol writes, and cleanup empties it.
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
            LoggingUtil.cleanup();
        }
    }
}
