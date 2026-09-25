package com.pingidentity.ps.oidf.pf.testkit;

import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.pf.PfRequestScope;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * PingFederate's sink, installed with an audit writer that keeps every record it is handed instead of writing it: the
 * event and the request scope it was emitted in. What a test reads here is what {@code audit.log} would have been given,
 * {@code ip} column and all.
 *
 * <p>{@link #install()} replaces the process sink for the duration of a test; {@link #close()} resets it, and leaves
 * no request scope behind on the test's thread.
 */
public final class AuditCapture implements AutoCloseable {
    /** One audit record: the event, and the request it was written for - null when there was none. */
    public record Record(FederationEvent event, PfRequestScope.Context request) {
        /** The address the record's {@code ip} column would carry, or null. */
        public String remoteAddress() {
            return this.request == null ? null : this.request.remoteAddress();
        }
    }

    private final List<Record> records = new CopyOnWriteArrayList<>();

    /** Installs a fresh capture as the process sink. */
    public static AuditCapture install() {
        AuditCapture capture = new AuditCapture();
        FederationEvents.reset();
        FederationEvents.configure(new PfAuditEventSink(event -> { }, (event, request) -> capture.records.add(new Record(event, request)), true));
        return capture;
    }

    public List<Record> records() {
        return List.copyOf(this.records);
    }

    /** The single audit record of {@code code}; fails when there is none or more than one. */
    public Record only(String code) {
        List<Record> matching = this.records.stream().filter(r -> r.event().code().equals(code)).toList();
        if (matching.size() != 1) {
            throw new AssertionError("expected exactly one " + code + " audit record, got " + matching.size() + ": "
                    + this.records.stream().map(r -> r.event().code()).toList());
        }
        return matching.get(0);
    }

    @Override
    public void close() {
        FederationEvents.reset();
        PfRequestScope.exit(null);
    }
}
