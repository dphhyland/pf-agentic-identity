/*
 * A socket whose every read waits no longer than what is left of the current deadline.
 */
package com.pingidentity.ps.oidf.platform.http;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;

/**
 * The plain socket under every {@link OutboundHttp} exchange, TLS or not. Before each read it sets
 * {@code SO_TIMEOUT} to what is left of the deadline for the phase the exchange is in, so however the peer spaces
 * its bytes - one a second, one a minute - no read outlives the deadline, and the reads together cannot either.
 *
 * <p>It works under TLS because JSSE's layered {@code SSLSocketImpl} reads the socket it wraps through that socket's
 * {@link #getInputStream()} ({@code BaseSSLSocketImpl.getInputStream} returns {@code self.getInputStream()} when
 * layered, and {@code SSLSocketImpl.doneConnect} hands that stream to the record layer; JDK 17 and 21 sources, read
 * 2026-09-28), so the handshake's reads and every record's reads come through here too.
 *
 * <p>It is made with {@link Proxy#NO_PROXY}: a {@code socksProxyHost} set for the JVM must not route a connection
 * to a checked address through a proxy that resolves or chooses for itself.
 */
final class DeadlineSocket extends Socket {

    /** Where an exchange is, for naming a timeout. */
    enum Phase { CONNECT, HEADERS, BODY }

    private volatile Deadline readBy;
    private volatile Phase phase = Phase.CONNECT;
    private volatile boolean timedOut;
    private InputStream in;

    DeadlineSocket(Deadline readBy) {
        super(Proxy.NO_PROXY);
        this.readBy = readBy;
    }

    /** Bounds every later read by {@code deadline}, and names the phase a timeout will be reported in. */
    void readBy(Deadline deadline, Phase next) {
        this.readBy = deadline;
        this.phase = next;
    }

    Phase phase() {
        return this.phase;
    }

    /** Whether a read ran out of time. */
    boolean timedOut() {
        return this.timedOut;
    }

    @Override
    public synchronized InputStream getInputStream() throws IOException {
        if (this.in == null) {
            this.in = new DeadlineInputStream(super.getInputStream());
        }
        return this.in;
    }

    /** Sets the read timeout to what is left, or fails the read at once when nothing is. */
    void arm() throws IOException {
        int millis = this.readBy.timeoutMillis();
        if (millis == 0) {
            this.timedOut = true;
            throw new SocketTimeoutException("the " + this.phase.name().toLowerCase(java.util.Locale.ROOT)
                    + " deadline has passed");
        }
        setSoTimeout(millis);
    }

    private final class DeadlineInputStream extends FilterInputStream {
        DeadlineInputStream(InputStream in) {
            super(in);
        }

        @Override
        public int read() throws IOException {
            arm();
            try {
                return super.read();
            } catch (SocketTimeoutException e) {
                DeadlineSocket.this.timedOut = true;
                throw e;
            }
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            arm();
            try {
                return super.read(buffer, offset, length);
            } catch (SocketTimeoutException e) {
                DeadlineSocket.this.timedOut = true;
                throw e;
            }
        }

        /** Skips by reading, so the skip is bounded like any read (the socket stream's own skip would read unarmed). */
        @Override
        public long skip(long count) throws IOException {
            byte[] discard = new byte[(int) Math.min(Math.max(count, 0L), 8192L)];
            return discard.length == 0 ? 0L : Math.max(read(discard, 0, discard.length), 0);
        }
    }
}
