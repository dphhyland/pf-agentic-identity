/*
 * A socket whose every read waits no longer than what is left of the current deadline.
 */
package com.pingidentity.ps.oidf.platform.http;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
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
 * <p>A read also ends when the reading thread is interrupted, as the JDK client's {@code send} did, so a
 * managed executor's close (C-3) stops a fetch stuck on a silent peer: a blocking socket read ignores
 * {@link Thread#interrupt()}, so no read waits longer than {@value #SLICE_MILLIS} ms at a time, and between waits
 * the thread's interrupt is looked at and the deadline checked. An interrupted read throws
 * {@link InterruptedIOException} and leaves the thread's interrupt set. Connecting is not interruptible: it waits
 * at most the connect deadline.
 *
 * <p>It is made with {@link Proxy#NO_PROXY}: a {@code socksProxyHost} set for the JVM must not route a connection
 * to a checked address through a proxy that resolves or chooses for itself.
 */
final class DeadlineSocket extends Socket {

    /** The longest a single socket read waits before the reading thread's interrupt is looked at again. */
    static final int SLICE_MILLIS = 250;

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

    /**
     * Sets the read timeout to what is left, at most one slice; fails the read at once when nothing is left or the
     * thread has been interrupted.
     */
    void arm() throws IOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException("interrupted while waiting for the "
                    + this.phase.name().toLowerCase(java.util.Locale.ROOT));
        }
        int millis = this.readBy.timeoutMillis();
        if (millis == 0) {
            this.timedOut = true;
            throw new SocketTimeoutException("the " + this.phase.name().toLowerCase(java.util.Locale.ROOT)
                    + " deadline has passed");
        }
        setSoTimeout(Math.min(millis, SLICE_MILLIS));
    }

    /**
     * Whether a read that ran out of its slice has also run out of the deadline; when it has, it is a timeout.
     * Otherwise the read is made again: the socket stays usable after a timed-out read.
     */
    boolean deadlinePassed() {
        if (this.readBy.expired()) {
            this.timedOut = true;
            return true;
        }
        return false;
    }

    private final class DeadlineInputStream extends FilterInputStream {
        DeadlineInputStream(InputStream in) {
            super(in);
        }

        @Override
        public int read() throws IOException {
            while (true) {
                arm();
                try {
                    return super.read();
                } catch (SocketTimeoutException e) {
                    if (deadlinePassed()) {
                        throw e;
                    }
                }
            }
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            while (true) {
                arm();
                try {
                    return super.read(buffer, offset, length);
                } catch (SocketTimeoutException e) {
                    if (deadlinePassed()) {
                        throw e;
                    }
                }
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
