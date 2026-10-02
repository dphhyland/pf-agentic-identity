/*
 * One socket to Redis, speaking RESP, every read under the command's deadline.
 */
package com.pingidentity.ps.oidf.platform.redis;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * A connection to one Redis server or sentinel. Over TLS the plain socket is connected first and the TLS socket
 * layered on it with the name to verify, so a master a sentinel reports by address can be checked against a name;
 * the handshake runs to completion before anything is written, so a password never travels before the peer is
 * verified. Each read waits at most what is left of the deadline it is given; writes are a command's few bytes and
 * are not timed.
 *
 * <p>Replies: simple and bulk strings are {@link String} (UTF-8), integers {@link Long}, nil {@code null}, arrays
 * {@link List}. An error reply at the top level throws {@link RedisErrorReply}, after the whole reply has been
 * read, so the connection stays aligned and can be reused; one inside an array is returned in place as a
 * {@link RedisErrorReply}. A reply larger than the caps below is a protocol failure ({@link IOException}): the
 * server is verified, but a runaway length must not take the heap.
 */
final class RedisConnection implements Closeable {
    static final int MAX_LINE = 64 * 1024;
    static final int MAX_BULK = 64 * 1024 * 1024;
    static final int MAX_ARRAY = 1024 * 1024;

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final byte[] buffer = new byte[8192];
    private int position;
    private int limit;
    private long deadline;
    /** The master generation this connection was opened under; see {@link MasterLocator#generation()}. */
    final long generation;

    private RedisConnection(Socket socket, long generation) throws IOException {
        this.socket = socket;
        this.in = socket.getInputStream();
        this.out = socket.getOutputStream();
        this.generation = generation;
    }

    /**
     * Connects to {@code host:port}, verifying {@code tlsName} over TLS when {@code ssl} is not null.
     *
     * @param deadline a {@link System#nanoTime()} value the connect, the handshake and every read must finish by
     */
    static RedisConnection open(String host, int port, SSLContext ssl, String tlsName, long deadline, long generation)
            throws IOException {
        Socket plain = new Socket();
        Socket socket = plain;
        try {
            plain.connect(new InetSocketAddress(host, port), remainingMillis(deadline));
            if (ssl != null) {
                SSLSocket tls = (SSLSocket) ssl.getSocketFactory().createSocket(plain, tlsName, port, true);
                socket = tls;
                tls.setSSLParameters(RedisTls.sslParametersFor(tls.getSSLParameters(), tlsName));
                tls.setSoTimeout(remainingMillis(deadline));
                // Verified before a byte of AUTH is encoded: a peer whose chain or name does not check out fails
                // here, with nothing of ours sent.
                tls.startHandshake();
            }
            return new RedisConnection(socket, generation);
        } catch (IOException | RuntimeException e) {
            closeQuietly(socket);
            closeQuietly(plain);
            throw e;
        }
    }

    /** Sends one command and reads its reply, both by {@code deadline}. */
    Object roundTrip(long deadline, String... args) throws IOException {
        this.deadline = deadline;
        ByteArrayOutputStream command = new ByteArrayOutputStream();
        command.write(("*" + args.length + "\r\n").getBytes(StandardCharsets.US_ASCII));
        for (String arg : args) {
            byte[] bytes = arg.getBytes(StandardCharsets.UTF_8);
            command.write(("$" + bytes.length + "\r\n").getBytes(StandardCharsets.US_ASCII));
            command.write(bytes);
            command.write('\r');
            command.write('\n');
        }
        this.out.write(command.toByteArray());
        this.out.flush();
        Object reply = this.readReply();
        if (reply instanceof RedisErrorReply) {
            throw (RedisErrorReply) reply;
        }
        return reply;
    }

    private Object readReply() throws IOException {
        int type = this.read();
        if (type == -1) {
            throw new EOFException("Redis connection closed");
        }
        String line = this.readLine();
        switch (type) {
            case '+':
                return line;
            case '-':
                // Server-reported error (bad command, NOAUTH, READONLY, NOSCRIPT, ...): not a transport failure.
                return new RedisErrorReply(line);
            case ':':
                return Long.valueOf(number(line, Long.MIN_VALUE, Long.MAX_VALUE));
            case '$': {
                int length = (int) number(line, -1, MAX_BULK);
                if (length == -1) {
                    return null;
                }
                byte[] data = this.readFully(length);
                this.expect('\r');
                this.expect('\n');
                return new String(data, StandardCharsets.UTF_8);
            }
            case '*': {
                int count = (int) number(line, -1, MAX_ARRAY);
                if (count == -1) {
                    return null;
                }
                List<Object> items = new ArrayList<>(Math.min(count, 1024));
                for (int i = 0; i < count; i++) {
                    items.add(this.readReply());
                }
                return items;
            }
            default:
                throw new IOException("Unexpected RESP reply type: 0x" + Integer.toHexString(type));
        }
    }

    /** A RESP length or integer, within {@code min} and {@code max}; anything else is a protocol failure. */
    static long number(String line, long min, long max) throws IOException {
        long value;
        try {
            value = Long.parseLong(line);
        } catch (NumberFormatException e) {
            throw new IOException("Malformed RESP reply: not a number");
        }
        if (value < min || value > max) {
            throw new IOException("Malformed RESP reply: " + value + " is outside " + min + ".." + max);
        }
        return value;
    }

    private String readLine() throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        while (true) {
            int b = this.read();
            if (b == -1) {
                throw new EOFException("Redis connection closed mid-reply");
            }
            if (b == '\r') {
                this.expect('\n');
                return line.toString(StandardCharsets.UTF_8);
            }
            if (line.size() == MAX_LINE) {
                throw new IOException("Malformed RESP reply: a line longer than " + MAX_LINE + " bytes");
            }
            line.write(b);
        }
    }

    private byte[] readFully(int length) throws IOException {
        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            if (this.position == this.limit && !this.fill()) {
                throw new EOFException("Redis connection closed mid-reply");
            }
            int n = Math.min(length - offset, this.limit - this.position);
            System.arraycopy(this.buffer, this.position, data, offset, n);
            this.position += n;
            offset += n;
        }
        return data;
    }

    private void expect(char c) throws IOException {
        if (this.read() != c) {
            throw new IOException("Malformed RESP reply: expected " + (c == '\r' ? "CR" : "LF"));
        }
    }

    private int read() throws IOException {
        if (this.position == this.limit && !this.fill()) {
            return -1;
        }
        return this.buffer[this.position++] & 0xff;
    }

    /** Reads what the socket has, waiting no longer than the deadline allows; false at end of stream. */
    private boolean fill() throws IOException {
        this.socket.setSoTimeout(remainingMillis(this.deadline));
        int n = this.in.read(this.buffer);
        if (n <= 0) {
            return false;
        }
        this.position = 0;
        this.limit = n;
        return true;
    }

    /** What is left before {@code deadline}, in whole milliseconds and at least 1; none left is a timeout. */
    static int remainingMillis(long deadline) throws SocketTimeoutException {
        long left = deadline - System.nanoTime();
        if (left <= 0L) {
            throw new SocketTimeoutException("Redis command deadline passed");
        }
        return (int) Math.max(1L, Math.min(Integer.MAX_VALUE, TimeUnit.NANOSECONDS.toMillis(left)));
    }

    @Override
    public void close() {
        closeQuietly(this.socket);
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // best-effort cleanup
        }
    }
}
