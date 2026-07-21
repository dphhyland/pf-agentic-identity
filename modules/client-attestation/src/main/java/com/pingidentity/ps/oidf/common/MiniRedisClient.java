/*
 * Minimal RESP (Redis) client — deliberately dependency-free.
 */
package com.pingidentity.ps.oidf.common;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLSocketFactory;

/**
 * Tiny Redis client speaking just enough RESP for the attestation stores ({@code AUTH}, {@code SELECT},
 * {@code SET}, {@code DEL}, {@code PING}). Written in-module so the WAR stays free of third-party Redis
 * client jars (this project builds offline against local distro jars).
 *
 * <p>Accepts {@code redis://[user[:password]@]host[:port][/db]} and {@code rediss://} (TLS) URLs — the
 * shape Railway and most managed Redis providers export as {@code REDIS_URL}. Connections are pooled
 * (small bounded pool) and re-established transparently; a command that fails on a pooled connection is
 * retried once on a fresh one.
 *
 * <p>Reply mapping: simple strings and bulk strings → {@link String}, integers → {@link Long},
 * nil → {@code null}, arrays → {@link List}. A Redis {@code -ERR} reply throws
 * {@link IllegalStateException} (not retried); transport failures throw {@link IOException}.
 */
final class MiniRedisClient implements Closeable {
    private static final int TIMEOUT_MS = 3000;
    private static final int MAX_POOLED = 4;

    private final String host;
    private final int port;
    private final boolean tls;
    private final String username;
    private final String password;
    private final int db;
    private final ArrayDeque<Conn> pool = new ArrayDeque<>();
    private volatile boolean closed;

    MiniRedisClient(String url) {
        URI uri = URI.create(url.trim());
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        if (!scheme.equals("redis") && !scheme.equals("rediss")) {
            throw new IllegalArgumentException("Unsupported Redis URL scheme: " + uri.getScheme());
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("Redis URL has no host: " + url);
        }
        this.tls = scheme.equals("rediss");
        this.host = uri.getHost();
        this.port = uri.getPort() != -1 ? uri.getPort() : 6379;
        String userInfo = uri.getUserInfo();
        if (userInfo == null || userInfo.isEmpty()) {
            this.username = null;
            this.password = null;
        } else if (userInfo.indexOf(':') >= 0) {
            int i = userInfo.indexOf(':');
            String user = urlDecode(userInfo.substring(0, i));
            this.username = user.isEmpty() ? null : user;
            this.password = urlDecode(userInfo.substring(i + 1));
        } else {
            // Bare userinfo: treat as password (redis://password@host is a common shorthand).
            this.username = null;
            this.password = urlDecode(userInfo);
        }
        String path = uri.getPath();
        int parsedDb = 0;
        if (path != null && path.length() > 1) {
            try {
                parsedDb = Integer.parseInt(path.substring(1));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Redis URL has a non-numeric db path: " + path);
            }
        }
        this.db = parsedDb;
    }

    /** Executes one command and returns the decoded reply (see class doc for the mapping). */
    Object call(String... args) throws IOException {
        Conn conn = this.borrow();
        boolean pooled = conn.pooled;
        try {
            Object reply = conn.roundTrip(args);
            this.give(conn);
            return reply;
        } catch (IllegalStateException e) {
            // -ERR reply: the connection is still protocol-aligned, keep it.
            this.give(conn);
            throw e;
        } catch (IOException e) {
            conn.closeQuietly();
            if (!pooled) {
                throw e;
            }
        }
        // The pooled connection may simply have gone stale (server-side idle timeout); retry once fresh.
        Conn fresh = this.connect();
        try {
            Object reply = fresh.roundTrip(args);
            this.give(fresh);
            return reply;
        } catch (IOException e) {
            fresh.closeQuietly();
            throw e;
        }
    }

    private Conn borrow() throws IOException {
        synchronized (this.pool) {
            Conn conn = this.pool.pollFirst();
            if (conn != null) {
                conn.pooled = true;
                return conn;
            }
        }
        return this.connect();
    }

    private void give(Conn conn) {
        synchronized (this.pool) {
            if (!this.closed && this.pool.size() < MAX_POOLED) {
                this.pool.addFirst(conn);
                return;
            }
        }
        conn.closeQuietly();
    }

    private Conn connect() throws IOException {
        Socket socket = this.tls ? SSLSocketFactory.getDefault().createSocket() : new Socket();
        try {
            socket.connect(new InetSocketAddress(this.host, this.port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            Conn conn = new Conn(socket);
            if (this.password != null && !this.password.isEmpty()) {
                if (this.username != null) {
                    conn.roundTrip(new String[]{"AUTH", this.username, this.password});
                } else {
                    conn.roundTrip(new String[]{"AUTH", this.password});
                }
            }
            if (this.db > 0) {
                conn.roundTrip(new String[]{"SELECT", Integer.toString(this.db)});
            }
            return conn;
        } catch (IOException | RuntimeException e) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // already failing; surface the original error
            }
            throw e;
        }
    }

    @Override
    public void close() {
        this.closed = true;
        synchronized (this.pool) {
            Conn conn;
            while ((conn = this.pool.pollFirst()) != null) {
                conn.closeQuietly();
            }
        }
    }

    private static String urlDecode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private static final class Conn {
        private final Socket socket;
        private final InputStream in;
        private final OutputStream out;
        boolean pooled;

        Conn(Socket socket) throws IOException {
            this.socket = socket;
            this.in = new BufferedInputStream(socket.getInputStream());
            this.out = new BufferedOutputStream(socket.getOutputStream());
        }

        Object roundTrip(String[] args) throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            buf.write(("*" + args.length + "\r\n").getBytes(StandardCharsets.US_ASCII));
            for (String arg : args) {
                byte[] bytes = arg.getBytes(StandardCharsets.UTF_8);
                buf.write(("$" + bytes.length + "\r\n").getBytes(StandardCharsets.US_ASCII));
                buf.write(bytes);
                buf.write('\r');
                buf.write('\n');
            }
            this.out.write(buf.toByteArray());
            this.out.flush();
            return this.readReply();
        }

        private Object readReply() throws IOException {
            int type = this.in.read();
            if (type == -1) {
                throw new EOFException("Redis connection closed");
            }
            String line = this.readLine();
            switch (type) {
                case '+':
                    return line;
                case '-':
                    // Server-reported error (bad command, NOAUTH, ...): not a transport failure, do not retry.
                    throw new IllegalStateException("Redis error reply: " + line);
                case ':':
                    return Long.valueOf(line);
                case '$': {
                    int len = Integer.parseInt(line);
                    if (len == -1) {
                        return null;
                    }
                    byte[] data = this.readFully(len);
                    this.expectCrlf();
                    return new String(data, StandardCharsets.UTF_8);
                }
                case '*': {
                    int count = Integer.parseInt(line);
                    if (count == -1) {
                        return null;
                    }
                    List<Object> items = new ArrayList<>(count);
                    for (int i = 0; i < count; i++) {
                        items.add(this.readReply());
                    }
                    return items;
                }
                default:
                    throw new IOException("Unexpected RESP reply type: 0x" + Integer.toHexString(type));
            }
        }

        private String readLine() throws IOException {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            while (true) {
                int b = this.in.read();
                if (b == -1) {
                    throw new EOFException("Redis connection closed mid-reply");
                }
                if (b == '\r') {
                    this.expectLf();
                    return new String(line.toByteArray(), StandardCharsets.UTF_8);
                }
                line.write(b);
            }
        }

        private byte[] readFully(int len) throws IOException {
            byte[] data = new byte[len];
            int off = 0;
            while (off < len) {
                int n = this.in.read(data, off, len - off);
                if (n == -1) {
                    throw new EOFException("Redis connection closed mid-reply");
                }
                off += n;
            }
            return data;
        }

        private void expectCrlf() throws IOException {
            if (this.in.read() != '\r') {
                throw new IOException("Malformed RESP reply: expected CR");
            }
            this.expectLf();
        }

        private void expectLf() throws IOException {
            if (this.in.read() != '\n') {
                throw new IOException("Malformed RESP reply: expected LF");
            }
        }

        void closeQuietly() {
            try {
                this.socket.close();
            } catch (IOException ignored) {
                // best-effort cleanup
            }
        }
    }
}
