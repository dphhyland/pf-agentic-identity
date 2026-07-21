package com.pingidentity.ps.oidf.common;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-process RESP server implementing just the commands {@link RedisAttestationStore} uses
 * (AUTH, SELECT, PING, SET [NX] [EX], DEL) with real key expiry, so the store can be tested
 * without a Redis installation.
 */
final class FakeRedisServer implements Closeable {

    private static final class Entry {
        final String value;
        final long expiresAtMillis; // 0 = no expiry

        Entry(String value, long expiresAtMillis) {
            this.value = value;
            this.expiresAtMillis = expiresAtMillis;
        }
    }

    private final ServerSocket server;
    private final Thread acceptor;
    private final Map<String, Entry> store = new ConcurrentHashMap<>();
    private final List<Socket> connections = new ArrayList<>();
    private final String requiredPassword;
    private volatile boolean closed;

    FakeRedisServer(String requiredPassword) throws IOException {
        this.requiredPassword = requiredPassword;
        this.server = new ServerSocket(0);
        this.acceptor = new Thread(this::acceptLoop, "fake-redis-acceptor");
        this.acceptor.setDaemon(true);
        this.acceptor.start();
    }

    int port() {
        return this.server.getLocalPort();
    }

    String url() {
        String auth = this.requiredPassword == null ? "" : "default:" + this.requiredPassword + "@";
        return "redis://" + auth + "127.0.0.1:" + this.port();
    }

    @Override
    public void close() throws IOException {
        this.closed = true;
        this.server.close();
        synchronized (this.connections) {
            for (Socket socket : this.connections) {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // best effort
                }
            }
            this.connections.clear();
        }
    }

    private void acceptLoop() {
        while (!this.closed) {
            try {
                Socket socket = this.server.accept();
                synchronized (this.connections) {
                    this.connections.add(socket);
                }
                Thread handler = new Thread(() -> this.handle(socket), "fake-redis-conn");
                handler.setDaemon(true);
                handler.start();
            } catch (IOException e) {
                return; // server closed
            }
        }
    }

    private void handle(Socket socket) {
        try (Socket s = socket;
             InputStream in = new BufferedInputStream(s.getInputStream());
             OutputStream out = new BufferedOutputStream(s.getOutputStream())) {
            boolean authed = this.requiredPassword == null;
            while (true) {
                List<String> cmd = readCommand(in);
                if (cmd == null || cmd.isEmpty()) {
                    return;
                }
                String name = cmd.get(0).toUpperCase(Locale.ROOT);
                if (name.equals("AUTH")) {
                    String pass = cmd.get(cmd.size() - 1);
                    if (this.requiredPassword != null && this.requiredPassword.equals(pass)) {
                        authed = true;
                        write(out, "+OK\r\n");
                    } else {
                        write(out, "-ERR invalid password\r\n");
                    }
                    continue;
                }
                if (!authed) {
                    write(out, "-NOAUTH Authentication required.\r\n");
                    continue;
                }
                switch (name) {
                    case "PING":
                        write(out, "+PONG\r\n");
                        break;
                    case "SELECT":
                        write(out, "+OK\r\n");
                        break;
                    case "SET":
                        this.handleSet(cmd, out);
                        break;
                    case "DEL": {
                        int removed = 0;
                        for (int i = 1; i < cmd.size(); i++) {
                            if (this.get(cmd.get(i)) != null) {
                                this.store.remove(cmd.get(i));
                                removed++;
                            }
                        }
                        write(out, ":" + removed + "\r\n");
                        break;
                    }
                    default:
                        write(out, "-ERR unknown command '" + name + "'\r\n");
                }
            }
        } catch (IOException ignored) {
            // connection dropped
        }
    }

    private void handleSet(List<String> cmd, OutputStream out) throws IOException {
        String key = cmd.get(1);
        String value = cmd.get(2);
        boolean nx = false;
        long exSeconds = 0L;
        for (int i = 3; i < cmd.size(); i++) {
            String opt = cmd.get(i).toUpperCase(Locale.ROOT);
            if (opt.equals("NX")) {
                nx = true;
            } else if (opt.equals("EX")) {
                exSeconds = Long.parseLong(cmd.get(++i));
            }
        }
        if (nx && this.get(key) != null) {
            write(out, "$-1\r\n"); // nil: not set
            return;
        }
        long expiresAt = exSeconds > 0L ? System.currentTimeMillis() + exSeconds * 1000L : 0L;
        this.store.put(key, new Entry(value, expiresAt));
        write(out, "+OK\r\n");
    }

    private Entry get(String key) {
        Entry e = this.store.get(key);
        if (e == null) {
            return null;
        }
        if (e.expiresAtMillis != 0L && e.expiresAtMillis <= System.currentTimeMillis()) {
            this.store.remove(key);
            return null;
        }
        return e;
    }

    private static void write(OutputStream out, String resp) throws IOException {
        out.write(resp.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder line = new StringBuilder();
        while (true) {
            int b = in.read();
            if (b == -1) {
                throw new IOException("EOF mid line");
            }
            if (b == '\r') {
                in.read(); // \n
                return line.toString();
            }
            line.append((char) b);
        }
    }

    /** Reads one RESP array-of-bulk-strings command; returns null on EOF. */
    private static List<String> readCommand(InputStream in) throws IOException {
        int type = in.read();
        if (type == -1) {
            return null;
        }
        if (type != '*') {
            throw new IOException("expected array, got 0x" + Integer.toHexString(type));
        }
        int count = Integer.parseInt(readLine(in));
        List<String> args = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            if (in.read() != '$') {
                throw new IOException("expected bulk string");
            }
            int len = Integer.parseInt(readLine(in));
            byte[] data = new byte[len];
            int off = 0;
            while (off < len) {
                int n = in.read(data, off, len - off);
                if (n == -1) {
                    throw new IOException("EOF mid bulk string");
                }
                off += n;
            }
            in.read(); // \r
            in.read(); // \n
            args.add(new String(data, StandardCharsets.UTF_8));
        }
        return args;
    }
}
