package com.pingidentity.ps.oidf.platform.redis;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * An in-process RESP server for {@link RedisClient}'s tests: a master, a replica (which answers writes with
 * {@code READONLY}) or a sentinel (which answers {@code SENTINEL get-master-addr-by-name} from a map it is given),
 * plain or over TLS. It keeps keys with real expiry, emulates the three {@link RedisScript}s by their digests (it
 * runs no Lua), holds a script only once {@code EVAL} has loaded it, and records every command and SNI name. Hooks
 * stage what a real server does badly: a reply that never comes, a connection dropped mid-command, idle connections
 * closed under the client, and a raw reply of any shape.
 */
final class FakeRedis implements Closeable {
    enum Role { MASTER, REPLICA, SENTINEL }

    private record Entry(String value, long expiresAt) {
    }

    private final ServerSocket server;
    private final Thread acceptor;
    private final String password;
    private volatile Role role;
    private final Map<String, Entry> store = new ConcurrentHashMap<>();
    private final Set<String> scripts = ConcurrentHashMap.newKeySet();
    private final Map<String, List<String>> masters = new ConcurrentHashMap<>();
    private final Map<String, List<String>> once = new ConcurrentHashMap<>();
    private final List<Socket> connections = Collections.synchronizedList(new ArrayList<>());
    private final List<String> commands = Collections.synchronizedList(new ArrayList<>());
    private final List<String> sniNames = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger accepted = new AtomicInteger();
    private final AtomicInteger handshakes = new AtomicInteger();
    private volatile boolean closed;
    private volatile boolean silent;
    private volatile boolean dropNext;
    private volatile String dropOn;
    private volatile String rawNext;
    private volatile boolean closeAfterRaw;
    private final AtomicInteger rawTimes = new AtomicInteger();
    private volatile long delayMillis;

    FakeRedis(String password, Role role) throws IOException {
        this(password, role, null);
    }

    FakeRedis(String password, Role role, SSLContext tls) throws IOException {
        this.password = password;
        this.role = role;
        this.server = tls == null ? new ServerSocket(0, 50, InetAddress.getLoopbackAddress())
                : tls.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        this.acceptor = new Thread(this::acceptLoop, "fake-redis-acceptor");
        this.acceptor.setDaemon(true);
        this.acceptor.start();
    }

    int port() {
        return this.server.getLocalPort();
    }

    String url(String scheme, String host) {
        return scheme + "://" + (this.password == null ? "" : "default:" + this.password + "@") + host + ":" + this.port();
    }

    void role(Role role) {
        this.role = role;
    }

    /** As a sentinel: the master {@code name} is at {@code host:port}; a null host forgets it. */
    void master(String name, String host, int port) {
        if (host == null) {
            this.masters.remove(name);
        } else {
            this.masters.put(name, List.of(host, Integer.toString(port)));
        }
    }

    /** As a sentinel: names {@code host:port} once more, and then whatever {@link #master} set before. */
    void masterOnce(String name, String host, int port) {
        this.once.put(name, List.of(host, Integer.toString(port)));
    }

    /** As a sentinel: answers get-master-addr-by-name with {@code reply}, whatever its shape. */
    void masterReply(String name, List<String> reply) {
        this.masters.put(name, reply);
    }

    void silent(boolean silent) {
        this.silent = silent;
    }

    void dropNextCommand() {
        this.dropNext = true;
    }

    /** The next command named {@code name} is read, recorded and not run, and its connection closed. */
    void dropNextCommandNamed(String name) {
        this.dropOn = name;
    }

    void rawNextReply(String raw) {
        this.rawReplies(raw, 1);
    }

    /** The next {@code times} replies are {@code raw}. */
    void rawReplies(String raw, int times) {
        this.closeAfterRaw = false;
        this.rawTimes.set(times);
        this.rawNext = raw;
    }

    /** The next reply is {@code raw}, and then the connection is closed: a reply cut off. */
    void rawNextReplyThenClose(String raw) {
        this.closeAfterRaw = true;
        this.rawTimes.set(1);
        this.rawNext = raw;
    }

    void delay(long millis) {
        this.delayMillis = millis;
    }

    void forgetScripts() {
        this.scripts.clear();
    }

    /** Closes every connection open now, as a server's idle timeout does. */
    void closeConnections() throws IOException {
        synchronized (this.connections) {
            for (Socket socket : this.connections) {
                socket.close();
            }
            this.connections.clear();
        }
    }

    List<String> commands() {
        return List.copyOf(this.commands);
    }

    void clearCommands() {
        this.commands.clear();
        this.sniNames.clear();
        this.handshakes.set(0);
    }

    List<String> sniNames() {
        return List.copyOf(this.sniNames);
    }

    int accepted() {
        return this.accepted.get();
    }

    void awaitHandshakes(int count) throws InterruptedException {
        for (int i = 0; i < 100 && this.handshakes.get() < count; i++) {
            Thread.sleep(20L);
        }
    }

    String value(String key) {
        Entry entry = this.live(key);
        return entry == null ? null : entry.value;
    }

    void put(String key, String value) {
        this.store.put(key, new Entry(value, 0L));
    }

    @Override
    public void close() throws IOException {
        this.closed = true;
        this.server.close();
        try {
            this.acceptor.join(2000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        this.closeConnections();
    }

    private void acceptLoop() {
        while (!this.closed) {
            try {
                Socket socket = this.server.accept();
                this.accepted.incrementAndGet();
                this.connections.add(socket);
                Thread handler = new Thread(() -> this.serve(socket), "fake-redis-conn");
                handler.setDaemon(true);
                handler.start();
            } catch (IOException e) {
                return;
            }
        }
    }

    private void serve(Socket socket) {
        try (socket) {
            if (socket instanceof SSLSocket tls) {
                try {
                    tls.startHandshake();
                } finally {
                    this.handshakes.incrementAndGet();
                }
                for (SNIServerName name : ((ExtendedSSLSession) tls.getSession()).getRequestedServerNames()) {
                    this.sniNames.add(new String(name.getEncoded(), StandardCharsets.US_ASCII));
                }
            }
            InputStream in = new BufferedInputStream(socket.getInputStream());
            OutputStream out = socket.getOutputStream();
            boolean authed = this.password == null;
            List<String> command;
            while ((command = readCommand(in)) != null) {
                this.commands.add(String.join(" ", command));
                if (this.dropNext) {
                    this.dropNext = false;
                    return;
                }
                if (command.get(0).equalsIgnoreCase(this.dropOn)) {
                    this.dropOn = null;
                    return;
                }
                while (this.silent && !this.closed) {
                    Thread.sleep(10L);
                }
                if (this.delayMillis > 0L) {
                    Thread.sleep(this.delayMillis);
                }
                String raw = this.rawNext;
                if (raw != null) {
                    if (this.rawTimes.decrementAndGet() <= 0) {
                        this.rawNext = null;
                    }
                    out.write(raw.getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    if (this.closeAfterRaw) {
                        return;
                    }
                    continue;
                }
                String name = command.get(0).toUpperCase(Locale.ROOT);
                String reply;
                if (name.equals("AUTH")) {
                    boolean ok = this.password != null && this.password.equals(command.get(command.size() - 1));
                    authed |= ok;
                    reply = ok ? "+OK\r\n" : "-WRONGPASS invalid username-password pair\r\n";
                } else if (!authed) {
                    reply = "-NOAUTH Authentication required.\r\n";
                } else {
                    reply = this.answer(name, command);
                }
                out.write(reply.getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        } catch (IOException | RuntimeException e) {
            // a dropped connection, a refused handshake or a closed server ends the conversation
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String answer(String name, List<String> c) {
        if (this.role == Role.SENTINEL) {
            if (name.equals("SENTINEL") && c.size() == 3 && c.get(1).equalsIgnoreCase("get-master-addr-by-name")) {
                List<String> first = this.once.remove(c.get(2));
                List<String> address = first != null ? first : this.masters.get(c.get(2));
                return address == null ? "*-1\r\n" : array(address);
            }
            return name.equals("PING") ? "+PONG\r\n" : "-ERR unknown command '" + name + "'\r\n";
        }
        boolean write = Set.of("SET", "DEL", "INCR", "PEXPIRE", "EVAL", "EVALSHA").contains(name);
        if (write && this.role == Role.REPLICA) {
            return "-READONLY You can't write against a read only replica.\r\n";
        }
        switch (name) {
            case "PING":
                return "+PONG\r\n";
            case "SELECT":
                return "+OK\r\n";
            case "ROLE":
                return this.role == Role.MASTER ? "*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n"
                        : "*5\r\n$5\r\nslave\r\n$9\r\n127.0.0.1\r\n:6379\r\n$9\r\nconnected\r\n:0\r\n";
            case "SET":
                return this.set(c);
            case "GET": {
                Entry e = this.live(c.get(1));
                return e == null ? "$-1\r\n" : bulk(e.value);
            }
            case "DEL": {
                int removed = 0;
                for (int i = 1; i < c.size(); i++) {
                    if (this.live(c.get(i)) != null) {
                        this.store.remove(c.get(i));
                        removed++;
                    }
                }
                return ":" + removed + "\r\n";
            }
            case "INCR":
                return ":" + this.incr(c.get(1)) + "\r\n";
            case "PEXPIRE":
                return ":" + (this.expire(c.get(1), Long.parseLong(c.get(2))) ? 1 : 0) + "\r\n";
            case "PTTL":
                return ":" + this.pttl(c.get(1)) + "\r\n";
            case "EVAL":
                this.scripts.add(RedisScript.sha1(c.get(1)));
                return this.run(RedisScript.sha1(c.get(1)), c);
            case "EVALSHA":
                if (!this.scripts.contains(c.get(1))) {
                    return "-NOSCRIPT No matching script. Please use EVAL.\r\n";
                }
                return this.run(c.get(1), c);
            default:
                return "-ERR unknown command '" + name + "'\r\n";
        }
    }

    /** The three platform scripts, by digest, as Redis would run them. */
    private String run(String sha, List<String> c) {
        String key = c.size() > 3 ? c.get(3) : null;
        if (sha.equals(RedisScript.COMPARE_AND_DELETE.sha1())) {
            Entry e = this.live(key);
            if (e != null && e.value.equals(c.get(4))) {
                this.store.remove(key);
                return ":1\r\n";
            }
            return ":0\r\n";
        }
        if (sha.equals(RedisScript.COMPARE_AND_EXTEND.sha1())) {
            Entry e = this.live(key);
            return e != null && e.value.equals(c.get(4)) && this.expire(key, Long.parseLong(c.get(5))) ? ":1\r\n" : ":0\r\n";
        }
        if (sha.equals(RedisScript.FIXED_WINDOW.sha1())) {
            long n = this.incr(key);
            long ttl = this.pttl(key);
            if (ttl < 0) {
                ttl = Long.parseLong(c.get(4));
                this.expire(key, ttl);
            }
            return "*2\r\n:" + n + "\r\n:" + ttl + "\r\n";
        }
        return "-ERR this fake runs only the platform's scripts\r\n";
    }

    private String set(List<String> c) {
        String key = c.get(1);
        boolean nx = false;
        long ttl = 0L;
        for (int i = 3; i < c.size(); i++) {
            String option = c.get(i).toUpperCase(Locale.ROOT);
            if (option.equals("NX")) {
                nx = true;
            } else if (option.equals("EX")) {
                ttl = Long.parseLong(c.get(++i)) * 1000L;
            } else if (option.equals("PX")) {
                ttl = Long.parseLong(c.get(++i));
            }
        }
        if (nx && this.live(key) != null) {
            return "$-1\r\n";
        }
        this.store.put(key, new Entry(c.get(2), ttl > 0L ? System.currentTimeMillis() + ttl : 0L));
        return "+OK\r\n";
    }

    private synchronized long incr(String key) {
        Entry e = this.live(key);
        long n = e == null ? 1L : Long.parseLong(e.value) + 1L;
        this.store.put(key, new Entry(Long.toString(n), e == null ? 0L : e.expiresAt));
        return n;
    }

    private boolean expire(String key, long millis) {
        Entry e = this.live(key);
        if (e == null) {
            return false;
        }
        this.store.put(key, new Entry(e.value, System.currentTimeMillis() + millis));
        return true;
    }

    private long pttl(String key) {
        Entry e = this.live(key);
        if (e == null) {
            return -2L;
        }
        return e.expiresAt == 0L ? -1L : Math.max(1L, e.expiresAt - System.currentTimeMillis());
    }

    private Entry live(String key) {
        Entry e = this.store.get(key);
        if (e != null && e.expiresAt != 0L && e.expiresAt <= System.currentTimeMillis()) {
            this.store.remove(key);
            return null;
        }
        return e;
    }

    private static String bulk(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return "$" + bytes.length + "\r\n" + value + "\r\n";
    }

    private static String array(List<String> items) {
        StringBuilder out = new StringBuilder("*" + items.size() + "\r\n");
        for (String item : items) {
            out.append(bulk(item));
        }
        return out.toString();
    }

    private static List<String> readCommand(InputStream in) throws IOException {
        String header = readLine(in);
        if (header == null) {
            return null;
        }
        int count = Integer.parseInt(header.substring(1));
        List<String> args = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int length = Integer.parseInt(readLine(in).substring(1));
            byte[] data = in.readNBytes(length);
            readLine(in);
            args.add(new String(data, StandardCharsets.UTF_8));
        }
        return args;
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\r') {
                in.read();
                return line.toString(StandardCharsets.UTF_8);
            }
            line.write(b);
        }
        return null;
    }
}
