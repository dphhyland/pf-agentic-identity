/*
 * Minimal RESP (Redis) client - deliberately dependency-free.
 */
package com.pingidentity.ps.oidf.clientattestation;

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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Tiny Redis client speaking just enough RESP for the attestation stores ({@code AUTH}, {@code SELECT},
 * {@code SET}, {@code GET}, {@code DEL}, {@code PING}). Written in-module so the WAR stays free of
 * third-party Redis client jars (this project builds offline against local distro jars).
 *
 * <p>Accepts {@code redis://[user[:password]@]host[:port][/db]} and {@code rediss://} (TLS) URLs - the
 * shape Railway and most managed Redis providers export as {@code REDIS_URL}. Connections are pooled
 * (small bounded pool) and re-established transparently; a command that fails on a pooled connection is
 * retried once on a fresh one.
 *
 * <p>TLS ({@code rediss://}) verifies the server the way a browser does: the certificate chains to a trusted
 * CA - the JVM's, or the PEM file {@code OIDF_REDIS_CA_FILE} names - and its name matches the URL's host
 * (the HTTPS endpoint identification algorithm, RFC 2818 §3.1), with the host sent as SNI. The handshake is
 * run to completion before anything is written, so the password in {@code AUTH} never travels before the
 * peer is verified. Under the production profile a plaintext {@code redis://} URL is refused: the same
 * password would otherwise cross the network in the clear. The profile is platform's
 * ({@link DeploymentProfile}, plan item PR-1).
 *
 * <p>Reply mapping: simple strings and bulk strings → {@link String}, integers → {@link Long},
 * nil → {@code null}, arrays → {@link List}. A Redis {@code -ERR} reply throws
 * {@link IllegalStateException} (not retried); transport failures throw {@link IOException}.
 */
final class MiniRedisClient implements Closeable {
    static final String CA_FILE_ENV = "OIDF_REDIS_CA_FILE";
    static final String CA_FILE_PROPERTY = "oidf.redis.ca.file";
    static final String ENDPOINT_IDENTIFICATION = "HTTPS";

    private static final int TIMEOUT_MS = 3000;
    private static final int MAX_POOLED = 4;
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private final String host;
    private final int port;
    private final boolean tls;
    private final SSLContext sslContext;
    private final String username;
    private final String password;
    private final int db;
    private final ArrayDeque<Conn> pool = new ArrayDeque<>();
    private volatile boolean closed;

    /** From the environment: the CA file from {@code OIDF_REDIS_CA_FILE} (or its system property) and the profile. */
    MiniRedisClient(String url) {
        this(url, caFileFromEnvironment(System::getProperty, System::getenv), DeploymentProfile.isProduction(System::getenv));
    }

    /**
     * @param caFile     a PEM file of one or more CA certificates to trust for {@code rediss://}, or null for the JVM's
     * @param production whether the production profile applies, which refuses {@code redis://}
     * @throws IllegalArgumentException for a URL this client does not accept, or a CA file it cannot use
     */
    MiniRedisClient(String url, String caFile, boolean production) {
        URI uri;
        try {
            uri = URI.create(url.trim());
        } catch (IllegalArgumentException e) {
            // URI's own message quotes the input, password and all; this one does not.
            throw new IllegalArgumentException("Redis URL is not a valid URI: " + redact(url));
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        if (!scheme.equals("redis") && !scheme.equals("rediss")) {
            throw new IllegalArgumentException("Unsupported Redis URL scheme: " + uri.getScheme());
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("Redis URL has no host: " + redact(url));
        }
        this.tls = scheme.equals("rediss");
        String refusal = transportRefusal(this.tls, production);
        if (refusal != null) {
            throw new IllegalArgumentException(refusal);
        }
        this.sslContext = this.tls ? sslContextFor(caFile) : null;
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

    boolean tls() {
        return this.tls;
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
        Socket socket = this.tls ? this.sslContext.getSocketFactory().createSocket() : new Socket();
        try {
            socket.connect(new InetSocketAddress(this.host, this.port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            if (this.tls) {
                SSLSocket ssl = (SSLSocket) socket;
                ssl.setSSLParameters(sslParametersFor(ssl.getSSLParameters(), this.host));
                // Verified before a byte of AUTH is encoded: a peer whose chain or name does not check out
                // fails here, with nothing of ours sent.
                ssl.startHandshake();
            }
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

    /**
     * The TLS parameters every connection uses: the HTTPS endpoint identification algorithm, so the server's
     * certificate must name {@code host}, and {@code host} as the SNI name when it is a name (RFC 6066 §3
     * permits no IP literal there; the JDK sends none for one and the certificate is then checked against the
     * address).
     */
    static SSLParameters sslParametersFor(SSLParameters base, String host) {
        base.setEndpointIdentificationAlgorithm(ENDPOINT_IDENTIFICATION);
        if (!isIpLiteral(host)) {
            base.setServerNames(List.of(new SNIHostName(host)));
        }
        return base;
    }

    /**
     * Why a URL's transport is refused, or null when it is allowed: the production profile accepts {@code rediss://}
     * only, because the password in {@code AUTH} would otherwise cross the network in the clear.
     */
    static String transportRefusal(boolean tls, boolean production) {
        if (tls || !production) {
            return null;
        }
        return "the Redis URL is redis:// (plaintext); the production profile accepts rediss:// only, because the"
                + " password in AUTH would otherwise cross the network in the clear. Use rediss://, or set "
                + DeploymentProfile.PROFILE_ENV + "=development on a rig";
    }

    /**
     * {@code url} with its userinfo replaced by {@code ***}, for messages that reach a log: everything between the
     * scheme's {@code ://} and the last {@code @}, so a password with an unencoded {@code @} or {@code /} goes too.
     */
    static String redact(String url) {
        if (url == null) {
            return null;
        }
        int authority = url.indexOf("://");
        int at = url.lastIndexOf('@');
        if (authority < 0 || at < authority) {
            return url;
        }
        return url.substring(0, authority + 3) + "***" + url.substring(at);
    }

    static boolean isIpLiteral(String host) {
        return host.startsWith("[") || IPV4.matcher(host).matches();
    }

    /**
     * The JVM's default context, or one that trusts only the certificates in {@code caFile} - a PEM file
     * with one or more CA certificates, the shape managed Redis providers publish.
     *
     * @throws IllegalArgumentException when the file cannot be read or holds no certificate
     */
    static SSLContext sslContextFor(String caFile) {
        if (caFile == null || caFile.isBlank()) {
            return jvmDefaultContext();
        }
        Path path = Path.of(caFile.trim());
        try (InputStream in = Files.newInputStream(path)) {
            Collection<? extends Certificate> certificates = CertificateFactory.getInstance("X.509").generateCertificates(in);
            if (certificates.isEmpty()) {
                throw new IllegalArgumentException(CA_FILE_ENV + " names " + path + ", which holds no certificate");
            }
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            trust.load(null, null);
            int i = 0;
            for (Certificate certificate : certificates) {
                trust.setCertificateEntry("redis-ca-" + i++, certificate);
            }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            return context;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException(CA_FILE_ENV + " names " + path + ", which cannot be used as a CA file: "
                    + e.getMessage(), e);
        }
    }

    private static SSLContext jvmDefaultContext() {
        try {
            return SSLContext.getDefault();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("no default SSLContext", e);
        }
    }

    static String caFileFromEnvironment(Function<String, String> props, Function<String, String> env) {
        String value = props.apply(CA_FILE_PROPERTY);
        if (value == null || value.isBlank()) {
            value = env.apply(CA_FILE_ENV);
        }
        return value == null || value.isBlank() ? null : value.trim();
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
