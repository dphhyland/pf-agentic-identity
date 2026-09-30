/*
 * A peer for the outbound call sites' tests (plan item S5d): answers at once, never, a byte at a time, or with too
 * much, over plain HTTP or TLS with a certificate a test CA signed.
 */
package com.pingidentity.ps.oidf.ssf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * One thread per connection on 127.0.0.1, so a stalled exchange does not hold the next. Each request's head and
 * Content-Length body are recorded, then the {@link Script} writes whatever the test wants. {@link #closedByClient}
 * says whether the client closed the connection while the script waited on it.
 */
final class OutboundPeer implements AutoCloseable {

    /** Writes the answer to the {@code n}th request (from 1). */
    @FunctionalInterface
    interface Script {
        void answer(int n, Recorded request, OutputStream out, Socket socket) throws Exception;
    }

    /** A request as it arrived. */
    record Recorded(String head, String body) {
        String requestLine() {
            return this.head.substring(0, this.head.indexOf("\r\n"));
        }

        String header(String name) {
            for (String line : this.head.split("\r\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 && line.substring(0, colon).equalsIgnoreCase(name)) {
                    return line.substring(colon + 1).trim();
                }
            }
            return null;
        }
    }

    private final ServerSocket server;
    private final SSLContext tls;
    private final Script script;
    private final AtomicInteger count = new AtomicInteger();
    final BlockingQueue<Recorded> requests = new LinkedBlockingQueue<>();
    /** Completed "closed" when the client closed a connection the script was waiting on, else what happened. */
    final CompletableFuture<String> closedByClient = new CompletableFuture<>();

    private OutboundPeer(SSLContext tls, Function<OutboundPeer, Script> script) throws IOException {
        this.tls = tls;
        this.script = script.apply(this);
        this.server = new ServerSocket();
        this.server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 50);
        Thread accept = new Thread(this::serve, "s5d-peer");
        accept.setDaemon(true);
        accept.start();
    }

    static OutboundPeer plain(Script script) throws IOException {
        return new OutboundPeer(null, peer -> script);
    }

    static OutboundPeer tls(SSLContext context, Script script) throws IOException {
        return new OutboundPeer(context, peer -> script);
    }

    /** A peer whose script needs the peer itself, to note when the client closed: {@code tls} null for plain HTTP. */
    static OutboundPeer of(SSLContext tls, Function<OutboundPeer, Script> script) throws IOException {
        return new OutboundPeer(tls, script);
    }

    /** A peer that reads the request and never answers. */
    static OutboundPeer stalling() throws IOException {
        return of(null, OutboundPeer::stallBeforeHead);
    }

    /** A peer that sends its head at once and its body a byte every 100 ms. */
    static OutboundPeer dribbling(int status) throws IOException {
        return of(null, peer -> peer.dribbleBody(status));
    }

    /** {@code http://127.0.0.1:<port>} or {@code https://<host>:<port>}, then {@code path}. */
    String url(String path) {
        return (this.tls == null ? "http://127.0.0.1:" : "https://localhost:") + this.server.getLocalPort() + path;
    }

    int port() {
        return this.server.getLocalPort();
    }

    private void serve() {
        while (!this.server.isClosed()) {
            Socket socket;
            try {
                socket = this.server.accept();
            } catch (IOException e) {
                return;
            }
            Thread worker = new Thread(() -> handle(socket), "s5d-peer-conn");
            worker.setDaemon(true);
            worker.start();
        }
    }

    private void handle(Socket accepted) {
        try (Socket socket = this.tls == null ? accepted : layer(accepted)) {
            InputStream in = socket.getInputStream();
            Recorded request = read(in);
            this.requests.add(request);
            OutputStream out = socket.getOutputStream();
            this.script.answer(this.count.incrementAndGet(), request, out, socket);
            out.flush();
        } catch (Exception e) {
            // A client that gave up or refused the certificate; the test looks at what the client saw.
        }
    }

    private Socket layer(Socket socket) throws IOException {
        SSLSocket ssl = (SSLSocket) this.tls.getSocketFactory().createSocket(socket, null, socket.getPort(), true);
        ssl.setUseClientMode(false);
        ssl.startHandshake();
        return ssl;
    }

    static Recorded read(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int matched = 0;
        while (matched < 4) {
            int b = in.read();
            if (b < 0) {
                throw new IOException("the connection closed inside the request head");
            }
            head.write(b);
            boolean expected = b == (matched % 2 == 0 ? '\r' : '\n');
            matched = expected ? matched + 1 : (b == '\r' ? 1 : 0);
        }
        String text = head.toString(StandardCharsets.ISO_8859_1);
        int length = 0;
        for (String line : text.split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                length = Integer.parseInt(line.substring("content-length:".length()).trim());
            }
        }
        return new Recorded(text, new String(in.readNBytes(length), StandardCharsets.UTF_8));
    }

    /** Answers {@code status} with {@code body} as JSON. */
    static Script answer(int status, String body) {
        return (n, request, out, socket) -> write(out, status, "", body);
    }

    static void write(OutputStream out, int status, String extraHeaders, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        out.write(("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\nContent-Length: " + bytes.length
                + "\r\n" + extraHeaders + "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        out.write(bytes);
    }

    /** Sends nothing, and waits up to 10 s for the client to close. */
    Script stallBeforeHead() {
        return (n, request, out, socket) -> awaitClose(socket);
    }

    /** Sends a head declaring 1000 bytes, then a byte every 100 ms, and notes when the client closes. */
    Script dribbleBody(int status) {
        return (n, request, out, socket) -> {
            out.write(("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            try {
                for (int i = 0; i < 1000; i++) {
                    out.write('{');
                    out.flush();
                    Thread.sleep(100);
                }
                this.closedByClient.complete("the client read the whole dribble");
            } catch (SocketException e) {
                this.closedByClient.complete("closed");
            }
        };
    }

    /** Answers {@code status} with a chunked body of {@code bytes} bytes and no length declared ahead. */
    static Script oversize(int status, int bytes) {
        return (n, request, out, socket) -> {
            out.write(("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            byte[] chunk = new byte[4096];
            java.util.Arrays.fill(chunk, (byte) 'x');
            for (int sent = 0; sent < bytes; sent += chunk.length) {
                out.write((Integer.toHexString(chunk.length) + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.write(chunk);
                out.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
            }
            out.write("0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
        };
    }

    private void awaitClose(Socket socket) throws IOException {
        socket.setSoTimeout(10_000);
        try {
            this.closedByClient.complete(socket.getInputStream().read() == -1 ? "closed" : "a byte after the request");
        } catch (SocketTimeoutException e) {
            this.closedByClient.complete("still open 10 s later");
        } catch (SocketException e) {
            this.closedByClient.complete("closed");
        }
    }

    /** What {@link #closedByClient} came to, waiting at most 15 s. */
    String closed() throws Exception {
        return this.closedByClient.get(15, TimeUnit.SECONDS);
    }

    @Override
    public void close() throws IOException {
        this.server.close();
    }

    /**
     * A certificate authority made by {@code keytool} for one test run, and two server keys it signed: one for
     * {@code localhost} (and 127.0.0.1), and one for {@code other.test}, which a client dialling localhost must refuse.
     * Nothing is written anywhere but a temporary directory.
     */
    static final class TestCa {
        private static final String PASSWORD = "changeit";
        private static TestCa instance;

        private final Path dir;
        final X509Certificate ca;

        private TestCa() throws Exception {
            this.dir = Files.createTempDirectory("s5d-ca");
            this.dir.toFile().deleteOnExit();
            keytool("-genkeypair", "-alias", "ca", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=S5D test CA",
                    "-ext", "bc:c=ca:true", "-validity", "2", "-keystore", store("ca"), "-storetype", "PKCS12",
                    "-storepass", PASSWORD, "-keypass", PASSWORD);
            Path caPem = this.dir.resolve("ca.pem");
            keytool("-exportcert", "-rfc", "-alias", "ca", "-keystore", store("ca"), "-storetype", "PKCS12",
                    "-storepass", PASSWORD, "-file", caPem.toString());
            try (InputStream in = Files.newInputStream(caPem)) {
                this.ca = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
            }
            leaf("localhost", "SAN=dns:localhost,ip:127.0.0.1", caPem);
            leaf("other.test", "SAN=dns:other.test", caPem);
        }

        static synchronized TestCa get() throws Exception {
            if (instance == null) {
                instance = new TestCa();
            }
            return instance;
        }

        /** A server context holding the key for {@code name}: localhost or other.test. */
        SSLContext server(String name) throws Exception {
            KeyStore keys = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Path.of(store(name)))) {
                keys.load(in, PASSWORD.toCharArray());
            }
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(keys, PASSWORD.toCharArray());
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(factory.getKeyManagers(), null, null);
            return context;
        }

        private void leaf(String cn, String san, Path caPem) throws Exception {
            String csr = this.dir.resolve(cn + ".csr").toString();
            String pem = this.dir.resolve(cn + ".pem").toString();
            keytool("-genkeypair", "-alias", "leaf", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=" + cn,
                    "-validity", "2", "-keystore", store(cn), "-storetype", "PKCS12", "-storepass", PASSWORD,
                    "-keypass", PASSWORD);
            keytool("-certreq", "-alias", "leaf", "-keystore", store(cn), "-storetype", "PKCS12", "-storepass", PASSWORD,
                    "-file", csr);
            keytool("-gencert", "-alias", "ca", "-keystore", store("ca"), "-storetype", "PKCS12", "-storepass", PASSWORD,
                    "-infile", csr, "-outfile", pem, "-rfc", "-ext", san, "-validity", "2");
            keytool("-importcert", "-noprompt", "-alias", "ca", "-file", caPem.toString(), "-keystore", store(cn),
                    "-storetype", "PKCS12", "-storepass", PASSWORD);
            keytool("-importcert", "-noprompt", "-alias", "leaf", "-file", pem, "-keystore", store(cn), "-storetype",
                    "PKCS12", "-storepass", PASSWORD);
        }

        private String store(String name) {
            return this.dir.resolve(name + ".p12").toString();
        }

        private static void keytool(String... args) throws Exception {
            List<String> command = new ArrayList<>();
            command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
            command.addAll(List.of(args));
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            process.getInputStream().transferTo(output);
            if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw new IOException("keytool " + args[0] + " failed: " + output.toString(StandardCharsets.UTF_8));
            }
        }
    }
}
