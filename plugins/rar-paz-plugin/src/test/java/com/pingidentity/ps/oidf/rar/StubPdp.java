/*
 * A loopback PDP for the transport tests: plain or TLS, answering with whatever bytes a test writes, whenever it writes them.
 */
package com.pingidentity.ps.oidf.rar;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
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
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Accepts connections on 127.0.0.1, one thread each, reads the request head and its Content-Length body, records it,
 * and hands the socket's output to the test's {@link Handler}: a well-formed answer, a malformed one, one that
 * stalls, or one sent a few bytes at a time.
 */
final class StubPdp implements AutoCloseable {

    @FunctionalInterface
    interface Handler {
        void handle(String head, byte[] body, OutputStream out) throws Exception;
    }

    /** What arrived: the request line and headers, and the body. */
    record Recorded(String head, String body) {
        String path() {
            return head.substring(head.indexOf(' ') + 1, head.indexOf(' ', head.indexOf(' ') + 1));
        }

        String header(String name) {
            for (String line : head.split("\r\n")) {
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
    private volatile Handler handler;
    final BlockingQueue<Recorded> requests = new LinkedBlockingQueue<>();
    final AtomicInteger accepted = new AtomicInteger();

    private StubPdp(SSLContext tls, Handler handler) throws IOException {
        this.tls = tls;
        this.handler = handler;
        this.server = new ServerSocket();
        this.server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 100);
        Thread acceptor = new Thread(this::accept, "stub-pdp");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    static StubPdp plain(Handler handler) throws IOException {
        return new StubPdp(null, handler);
    }

    static StubPdp tls(SSLContext context, Handler handler) throws IOException {
        return new StubPdp(context, handler);
    }

    void handler(Handler next) {
        this.handler = next;
    }

    /** {@code http://127.0.0.1:<port><path>}. */
    String url(String path) {
        return "http://127.0.0.1:" + server.getLocalPort() + path;
    }

    /** {@code https://<host>:<port><path>}. */
    String httpsUrl(String host, String path) {
        return "https://" + host + ":" + server.getLocalPort() + path;
    }

    Recorded take() throws InterruptedException {
        Recorded recorded = requests.poll(10, TimeUnit.SECONDS);
        if (recorded == null) {
            throw new AssertionError("no request arrived");
        }
        return recorded;
    }

    private void accept() {
        while (!server.isClosed()) {
            Socket socket;
            try {
                socket = server.accept();
            } catch (IOException e) {
                return;
            }
            accepted.incrementAndGet();
            Thread worker = new Thread(() -> serve(socket), "stub-pdp-connection");
            worker.setDaemon(true);
            worker.start();
        }
    }

    private void serve(Socket plain) {
        try (Socket socket = plain) {
            socket.setSoTimeout(20_000);
            Socket conversation = socket;
            if (tls != null) {
                SSLSocket ssl = (SSLSocket) tls.getSocketFactory().createSocket(socket, null, socket.getPort(), false);
                ssl.setUseClientMode(false);
                ssl.startHandshake();
                conversation = ssl;
            }
            InputStream in = conversation.getInputStream();
            String head = readHead(in);
            if (head == null) {
                return;
            }
            byte[] body = new byte[0];
            String length = new Recorded(head, "").header("Content-Length");
            if (length != null) {
                body = in.readNBytes(Integer.parseInt(length));
            }
            requests.add(new Recorded(head, new String(body, StandardCharsets.UTF_8)));
            OutputStream out = conversation.getOutputStream();
            handler.handle(head, body, out);
            out.flush();
        } catch (Exception e) {
            // The client gave up, refused the handshake, or the handler wrote past a closed socket.
        }
    }

    private static String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int matched = 0;
        byte[] end = {'\r', '\n', '\r', '\n'};
        while (matched < 4) {
            int b = in.read();
            if (b == -1) {
                return null;
            }
            head.write(b);
            matched = b == end[matched] ? matched + 1 : (b == '\r' ? 1 : 0);
        }
        return head.toString(StandardCharsets.ISO_8859_1);
    }

    static void write(OutputStream out, String text) throws IOException {
        out.write(text.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    /** A JSON answer with this status. */
    static Handler json(int status, String body) {
        return (head, requestBody, out) -> write(out, "HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\n"
                + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\nConnection: close\r\n\r\n" + body);
    }

    @Override
    public void close() throws IOException {
        server.close();
    }

    /**
     * A CA made by {@code keytool} for this run, and server keys it signed: {@code localhost} (with the address
     * 127.0.0.1) and {@code wrong.example}. Nothing is written anywhere but a temporary directory.
     */
    static final class Ca {
        static final String PASSWORD = "changeit";
        private static Ca instance;

        final Path dir;
        final String caPem;
        final X509Certificate ca;

        private Ca() throws Exception {
            dir = Files.createTempDirectory("s2c-pki");
            dir.toFile().deleteOnExit();
            keytool("-genkeypair", "-alias", "ca", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=S2C test CA",
                    "-ext", "bc:c=ca:true", "-validity", "2", "-keystore", store("ca"), "-storetype", "PKCS12",
                    "-storepass", PASSWORD, "-keypass", PASSWORD);
            Path pem = dir.resolve("ca.pem");
            keytool("-exportcert", "-rfc", "-alias", "ca", "-keystore", store("ca"), "-storetype", "PKCS12",
                    "-storepass", PASSWORD, "-file", pem.toString());
            caPem = Files.readString(pem, StandardCharsets.US_ASCII);
            try (InputStream in = Files.newInputStream(pem)) {
                ca = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
            }
            leaf("localhost", "localhost", "SAN=dns:localhost,ip:127.0.0.1");
            leaf("wrong", "wrong.example", "SAN=dns:wrong.example");
        }

        static synchronized Ca get() throws Exception {
            if (instance == null) {
                instance = new Ca();
            }
            return instance;
        }

        /** A server context holding the key of {@code name}: localhost or wrong. */
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

        /** A client context trusting this CA and nothing else, to stand in for the JVM's default. */
        SSLContext clientTrustingCa() throws Exception {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            store.setCertificateEntry("ca", ca);
            javax.net.ssl.TrustManagerFactory factory =
                    javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
            factory.init(store);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            return context;
        }

        private void leaf(String name, String cn, String san) throws Exception {
            String csr = dir.resolve(name + ".csr").toString();
            String pem = dir.resolve(name + ".pem").toString();
            keytool("-genkeypair", "-alias", "leaf", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=" + cn,
                    "-validity", "2", "-keystore", store(name), "-storetype", "PKCS12", "-storepass", PASSWORD,
                    "-keypass", PASSWORD);
            keytool("-certreq", "-alias", "leaf", "-keystore", store(name), "-storetype", "PKCS12", "-storepass", PASSWORD,
                    "-file", csr);
            keytool("-gencert", "-alias", "ca", "-keystore", store("ca"), "-storetype", "PKCS12", "-storepass", PASSWORD,
                    "-infile", csr, "-outfile", pem, "-rfc", "-ext", san, "-validity", "2");
            keytool("-importcert", "-noprompt", "-alias", "ca", "-file", dir.resolve("ca.pem").toString(), "-keystore",
                    store(name), "-storetype", "PKCS12", "-storepass", PASSWORD);
            keytool("-importcert", "-noprompt", "-alias", "leaf", "-file", pem, "-keystore", store(name), "-storetype",
                    "PKCS12", "-storepass", PASSWORD);
        }

        private String store(String name) {
            return dir.resolve(name + ".p12").toString();
        }

        private static void keytool(String... args) throws Exception {
            List<String> command = new ArrayList<>();
            command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
            command.addAll(List.of(args));
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            process.getInputStream().transferTo(output);
            if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw new IOException("keytool " + args[0] + " failed: " + output.toString(StandardCharsets.UTF_8)
                        .toLowerCase(Locale.ROOT));
            }
        }
    }
}
