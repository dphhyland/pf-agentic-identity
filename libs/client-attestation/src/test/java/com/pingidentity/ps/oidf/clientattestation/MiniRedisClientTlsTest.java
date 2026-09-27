package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The S3a guard on a real socket, inside the JVM, so a build without a TLS Redis still catches its loss. The server's
 * certificate, made by {@code keytool} for this run and trusted through {@code OIDF_REDIS_CA_FILE}'s code path,
 * names {@code localhost} and not {@code 127.0.0.1}. Addressed by the name it carries, the client verifies the peer,
 * sends the name as SNI, authenticates and pings. Addressed by the address it does not carry, the handshake fails on
 * the name and the server reads nothing - no {@code AUTH}, so no password. {@link RedisLiveTest} repeats the refusal
 * against a real Redis when one is configured.
 */
class MiniRedisClientTlsTest {
    private static final String PASSWORD = "not-a-real-password";

    @TempDir
    static Path dir;
    private static TlsRespServer server;
    private static String caFile;

    @BeforeAll
    static void startAServerWhoseCertificateNamesOnlyLocalhost() throws Exception {
        Path keystore = dir.resolve("redis.p12");
        Path ca = dir.resolve("redis-ca.pem");
        String storePass = "changeit-" + System.nanoTime();
        keytool("-genkeypair", "-alias", "redis", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=localhost",
                "-ext", "SAN=dns:localhost", "-validity", "2", "-keystore", keystore.toString(), "-storetype", "PKCS12",
                "-storepass", storePass, "-keypass", storePass);
        keytool("-exportcert", "-rfc", "-alias", "redis", "-keystore", keystore.toString(), "-storetype", "PKCS12",
                "-storepass", storePass, "-file", ca.toString());
        caFile = ca.toString();
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = java.nio.file.Files.newInputStream(keystore)) {
            keys.load(in, storePass.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, storePass.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), null, null);
        server = new TlsRespServer(context);
    }

    @AfterAll
    static void stop() throws IOException {
        if (server != null) {
            server.close();
        }
    }

    @Test
    void theNameTheCertificateCarriesIsVerifiedSentAsSniAndThenAuthenticated() throws Exception {
        server.reset();
        try (MiniRedisClient client = new MiniRedisClient("rediss://:" + PASSWORD + "@localhost:" + server.port(), caFile, true)) {
            assertEquals("PONG", client.call("PING"));
        }
        assertEquals(List.of("AUTH " + PASSWORD, "PING"), server.commands());
        assertEquals(List.of("localhost"), server.sniNames(), "the host goes out as SNI");
    }

    @Test
    void anAddressTheCertificateDoesNotCarryFailsTheHandshakeBeforeAnyCommand() throws Exception {
        server.reset();
        try (MiniRedisClient client = new MiniRedisClient("rediss://:" + PASSWORD + "@127.0.0.1:" + server.port(), caFile, true)) {
            SSLHandshakeException e = assertThrows(SSLHandshakeException.class, () -> client.call("PING"));
            assertTrue(String.valueOf(e.getMessage()).contains("127.0.0.1"), e.getMessage());
        }
        server.awaitHandshakes(1);
        assertEquals(List.of(), server.commands(), "nothing was sent: the password never left");
    }

    private static void keytool(String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        Collections.addAll(command, args);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + output);
        }
    }

    /** A TLS server speaking just enough RESP for AUTH and PING, recording the commands and SNI names it receives. */
    private static final class TlsRespServer implements Closeable {
        private final SSLServerSocket socket;
        private final Thread acceptor;
        private final List<String> commands = Collections.synchronizedList(new ArrayList<>());
        private final List<String> sniNames = Collections.synchronizedList(new ArrayList<>());
        private final java.util.concurrent.atomic.AtomicInteger handshakes = new java.util.concurrent.atomic.AtomicInteger();
        private volatile boolean closed;

        TlsRespServer(SSLContext context) throws IOException {
            this.socket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0);
            this.acceptor = new Thread(this::acceptLoop, "tls-resp-acceptor");
            this.acceptor.setDaemon(true);
            this.acceptor.start();
        }

        int port() {
            return this.socket.getLocalPort();
        }

        void reset() {
            this.commands.clear();
            this.sniNames.clear();
            this.handshakes.set(0);
        }

        List<String> commands() {
            return List.copyOf(this.commands);
        }

        List<String> sniNames() {
            return List.copyOf(this.sniNames);
        }

        void awaitHandshakes(int count) throws InterruptedException {
            for (int i = 0; i < 100 && this.handshakes.get() < count; i++) {
                Thread.sleep(20L);
            }
        }

        private void acceptLoop() {
            while (!this.closed) {
                try {
                    SSLSocket s = (SSLSocket) this.socket.accept();
                    Thread handler = new Thread(() -> this.serve(s), "tls-resp-conn");
                    handler.setDaemon(true);
                    handler.start();
                } catch (IOException e) {
                    return;
                }
            }
        }

        private void serve(SSLSocket s) {
            try (s) {
                s.setSoTimeout(5000);
                try {
                    s.startHandshake();
                } finally {
                    this.handshakes.incrementAndGet();
                }
                for (SNIServerName name : ((ExtendedSSLSession) s.getSession()).getRequestedServerNames()) {
                    this.sniNames.add(new String(name.getEncoded(), StandardCharsets.US_ASCII));
                }
                InputStream in = new BufferedInputStream(s.getInputStream());
                OutputStream out = s.getOutputStream();
                List<String> command;
                while ((command = readCommand(in)) != null) {
                    this.commands.add(String.join(" ", command));
                    String name = command.get(0).toUpperCase(java.util.Locale.ROOT);
                    out.write(("AUTH".equals(name) ? "+OK\r\n" : "PING".equals(name) ? "+PONG\r\n" : "-ERR unknown\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                }
            } catch (IOException e) {
                // a refused handshake or a closed client ends the connection; either is expected here
            }
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
                    return line.toString(StandardCharsets.US_ASCII);
                }
                line.write(b);
            }
            return line.size() == 0 ? null : line.toString(StandardCharsets.US_ASCII);
        }

        @Override
        public void close() throws IOException {
            this.closed = true;
            this.socket.close();
        }
    }
}
