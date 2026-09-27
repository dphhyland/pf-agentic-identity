package com.pingidentity.ps.oidf.platform.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException.Reason;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * OutboundHttp over TLS against a local server whose certificates a CA made for this run signed. Each test names the
 * host {@code pinned.test} (which no DNS resolves) and resolves it with a stub, so a pass proves the connection went
 * to the stub's address, the name travelled as SNI, and the certificate was checked against the name.
 */
class OutboundHttpTlsTest {

    private static TestPki pki;
    private static InetAddress loopback;

    @BeforeAll
    static void pki() throws Exception {
        pki = TestPki.get();
        loopback = InetAddress.getByName("127.0.0.1");
    }

    private static AddressPolicy stub(AtomicInteger lookups) {
        return AddressPolicy.builder()
                .publicAddress(address -> address.equals(loopback))
                .resolver(host -> {
                    lookups.incrementAndGet();
                    if (host.equals("pinned.test") || host.equals("127.0.0.1")) {
                        return new InetAddress[] {loopback};
                    }
                    throw new java.net.UnknownHostException(host);
                })
                .build();
    }

    private static OutboundHttp client(TlsTrust trust) {
        return OutboundHttp.builder(stub(new AtomicInteger())).tls(trust).connectTimeout(Duration.ofSeconds(3)).build();
    }

    private static Deadline seconds(long seconds) {
        return Deadline.after(Duration.ofSeconds(seconds));
    }

    @Test
    void theNameIsSentAsSniAndTheCertificateIsCheckedAgainstItAtTheCheckedAddress() throws Exception {
        try (TestServer server = TestServer.tls(pki.server("pinned"), TestServer.ok("over tls"))) {
            AtomicInteger lookups = new AtomicInteger();
            OutboundHttp http = OutboundHttp.builder(stub(lookups)).tls(pki.trust()).build();
            OutboundResponse response = http.get("https://pinned.test:" + server.port() + "/x", "*/*", seconds(10));
            assertEquals("over tls", response.bodyText());
            assertEquals(loopback, response.remoteAddress().getAddress());
            assertEquals(1, lookups.get());
            TestServer.Recorded request = server.take();
            assertEquals("pinned.test", request.sni());
            assertEquals("pinned.test:" + server.port(), request.header("Host"));
        }
    }

    @Test
    void anAddressLiteralSendsNoSniAndIsCheckedAgainstTheCertificatesAddress() throws Exception {
        try (TestServer server = TestServer.tls(pki.server("pinned"), TestServer.ok("literal"))) {
            OutboundResponse response = client(pki.trust()).get("https://127.0.0.1:" + server.port() + "/", "*/*", seconds(10));
            assertEquals("literal", response.bodyText());
            assertNull(server.take().sni());
        }
    }

    @Test
    void aCertificateForAnotherNameIsRefused() throws Exception {
        try (TestServer server = TestServer.tls(pki.server("other"), TestServer.ok("wrong"))) {
            OutboundHttpException e = assertThrows(OutboundHttpException.class,
                    () -> client(pki.trust()).get("https://pinned.test:" + server.port() + "/", "*/*", seconds(10)));
            assertEquals(Reason.TLS, e.reason(), e.getMessage());
            assertTrue(server.requests.isEmpty());
        }
    }

    @Test
    void aCertificateNoTrustedCaSignedIsRefused() throws Exception {
        try (TestServer server = TestServer.tls(pki.server("selfsigned"), TestServer.ok("untrusted"))) {
            assertEquals(Reason.TLS, assertThrows(OutboundHttpException.class,
                    () -> client(pki.trust()).get("https://pinned.test:" + server.port() + "/", "*/*", seconds(10))).reason());
            assertEquals(Reason.TLS, assertThrows(OutboundHttpException.class,
                    () -> client(TlsTrust.jvmDefault()).get("https://pinned.test:" + server.port() + "/", "*/*", seconds(10))).reason());
        }
    }

    @Test
    void insecureTrustAcceptsAnyChainButStillChecksTheName() throws Exception {
        TlsTrust insecure = TlsTrust.insecureIf("S5A_TEST_IGNORE_TLS", true);
        assertTrue(insecure.toString().contains("S5A_TEST_IGNORE_TLS"));
        assertTrue(InsecureTls.uses().stream().anyMatch(use -> use.setting().equals("S5A_TEST_IGNORE_TLS")));
        try (TestServer server = TestServer.tls(pki.server("selfsigned"), TestServer.ok("any chain"))) {
            assertEquals("any chain", client(insecure).get("https://pinned.test:" + server.port() + "/", "*/*", seconds(10)).bodyText());
        }
        try (TestServer server = TestServer.tls(pki.server("other"), TestServer.ok("wrong name"))) {
            assertEquals(Reason.TLS, assertThrows(OutboundHttpException.class,
                    () -> client(insecure).get("https://pinned.test:" + server.port() + "/", "*/*", seconds(10))).reason());
        }
    }

    @Test
    void insecureTrustNotAskedForIsTheJvmsTrust() {
        assertTrue(TlsTrust.insecureIf("S5A_TEST_NOT_ASKED", false).toString().contains("JVM"));
        assertTrue(InsecureTls.uses().stream().noneMatch(use -> use.setting().equals("S5A_TEST_NOT_ASKED")));
    }

    @Test
    void aCaBundleFileAndASuppliedContextAreTrusted() throws Exception {
        try (TestServer server = TestServer.tls(pki.server("pinned"), TestServer.ok("bundle"))) {
            assertEquals("bundle", client(TlsTrust.caBundle(pki.caPem))
                    .get("https://pinned.test:" + server.port() + "/", "*/*", seconds(10)).bodyText());
        }
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);
        assertTrue(TlsTrust.of(context).toString().contains("SSLContext"));
    }

    @Test
    void anEmptyCaBundleIsRefused() throws Exception {
        assertThrows(GeneralSecurityException.class, () -> TlsTrust.caCertificates(List.of()));
        Path empty = Files.createTempFile("s5a-empty", ".pem");
        try {
            assertThrows(GeneralSecurityException.class, () -> TlsTrust.caBundle(empty));
        } finally {
            Files.delete(empty);
        }
    }

    @Test
    void aServerThatNeverAnswersTheHandshakeRunsIntoTheConnectDeadline() throws Exception {
        // A plain server waits for a request head that a ClientHello never completes.
        try (TestServer server = TestServer.plain(TestServer.ok("never"))) {
            OutboundRequest request = OutboundRequest.builder(OutboundRequest.Method.GET,
                    URI.create("https://pinned.test:" + server.port() + "/")).connectTimeout(Duration.ofMillis(400)).build();
            long start = System.nanoTime();
            OutboundHttpException e = assertThrows(OutboundHttpException.class,
                    () -> client(pki.trust()).send(request, seconds(10)));
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;
            assertEquals(Reason.CONNECT_TIMEOUT, e.reason(), e.getMessage());
            assertTrue(elapsedMillis < 1500, "took " + elapsedMillis + " ms");
        }
    }

    @Test
    void aServerThatIsNotTlsIsATlsFailure() throws Exception {
        try (java.net.ServerSocket garbage = new java.net.ServerSocket(0, 5, loopback)) {
            Thread writer = new Thread(() -> {
                try (java.net.Socket socket = garbage.accept()) {
                    socket.getOutputStream().write("HTTP/1.1 400 Bad Request\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                    socket.getOutputStream().flush();
                    Thread.sleep(500);
                } catch (Exception ignored) {
                    // the client hung up
                }
            });
            writer.start();
            OutboundHttpException e = assertThrows(OutboundHttpException.class,
                    () -> client(pki.trust()).get("https://pinned.test:" + garbage.getLocalPort() + "/", "*/*", seconds(10)));
            assertEquals(Reason.TLS, e.reason(), e.getMessage());
            writer.join(5000);
        }
    }

    @Test
    void theContextCaptureOnlyTakesAContext() {
        TlsTrust.ContextCapture capture = new TlsTrust.ContextCapture();
        assertThrows(UnsupportedOperationException.class, () -> capture.cookieHandler(null));
        assertThrows(UnsupportedOperationException.class, () -> capture.connectTimeout(null));
        assertThrows(UnsupportedOperationException.class, () -> capture.sslParameters(null));
        assertThrows(UnsupportedOperationException.class, () -> capture.executor(null));
        assertThrows(UnsupportedOperationException.class, () -> capture.followRedirects(HttpClient.Redirect.NEVER));
        assertThrows(UnsupportedOperationException.class, () -> capture.version(HttpClient.Version.HTTP_1_1));
        assertThrows(UnsupportedOperationException.class, () -> capture.priority(1));
        assertThrows(UnsupportedOperationException.class, () -> capture.proxy(null));
        assertThrows(UnsupportedOperationException.class, () -> capture.authenticator(null));
        assertThrows(UnsupportedOperationException.class, capture::build);
    }
}
