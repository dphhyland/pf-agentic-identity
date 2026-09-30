package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.Bulkhead;
import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException.Reason;
import org.junit.jupiter.api.Test;

import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketException;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The PDP call on platform's client (plan S2c): the total deadline holds against a PDP that stalls before its headers
 * and one that dribbles its body, the body cap holds, and each failure is sorted into "unreachable" - which fail-open
 * and the breaker act on - or a refusal.
 */
class PdpTransportTest {

    private static final Map<String, String> JSON = Map.of("Content-Type", "application/json");

    private static PdpTransport transport(int totalMillis) {
        return new PdpTransport(PdpTls.jvmDefault(), totalMillis, true);
    }

    @Test
    void theTotalIsHeldToOneToTenSecondsAndDefaultsToTwoAndAHalf() {
        assertEquals(2_500, PdpTransport.totalMillisOf(0));
        assertEquals(2_500, PdpTransport.totalMillisOf(-5));
        assertEquals(1_000, PdpTransport.totalMillisOf(1));
        assertEquals(1_500, PdpTransport.totalMillisOf(1_500));
        assertEquals(10_000, PdpTransport.totalMillisOf(60_000));
        assertEquals(Duration.ofMillis(2_500), transport(0).total());
        assertEquals(Duration.ofSeconds(1), PdpTransport.CONNECT_TIMEOUT);
        assertEquals(64 * 1024, PdpTransport.MAX_BODY_BYTES);
        assertTrue(transport(0).toString().contains("2500"));
    }

    @Test
    void anAnswerComesBackWithItsStatusBodyAndMediaTypeAndTheRequestAsSent() throws Exception {
        try (StubPdp pdp = StubPdp.plain(StubPdp.json(200, "{\"decision\":true}"))) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("Accept", "application/json");
            headers.put("CLIENT-TOKEN", "s3cret");
            HttpTransport.Response response = transport(2_000).post(pdp.url("/access/v1/evaluation"), "{\"a\":1}", headers);
            assertEquals(200, response.status());
            assertEquals("{\"decision\":true}", response.body());
            assertEquals("application/json", response.contentType());
            StubPdp.Recorded request = pdp.take();
            assertEquals("/access/v1/evaluation", request.path());
            assertEquals("{\"a\":1}", request.body());
            assertEquals("s3cret", request.header("CLIENT-TOKEN"));
            assertEquals("application/json", request.header("Content-Type"));
            assertEquals("close", request.header("Connection"));
        }
        try (StubPdp pdp = StubPdp.plain(StubPdp.json(200, "{}"))) {
            transport(2_000).post(pdp.url("/"), null, null);
            assertEquals("application/json", pdp.take().header("Content-Type"), "no headers: a JSON body still says so");
        }
    }

    @Test
    void aPdpThatStallsBeforeItsHeadersIsUnreachableAtTheTotal() throws Exception {
        try (StubPdp pdp = StubPdp.plain((head, body, out) -> Thread.sleep(6_000))) {
            long start = System.nanoTime();
            PdpUnavailableException e = assertThrows(PdpUnavailableException.class,
                    () -> transport(1_000).post(pdp.url("/"), "{}", JSON));
            long millis = (System.nanoTime() - start) / 1_000_000;
            assertTrue(millis >= 900 && millis < 2_500, "gave up after " + millis + " ms: " + e);
        }
    }

    /** The JDK client's timeout ended at the headers (F-0010): a body sent a byte at a time now stops at the total. */
    @Test
    void aPdpThatDribblesItsBodyIsUnreachableAtTheTotal() throws Exception {
        try (StubPdp pdp = StubPdp.plain((head, body, out) -> {
            StubPdp.write(out, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n");
            for (int i = 0; i < 200; i++) {
                StubPdp.write(out, " ");
                Thread.sleep(100);
            }
        })) {
            long start = System.nanoTime();
            PdpUnavailableException e = assertThrows(PdpUnavailableException.class,
                    () -> transport(1_000).post(pdp.url("/"), "{}", JSON));
            long millis = (System.nanoTime() - start) / 1_000_000;
            assertTrue(millis >= 900 && millis < 2_500, "gave up after " + millis + " ms: " + e);
            assertInstanceOf(OutboundHttpException.class, e.getCause());
            assertEquals(Reason.DEADLINE, ((OutboundHttpException) e.getCause()).reason());
        }
    }

    @Test
    void aBodyOverTheCapIsRefusedAndOneAtTheCapIsRead() throws Exception {
        int cap = (int) PdpTransport.MAX_BODY_BYTES;
        String atCap = "\"" + "a".repeat(cap - 2) + "\"";
        try (StubPdp pdp = StubPdp.plain(StubPdp.json(200, atCap))) {
            assertEquals(cap, transport(3_000).post(pdp.url("/"), "{}", JSON).body().length());
        }
        try (StubPdp pdp = StubPdp.plain(StubPdp.json(200, atCap + " "))) {
            IOException e = assertThrows(IOException.class, () -> transport(3_000).post(pdp.url("/"), "{}", JSON));
            assertFalse(e instanceof PdpUnavailableException, "a PDP that answered too much answered: " + e);
            assertEquals(Reason.BODY_TOO_LARGE, ((OutboundHttpException) e).reason());
        }
        try (StubPdp pdp = StubPdp.plain((head, body, out) -> {
            StubPdp.write(out, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
            String chunk = "a".repeat(8192);
            for (int i = 0; i < 9; i++) {
                StubPdp.write(out, Integer.toHexString(chunk.length()) + "\r\n" + chunk + "\r\n");
            }
            StubPdp.write(out, "0\r\n\r\n");
        })) {
            IOException e = assertThrows(IOException.class, () -> transport(3_000).post(pdp.url("/"), "{}", JSON));
            assertEquals(Reason.BODY_TOO_LARGE, ((OutboundHttpException) e).reason(), "a chunked body is capped as it arrives");
        }
    }

    @Test
    void aRefusedConnectionAndAConnectionClosedWithoutAnAnswerAreUnreachable() throws Exception {
        int closedPort;
        try (java.net.ServerSocket probe = new java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))) {
            closedPort = probe.getLocalPort();
        }
        assertThrows(PdpUnavailableException.class,
                () -> transport(2_000).post("http://127.0.0.1:" + closedPort + "/", "{}", JSON));
        try (StubPdp pdp = StubPdp.plain((head, body, out) -> { })) {
            assertThrows(PdpUnavailableException.class, () -> transport(2_000).post(pdp.url("/"), "{}", JSON),
                    "closed before a status line: the JDK client said EOF, and so does this");
        }
        try (StubPdp pdp = StubPdp.plain((head, body, out) -> StubPdp.write(out,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"decision\""))) {
            assertThrows(PdpUnavailableException.class, () -> transport(2_000).post(pdp.url("/"), "{}", JSON),
                    "closed part-way through the body");
        }
    }

    @Test
    void aMalformedAnswerIsARefusalNotAnOutage() throws Exception {
        try (StubPdp pdp = StubPdp.plain((head, body, out) -> StubPdp.write(out,
                "HTTP/1.1 2x0 connection reset\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"))) {
            IOException e = assertThrows(IOException.class, () -> transport(2_000).post(pdp.url("/"), "{}", JSON));
            assertFalse(e instanceof PdpUnavailableException, e.toString());
        }
        try (StubPdp pdp = StubPdp.plain((head, body, out) -> StubPdp.write(out,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}"))) {
            IOException e = assertThrows(IOException.class, () -> transport(2_000).post(pdp.url("/"), "{}", JSON));
            assertFalse(e instanceof PdpUnavailableException, e.toString());
        }
    }

    @Test
    void aRequestThatCannotBeWrittenIsRefusedAndNothingIsSent() throws Exception {
        try (StubPdp pdp = StubPdp.plain(StubPdp.json(200, "{}"))) {
            IOException e = assertThrows(IOException.class,
                    () -> transport(2_000).post(pdp.url("/"), "{}", Map.of("CLIENT-TOKEN", "a\r\nX-Injected: 1")));
            assertFalse(e instanceof PdpUnavailableException, e.toString());
            IOException bad = assertThrows(IOException.class, () -> transport(2_000).post("http://[not a url", "{}", JSON));
            assertFalse(bad instanceof PdpUnavailableException, bad.toString());
            Thread.sleep(200);
            assertEquals(0, pdp.accepted.get());
        }
    }

    /** Outside development the policy refuses http itself, as PdpUrlPolicy does for the URL: a refusal, not an outage. */
    @Test
    void plaintextIsRefusedWhenHttpIsNotAllowed() throws Exception {
        try (StubPdp pdp = StubPdp.plain(StubPdp.json(200, "{}"))) {
            IOException e = assertThrows(IOException.class,
                    () -> new PdpTransport(PdpTls.jvmDefault(), 2_000, false).post(pdp.url("/"), "{}", JSON));
            assertEquals(Reason.REFUSED_URL, ((OutboundHttpException) e).reason());
        }
    }

    /** Thirty-two calls at once per instance; the thirty-third waits for a place until its deadline, then is unreachable. */
    @Test
    void aFullBulkheadIsUnreachableAtTheDeadline() throws Exception {
        PdpTransport.InstanceBulkhead bulkhead = new PdpTransport.InstanceBulkhead(1);
        Bulkhead.Permit held = bulkhead.enter("http://127.0.0.1:1", Deadline.after(Duration.ofSeconds(1)));
        assertEquals(0, bulkhead.available());
        try (StubPdp pdp = StubPdp.plain(StubPdp.json(200, "{}"))) {
            PdpTransport transport = new PdpTransport(PdpTls.jvmDefault(), 1_000,
                    AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true).build(), bulkhead);
            long start = System.nanoTime();
            PdpUnavailableException e = assertThrows(PdpUnavailableException.class, () -> transport.post(pdp.url("/"), "{}", JSON));
            assertTrue((System.nanoTime() - start) / 1_000_000 >= 900, "waited for a place until the deadline");
            assertEquals(Reason.BULKHEAD_FULL, ((OutboundHttpException) e.getCause()).reason());
            assertEquals(0, pdp.accepted.get(), "a call with no place never connects");
            held.close();
            assertEquals(200, transport.post(pdp.url("/"), "{}", JSON).status());
            assertEquals(1, bulkhead.available(), "the place is given back after the call");
        }
        assertEquals(32, PdpTransport.MAX_CONCURRENT);
        assertEquals(32, new PdpTransport.InstanceBulkhead(PdpTransport.MAX_CONCURRENT).available());
    }

    @Test
    void anInterruptedWaitForAPlaceIsARefusalAndKeepsTheInterrupt() throws Exception {
        PdpTransport.InstanceBulkhead bulkhead = new PdpTransport.InstanceBulkhead(1);
        bulkhead.enter("o", Deadline.after(Duration.ofSeconds(1)));
        Thread.currentThread().interrupt();
        try {
            OutboundHttpException e = assertThrows(OutboundHttpException.class,
                    () -> bulkhead.enter("o", Deadline.after(Duration.ofSeconds(5))));
            assertEquals(Reason.IO, e.reason());
            assertTrue(Thread.currentThread().isInterrupted());
            assertFalse(PdpTransport.classify(e) instanceof PdpUnavailableException);
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void eachReasonIsSortedOnce() {
        Set<Reason> unreachable = EnumSet.of(Reason.UNRESOLVED, Reason.BULKHEAD_FULL, Reason.CONNECT_FAILED,
                Reason.CONNECT_TIMEOUT, Reason.HEADER_TIMEOUT, Reason.DEADLINE, Reason.BUDGET_EXHAUSTED);
        assertEquals(unreachable, PdpTransport.UNREACHABLE);
        for (Reason reason : Reason.values()) {
            OutboundHttpException e = new OutboundHttpException(reason, "x");
            IOException sorted = PdpTransport.classify(e);
            if (unreachable.contains(reason)) {
                assertInstanceOf(PdpUnavailableException.class, sorted, reason.name());
                assertSame(e, sorted.getCause());
            } else {
                assertSame(e, sorted, reason + ": TLS, a malformed or oversized answer, a refused URL - each refuses");
            }
        }
    }

    @Test
    void anIoFailureOrCutShortResponseIsUnreachableOnlyWhenThePeerWentAway() {
        for (Throwable cause : new Throwable[] {new SocketException("Connection reset"), new EOFException(),
                new ClosedChannelException(), new IOException("Connection reset by peer"),
                new IOException("wrapped", new SocketException("Broken pipe")), new NoHttpResponseException(),
                new ConnectionClosedException()}) {
            for (Reason reason : new Reason[] {Reason.IO, Reason.MALFORMED_RESPONSE}) {
                assertInstanceOf(PdpUnavailableException.class,
                        PdpTransport.classify(new OutboundHttpException(reason, "x", cause)), reason + " " + cause);
            }
        }
        for (Throwable cause : new Throwable[] {null, new IOException("the PDP said: connection reset"),
                new InterruptedIOException("interrupted"), new IOException((String) null), new IllegalStateException()}) {
            OutboundHttpException e = new OutboundHttpException(Reason.IO, "x", cause);
            assertSame(e, PdpTransport.classify(e), String.valueOf(cause));
        }
        OutboundHttpException tls = new OutboundHttpException(Reason.TLS, "x", new SocketException("reset"));
        assertSame(tls, PdpTransport.classify(tls), "a TLS failure refuses whatever lies under it");
        IOException a = new IOException("a");
        IOException b = new IOException("b");
        a.initCause(b);
        b.initCause(a);
        assertFalse(PdpTransport.peerWentAway(a), "a cycle of causes ends");
    }

    /** HttpCore's two exceptions as the relocation leaves them: matched by simple name. */
    static final class NoHttpResponseException extends IOException { }

    static final class ConnectionClosedException extends IOException { }
}
