/*
 * The push POST's deadlines: a receiver that never answers, or answers and then stalls, costs one bounded
 * attempt; and however much it sends back, only the cap is read.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Deliberately untagged: RFC 8935 says how a SET is posted and what the answers mean, and nothing about how
 * long the transmitter waits. These deadlines are this transmitter's (the plan's S-10 values, a constant
 * until S-5 makes them settings), and what they buy is that one receiver cannot hold the delivery loop's
 * one thread, and with it every other stream's delivery, for as long as it keeps a socket open (B5).
 *
 * <p>The servers are on loopback, which the outbound policy rightly refuses in production; the client here
 * is built with a permissive policy, which is the test seam {@code PushDeliverySsrfTest} covers the other
 * half of.
 */
class PushDeliveryHttpTest {

    private static final Duration SHORT = Duration.ofMillis(400);
    private static final int CAP = 64;

    private static PushDeliveryService.SetDeliveryClient client() {
        return PushDeliveryService.httpClient(OutboundUrlPolicy.permissive(), SHORT, SHORT, CAP);
    }

    /** A receiver that accepts the connection and never writes a byte. */
    @Test
    void aReceiverThatNeverAnswersCostsOneBoundedAttempt() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread accept = new Thread(() -> {
                try (Socket s = silent.accept()) {
                    Thread.sleep(5_000);
                } catch (Exception ignored) {
                    // the client gave up, which is the point
                }
            });
            accept.setDaemon(true);
            accept.start();

            long started = System.nanoTime();
            PushDeliveryService.DeliveryResult r = client().deliver(
                    "http://127.0.0.1:" + silent.getLocalPort() + "/set", "Bearer t", "eyJ.set.jws");
            long elapsedMs = (System.nanoTime() - started) / 1_000_000;

            assertEquals(PushDeliveryService.Outcome.RETRYABLE, r.outcome(), r.message());
            assertTrue(elapsedMs < 3_000, "gave up in " + elapsedMs + " ms, not when the receiver felt like it");
        }
    }

    /**
     * The case {@code HttpRequest.timeout} does not cover: the status line arrives at once and the body
     * never finishes. The deadline is on the exchange, so this is over in {@code SHORT}, not in the five
     * seconds the receiver takes.
     */
    @Test
    void aReceiverThatAnswersAndThenStallsTheBodyCostsOneBoundedAttempt() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        CountDownLatch stalled = new CountDownLatch(1);
        CountDownLatch released = new CountDownLatch(1); // the handler stalls until the test is done with it
        server.createContext("/set", exchange -> {
            exchange.sendResponseHeaders(503, 100);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write("partial...".getBytes(StandardCharsets.UTF_8));
                out.flush();
                stalled.countDown();
                released.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        server.start();
        try {
            long started = System.nanoTime();
            PushDeliveryService.DeliveryResult r = client().deliver(
                    "http://127.0.0.1:" + server.getAddress().getPort() + "/set", null, "eyJ.set.jws");
            long elapsedMs = (System.nanoTime() - started) / 1_000_000;

            assertTrue(stalled.await(1, TimeUnit.SECONDS), "the receiver did send its headers");
            assertEquals(PushDeliveryService.Outcome.RETRYABLE, r.outcome(), r.message());
            assertTrue(elapsedMs < 3_000, "gave up in " + elapsedMs + " ms");
        } finally {
            released.countDown();
            server.stop(0);
        }
    }

    /** Reads one request - its head, then as many body bytes as it declares - so what follows is the next read. */
    private static void readRequest(InputStream in) throws Exception {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int matched = 0; // how much of CRLF CRLF has just been read
        while (matched < 4) {
            int b = in.read();
            if (b < 0) {
                throw new IllegalStateException("the connection closed inside the request head");
            }
            head.write(b);
            boolean expected = b == (matched % 2 == 0 ? '\r' : '\n');
            matched = expected ? matched + 1 : (b == '\r' ? 1 : 0);
        }
        int length = 0;
        for (String line : head.toString(StandardCharsets.ISO_8859_1).split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                length = Integer.parseInt(line.substring("content-length:".length()).trim());
            }
        }
        in.readNBytes(length);
    }

    /**
     * The deadline gives the thread back and the connection goes with it: the receiver sends its status line
     * and part of a body, then waits, and sees the transmitter close the socket at the deadline. Without the
     * cancel in {@code PushDeliveryService.send} the socket stays open after the thread has moved on (tried by
     * hand on JDK 17, 20 and 21.0.12.1, 2026-09-27), and a receiver that stalls every body would hold one of
     * our connections per attempt (U-0077).
     */
    @Test
    void aStalledExchangeIsClosedAtTheDeadline() throws Exception {
        try (ServerSocket receiver = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<String> seen = new CompletableFuture<>();
            Thread accept = new Thread(() -> {
                try (Socket s = receiver.accept()) {
                    readRequest(s.getInputStream());
                    OutputStream out = s.getOutputStream();
                    out.write("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 100\r\n\r\npartial..."
                            .getBytes(StandardCharsets.ISO_8859_1));
                    out.flush();
                    s.setSoTimeout(5_000);
                    try {
                        seen.complete(s.getInputStream().read() == -1 ? "closed" : "a byte after the request");
                    } catch (SocketTimeoutException stillOpen) {
                        seen.complete("still open 5 s after the headers");
                    } catch (SocketException reset) {
                        seen.complete("closed");
                    }
                } catch (Exception e) {
                    seen.completeExceptionally(e);
                }
            });
            accept.setDaemon(true);
            accept.start();

            long started = System.nanoTime();
            PushDeliveryService.DeliveryResult r = client().deliver(
                    "http://127.0.0.1:" + receiver.getLocalPort() + "/set", "Bearer t", "eyJ.set.jws");
            String verdict = seen.get(10, TimeUnit.SECONDS);
            long elapsedMs = (System.nanoTime() - started) / 1_000_000;

            assertEquals(PushDeliveryService.Outcome.RETRYABLE, r.outcome(), r.message());
            assertEquals("closed", verdict, "the connection outlived the attempt");
            assertTrue(elapsedMs < 3_000, "closed " + elapsedMs + " ms after the attempt began");
        }
    }

    /**
     * The other way a wait ends: the loop is stopped and its thread interrupted. {@code send} gives up at once,
     * cancels the exchange - the receiver sees the socket close - and leaves the interrupt set for the loop.
     */
    @Test
    void anInterruptEndsTheWaitAndClosesTheConnection() throws Exception {
        try (ServerSocket receiver = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread caller = Thread.currentThread();
            CompletableFuture<String> seen = new CompletableFuture<>();
            Thread accept = new Thread(() -> {
                try (Socket s = receiver.accept()) {
                    readRequest(s.getInputStream());
                    OutputStream out = s.getOutputStream();
                    out.write("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 100\r\n\r\npartial..."
                            .getBytes(StandardCharsets.ISO_8859_1));
                    out.flush();
                    caller.interrupt();
                    s.setSoTimeout(5_000);
                    try {
                        seen.complete(s.getInputStream().read() == -1 ? "closed" : "a byte after the request");
                    } catch (SocketTimeoutException stillOpen) {
                        seen.complete("still open 5 s after the headers");
                    } catch (SocketException reset) {
                        seen.complete("closed");
                    }
                } catch (Exception e) {
                    seen.completeExceptionally(e);
                }
            });
            accept.setDaemon(true);
            accept.start();
            HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + receiver.getLocalPort() + "/set"))
                    .POST(HttpRequest.BodyPublishers.ofString("eyJ.set.jws")).build();

            long started = System.nanoTime();
            try {
                assertThrows(InterruptedException.class,
                        () -> PushDeliveryService.send(HttpClient.newHttpClient(), request, Duration.ofSeconds(10), CAP));
            } finally {
                assertTrue(Thread.interrupted(), "the interrupt is kept for the loop to see");
            }
            long elapsedMs = (System.nanoTime() - started) / 1_000_000;

            assertTrue(elapsedMs < 3_000, "gave up " + elapsedMs + " ms in, not at the 10 s deadline");
            assertEquals("closed", seen.get(10, TimeUnit.SECONDS), "the exchange was cancelled with the wait");
        }
    }

    /** A 400 is permanent and its body is logged - the first {@code CAP} bytes of it, however long it is. */
    @Test
    void aFourHundredsBodyIsReadUpToTheCap() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        byte[] body = "x".repeat(100_000).getBytes(StandardCharsets.UTF_8);
        server.createContext("/set", exchange -> {
            exchange.sendResponseHeaders(400, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            } catch (Exception ignored) {
                // the client stopped reading at the cap; the rest has nowhere to go
            }
        });
        server.start();
        try {
            PushDeliveryService.DeliveryResult r = client().deliver(
                    "http://127.0.0.1:" + server.getAddress().getPort() + "/set", null, "eyJ.set.jws");

            assertEquals(PushDeliveryService.Outcome.PERMANENT, r.outcome());
            assertEquals(400, r.statusCode());
            assertEquals(CAP, r.message().length(), "the log line carries the cap, not the receiver's 100 kB");
        } finally {
            server.stop(0);
        }
    }

    /** A 202 with no body is what a conforming receiver sends (RFC 8935 §2.2), and it is delivered. */
    @Test
    void aTwoOhTwoIsDelivered() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/set", exchange -> {
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
        });
        server.start();
        try {
            assertEquals(PushDeliveryService.Outcome.DELIVERED, client().deliver(
                    "http://127.0.0.1:" + server.getAddress().getPort() + "/set", "Bearer t", "eyJ.set.jws").outcome());
        } finally {
            server.stop(0);
        }
    }

    // ─────────────────────────────── the capped subscriber, on its own ───────────────────────────────

    private static final class CountingSubscription implements Flow.Subscription {
        final AtomicInteger cancelled = new AtomicInteger();

        @Override
        public void request(long n) {
            // unbounded, as the subscriber asks
        }

        @Override
        public void cancel() {
            this.cancelled.incrementAndGet();
        }
    }

    /** The cap is reached inside one delivery of several buffers: the rest of that delivery is not read. */
    @Test
    void theCapEndsTheBodyMidDeliveryAndCancelsTheRest() throws Exception {
        PushDeliveryService.CappedBody body = new PushDeliveryService.CappedBody(4);
        CountingSubscription subscription = new CountingSubscription();
        body.onSubscribe(subscription);
        ByteBuffer first = ByteBuffer.wrap("abcdef".getBytes(StandardCharsets.UTF_8));
        ByteBuffer second = ByteBuffer.wrap("ghi".getBytes(StandardCharsets.UTF_8));

        body.onNext(List.of(first, second));

        assertEquals("abcd", body.getBody().toCompletableFuture().get(1, TimeUnit.SECONDS));
        assertEquals(1, subscription.cancelled.get());
        assertEquals(3, second.remaining(), "the buffer after the cap was not touched");
    }

    @Test
    void aBodyUnderTheCapIsKeptWholeOnCompletion() throws Exception {
        PushDeliveryService.CappedBody body = new PushDeliveryService.CappedBody(64);
        body.onSubscribe(new CountingSubscription());
        body.onNext(List.of(ByteBuffer.wrap("ab".getBytes(StandardCharsets.UTF_8))));
        body.onNext(List.of(ByteBuffer.wrap("cd".getBytes(StandardCharsets.UTF_8))));
        body.onComplete();
        assertEquals("abcd", body.getBody().toCompletableFuture().get(1, TimeUnit.SECONDS));
    }

    @Test
    void aTransportErrorFailsTheBody() {
        PushDeliveryService.CappedBody body = new PushDeliveryService.CappedBody(64);
        body.onSubscribe(new CountingSubscription());
        body.onError(new java.io.IOException("reset"));
        assertTrue(body.getBody().toCompletableFuture().isCompletedExceptionally());
    }
}
