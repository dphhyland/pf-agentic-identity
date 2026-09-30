/*
 * The push POST's deadlines through platform's OutboundHttp: a receiver that never answers, or answers and then
 * stalls, costs one bounded attempt; a body over the cap is a failed attempt; TLS names the host.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Deliberately untagged: RFC 8935 says how a SET is posted and what the answers mean, and nothing about how
 * long the transmitter waits. These deadlines are this transmitter's (the plan's S-10 values, constants
 * until S-10 makes them settings), and what they buy is that one receiver cannot hold the delivery loop's
 * one thread, and with it every other stream's delivery, for as long as it keeps a socket open (B5).
 *
 * <p>The receivers are on loopback, which the outbound policy rightly refuses in production; the client here
 * is built with a permissive policy, which is the test seam {@code PushDeliverySsrfTest} covers the other
 * half of.
 */
class PushDeliveryHttpTest {

    private static final Duration SHORT = Duration.ofMillis(600);
    private static final long CAP = 1024;

    private static PushDeliveryService.SetDeliveryClient client() {
        return PushDeliveryService.httpClient(OutboundUrlPolicy.permissive(), SHORT, SHORT, CAP);
    }

    private static long millisSince(long started) {
        return (System.nanoTime() - started) / 1_000_000;
    }

    /** At the deadline: not before it, and not long after. */
    private static void atTheDeadline(long elapsedMs) {
        assertTrue(elapsedMs >= SHORT.toMillis() - 50 && elapsedMs < SHORT.toMillis() + 1_500,
                "gave up after " + elapsedMs + " ms against a " + SHORT.toMillis() + " ms deadline");
    }

    @Test
    void theDeadlinesAreS10sAndTheCapIsSmall() {
        assertEquals(Duration.ofSeconds(2), PushDeliveryService.CONNECT_TIMEOUT);
        assertEquals(Duration.ofSeconds(10), PushDeliveryService.REQUEST_TIMEOUT);
        assertEquals(64 * 1024, PushDeliveryService.RESPONSE_BODY_CAP);
    }

    /** A receiver that accepts the connection and never writes a byte: over at the deadline, and the socket closed. */
    @Test
    void aReceiverThatNeverAnswersCostsOneBoundedAttempt() throws Exception {
        try (OutboundPeer peer = OutboundPeer.stalling()) {
            long started = System.nanoTime();
            PushDeliveryService.DeliveryResult r = client().deliver(peer.url("/set"), "Bearer t", "eyJ.set.jws");
            long elapsedMs = millisSince(started);

            assertEquals(PushDeliveryService.Outcome.RETRYABLE, r.outcome(), r.message());
            assertEquals(0, r.statusCode());
            assertTrue(r.message().startsWith("HEADER_TIMEOUT: ") || r.message().startsWith("DEADLINE: "), r.message());
            atTheDeadline(elapsedMs);
            assertEquals("closed", peer.closed(), "the connection outlived the attempt");
        }
    }

    /**
     * The case {@code HttpRequest.timeout} did not cover: the status line arrives at once and the body a byte every
     * 100 ms. The deadline is on the whole exchange, so this is over at it, and the socket is closed.
     */
    @Test
    void aReceiverThatDribblesItsBodyCostsOneBoundedAttempt() throws Exception {
        try (OutboundPeer peer = OutboundPeer.dribbling(503)) {
            long started = System.nanoTime();
            PushDeliveryService.DeliveryResult r = client().deliver(peer.url("/set"), null, "eyJ.set.jws");
            long elapsedMs = millisSince(started);

            assertEquals(PushDeliveryService.Outcome.RETRYABLE, r.outcome(), r.message());
            assertTrue(r.message().startsWith("DEADLINE: "), r.message());
            atTheDeadline(elapsedMs);
            assertEquals("closed", peer.closed(), "the connection outlived the attempt");
        }
    }

    /**
     * The other way a wait ends: the loop is stopped and its thread interrupted. The attempt gives up within
     * platform's 250 ms read slice, the receiver sees the socket close, and the interrupt stays set for the loop.
     */
    @Test
    void anInterruptEndsTheWaitAndClosesTheConnection() throws Exception {
        Thread caller = Thread.currentThread();
        try (OutboundPeer peer = OutboundPeer.of(null, p -> (n, request, out, socket) -> {
            caller.interrupt();
            p.stallBeforeHead().answer(n, request, out, socket);
        })) {
            PushDeliveryService.SetDeliveryClient patient = PushDeliveryService.httpClient(OutboundUrlPolicy.permissive(),
                    SHORT, Duration.ofSeconds(10), CAP);
            long started = System.nanoTime();
            PushDeliveryService.DeliveryResult r;
            try {
                r = patient.deliver(peer.url("/set"), "Bearer t", "eyJ.set.jws");
            } finally {
                assertTrue(Thread.interrupted(), "the interrupt is kept for the loop to see");
            }
            long elapsedMs = millisSince(started);

            assertEquals(PushDeliveryService.Outcome.RETRYABLE, r.outcome(), r.message());
            assertTrue(r.message().startsWith("IO: "), r.message());
            assertTrue(elapsedMs < 3_000, "gave up " + elapsedMs + " ms in, not at the 10 s deadline");
            assertEquals("closed", peer.closed(), "the exchange ended with the wait");
        }
    }

    /** A 400 is permanent and its body is logged - the first 4096 characters of it, however long it is under the cap. */
    @Test
    void aFourHundredsBodyIsLoggedUpToItsClip() throws Exception {
        String body = "x".repeat(10_000);
        try (OutboundPeer peer = OutboundPeer.plain(OutboundPeer.answer(400, body))) {
            PushDeliveryService.DeliveryResult r = PushDeliveryService.httpClient(OutboundUrlPolicy.permissive(), SHORT,
                    SHORT, 64 * 1024).deliver(peer.url("/set"), null, "eyJ.set.jws");

            assertEquals(PushDeliveryService.Outcome.PERMANENT, r.outcome());
            assertEquals(400, r.statusCode());
            assertEquals(PushDeliveryService.LOGGED_BODY_CHARS, r.message().length());
        }
    }

    /** A body over the cap is a failed attempt, retried, and never read past the cap - whatever the status. */
    @Test
    void aBodyOverTheCapIsARetryNotARead() throws Exception {
        try (OutboundPeer declared = OutboundPeer.plain(OutboundPeer.answer(202, "y".repeat((int) CAP + 1)));
             OutboundPeer chunked = OutboundPeer.plain(OutboundPeer.oversize(400, 1_000_000))) {
            for (OutboundPeer peer : List.of(declared, chunked)) {
                PushDeliveryService.DeliveryResult r = client().deliver(peer.url("/set"), null, "eyJ.set.jws");
                assertEquals(PushDeliveryService.Outcome.RETRYABLE, r.outcome(), r.message());
                assertTrue(r.message().startsWith("BODY_TOO_LARGE: "), r.message());
            }
        }
    }

    /** RFC 8935 §2.2's POST: the SET as the body, its media type, and the stream's authorization header. */
    @Test
    void aTwoOhTwoOrTwoHundredIsDeliveredAndAnythingElseRetried() throws Exception {
        try (OutboundPeer accepted = OutboundPeer.plain(OutboundPeer.answer(202, ""));
             OutboundPeer ok = OutboundPeer.plain(OutboundPeer.answer(200, "{}"));
             OutboundPeer busy = OutboundPeer.plain(OutboundPeer.answer(503, "{}"))) {
            assertEquals(PushDeliveryService.Outcome.DELIVERED,
                    client().deliver(accepted.url("/set"), "Bearer t", "eyJ.set.jws").outcome());
            OutboundPeer.Recorded request = accepted.requests.poll(1, TimeUnit.SECONDS);
            assertEquals("POST /set HTTP/1.1", request.requestLine());
            assertEquals("application/secevent+jwt", request.header("Content-Type"));
            assertEquals("Bearer t", request.header("Authorization"));
            assertEquals("eyJ.set.jws", request.body());
            assertEquals(PushDeliveryService.Outcome.DELIVERED, client().deliver(ok.url("/set"), "", "j").outcome());
            assertEquals(null, ok.requests.poll(1, TimeUnit.SECONDS).header("Authorization"), "a blank header is not sent");
            PushDeliveryService.DeliveryResult r = client().deliver(busy.url("/set"), null, "j");
            assertEquals(PushDeliveryService.Outcome.RETRYABLE, r.outcome());
            assertEquals(503, r.statusCode());
        }
    }

    /** An authorization header that could split the request is refused before anything is sent, and for good. */
    @Test
    void anAuthorizationHeaderThatCouldSplitTheRequestIsPermanent() throws Exception {
        try (OutboundPeer peer = OutboundPeer.plain(OutboundPeer.answer(202, ""))) {
            PushDeliveryService.DeliveryResult r = client().deliver(peer.url("/set"), "Bearer t\r\nX-Evil: 1", "j");
            assertEquals(PushDeliveryService.Outcome.PERMANENT, r.outcome(), r.message());
            assertTrue(peer.requests.isEmpty(), "nothing was sent");
        }
    }

    /**
     * TLS: a receiver whose certificate a CA made for this run signed, trusted by that CA alone, is delivered to; one
     * whose certificate names another host is refused in the handshake, and that is a retry.
     */
    @Test
    void theCertificateMustNameTheReceiversHost() throws Exception {
        OutboundPeer.TestCa ca = OutboundPeer.TestCa.get();
        TlsTrust trust = TlsTrust.caCertificates(List.of(ca.ca));
        try (OutboundPeer right = OutboundPeer.tls(ca.server("localhost"), OutboundPeer.answer(202, ""));
             OutboundPeer wrong = OutboundPeer.tls(ca.server("other.test"), OutboundPeer.answer(202, ""))) {
            PushDeliveryService.SetDeliveryClient tls = PushDeliveryService.httpClient(OutboundUrlPolicy.permissive(), trust,
                    SHORT, Duration.ofSeconds(5), CAP);
            assertEquals(PushDeliveryService.Outcome.DELIVERED, tls.deliver(right.url("/set"), null, "j").outcome());
            PushDeliveryService.DeliveryResult r = tls.deliver(wrong.url("/set"), null, "j");
            assertEquals(PushDeliveryService.Outcome.RETRYABLE, r.outcome(), r.message());
            assertTrue(r.message().startsWith("TLS: "), r.message());
            PushDeliveryService.DeliveryResult untrusted = PushDeliveryService.httpClient(OutboundUrlPolicy.permissive(),
                    SHORT, Duration.ofSeconds(5), CAP).deliver(right.url("/set"), null, "j");
            assertTrue(untrusted.message().startsWith("TLS: "), "the JVM's store does not hold the test CA: " + untrusted.message());
        }
    }

    /**
     * F-0405, pinned as it stands: under the production rules a host that does not resolve is refused, not retried,
     * so its SET is dropped - as before 0.6.0, when the check ran ahead of the JDK client. S-10 is to make it a retry.
     */
    @Test
    void anEndpointWhoseHostDoesNotResolveIsDroppedAsBefore() {
        OutboundUrlPolicy strict = OutboundUrlPolicy.from(name -> null).withResolver(host -> {
            throw new IllegalArgumentException("cannot resolve " + host);
        });
        PushDeliveryService.DeliveryResult r = PushDeliveryService.httpClient(strict, SHORT, SHORT, CAP)
                .deliver("https://receiver.invalid/set", null, "j");
        assertEquals(PushDeliveryService.Outcome.PERMANENT, r.outcome(), r.message());
        PushDeliveryService.DeliveryResult lenient = PushDeliveryService.httpClient(OutboundUrlPolicy.permissive()
                .withResolver(host -> {
                    throw new IllegalArgumentException("cannot resolve " + host);
                }), SHORT, SHORT, CAP).deliver("https://receiver.invalid/set", null, "j");
        assertEquals(PushDeliveryService.Outcome.RETRYABLE, lenient.outcome(), "where the address rule does not apply it is a retry");
        assertTrue(lenient.message().startsWith("UNRESOLVED: "), lenient.message());
    }
}
