/*
 * The SSF receiver's three outbound calls - the poll, stream management and the JWKS fetch - through platform's
 * OutboundHttp: each ends at its deadline however the transmitter stalls, reads no more than its cap, and checks the
 * transmitter's certificate names its host.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class ReceiverTransportTest {

    private static final Duration SHORT = Duration.ofMillis(600);

    private static OutboundHttp http(TlsTrust trust, long cap) {
        return OutboundHttp.builder(PollReceiverClient.receiverPolicy()).tls(trust).connectTimeout(SHORT)
                .maxBodyBytes(cap).build();
    }

    private static OutboundHttp http(long cap) {
        return http(TlsTrust.jvmDefault(), cap);
    }

    /** Runs {@code call}, which must fail with {@code reason} at the front of its message, about {@code deadline} in. */
    private static OutboundHttpException failsAt(Duration deadline, Executable call, OutboundHttpException.Reason... reasons)
            throws Exception {
        long started = System.nanoTime();
        OutboundHttpException e = assertThrows(OutboundHttpException.class, call);
        long elapsedMs = (System.nanoTime() - started) / 1_000_000;
        assertTrue(elapsedMs >= deadline.toMillis() - 50 && elapsedMs < deadline.toMillis() + 1_500,
                "gave up after " + elapsedMs + " ms against a " + deadline.toMillis() + " ms deadline");
        assertTrue(List.of(reasons).contains(e.reason()), e.reason() + ": " + e.getMessage());
        assertTrue(e.getMessage().startsWith(e.reason() + ": "), "the log shows the reason first: " + e.getMessage());
        return e;
    }

    private static final OutboundHttpException.Reason[] NO_HEAD = {
        OutboundHttpException.Reason.HEADER_TIMEOUT, OutboundHttpException.Reason.DEADLINE};

    @Test
    void theDeadlinesAndCapsAreTheReceivers() {
        assertEquals(Duration.ofSeconds(1), PollReceiverClient.CONNECT_TIMEOUT);
        assertEquals(Duration.ofSeconds(5), PollReceiverClient.TOTAL_TIMEOUT);
        assertEquals(4L * 1024 * 1024, PollReceiverClient.MAX_BODY_BYTES);
        assertEquals(Duration.ofSeconds(1), ReceiverStreamClient.CONNECT_TIMEOUT);
        assertEquals(Duration.ofSeconds(5), ReceiverStreamClient.TOTAL_TIMEOUT);
        assertEquals(Duration.ofSeconds(1), JwksHttpSource.CONNECT_TIMEOUT);
        assertEquals(Duration.ofMillis(2500), JwksHttpSource.TOTAL_TIMEOUT);
        assertEquals(64 * 1024, JwksHttpSource.MAX_BODY_BYTES);
    }

    // ─────────────────────────────── the deadlines, as shipped ───────────────────────────────

    @Test
    void aJwksEndpointThatNeverAnswersIsGivenUpOnAtTwoAndAHalfSeconds() throws Exception {
        try (OutboundPeer peer = OutboundPeer.stalling()) {
            failsAt(JwksHttpSource.TOTAL_TIMEOUT, () -> JwksHttpSource.of(peer.url("/jwks"), 60, false).keys(true), NO_HEAD);
            assertEquals("closed", peer.closed());
        }
    }

    @Test
    void aJwksEndpointThatDribblesIsGivenUpOnAtTwoAndAHalfSeconds() throws Exception {
        try (OutboundPeer peer = OutboundPeer.dribbling(200)) {
            failsAt(JwksHttpSource.TOTAL_TIMEOUT, () -> JwksHttpSource.of(peer.url("/jwks"), 60, false).keys(true),
                    OutboundHttpException.Reason.DEADLINE);
            assertEquals("closed", peer.closed());
        }
    }

    @Test
    void aPollThatNeverAnswersIsGivenUpOnAtFiveSeconds() throws Exception {
        try (OutboundPeer peer = OutboundPeer.stalling()) {
            failsAt(PollReceiverClient.TOTAL_TIMEOUT, () -> PollReceiverClient.httpTransport(() -> peer.url("/poll"),
                    ReceiverBearer.fixed("t"), false).poll("{}"), NO_HEAD);
        }
    }

    @Test
    void aStreamCallThatNeverAnswersIsGivenUpOnAtFiveSeconds() throws Exception {
        try (OutboundPeer peer = OutboundPeer.stalling()) {
            failsAt(ReceiverStreamClient.TOTAL_TIMEOUT, () -> ReceiverStreamClient.httpTransport(ReceiverBearer.fixed("t"),
                    false).call("GET", peer.url("/ssf/streams"), null), NO_HEAD);
        }
    }

    // ─────────────────────────────── the same, through the seams ───────────────────────────────

    @Test
    void aPollOrStreamCallThatDribblesEndsAtItsDeadline() throws Exception {
        try (OutboundPeer poll = OutboundPeer.dribbling(200); OutboundPeer stream = OutboundPeer.dribbling(200)) {
            failsAt(SHORT, () -> PollReceiverClient.httpTransport(() -> poll.url("/poll"), ReceiverBearer.fixed("t"),
                    http(1 << 20), SHORT).poll("{}"), OutboundHttpException.Reason.DEADLINE);
            failsAt(SHORT, () -> ReceiverStreamClient.httpTransport(ReceiverBearer.fixed("t"), http(1 << 20), SHORT)
                    .call("POST", stream.url("/ssf/streams"), "{}"), OutboundHttpException.Reason.DEADLINE);
            assertEquals("closed", poll.closed());
            assertEquals("closed", stream.closed());
        }
    }

    @Test
    void aStreamCallThatNeverAnswersEndsAtItsDeadline() throws Exception {
        try (OutboundPeer peer = OutboundPeer.stalling()) {
            failsAt(SHORT, () -> ReceiverStreamClient.httpTransport(ReceiverBearer.fixed("t"), http(1 << 20), SHORT)
                    .call("DELETE", peer.url("/ssf/streams?stream_id=s1"), null), NO_HEAD);
            assertEquals("closed", peer.closed());
        }
    }

    /**
     * A stream call that cannot be made is not a configuration the receiver's settings got wrong: it is an exception
     * the supervisor retries ({@code FAILED_DEPENDENCY}), never {@link ReceiverStreamClient.Misconfigured}.
     */
    @Test
    void aTransmitterThatDoesNotAnswerIsADependencyNotAMisconfiguration() throws Exception {
        try (OutboundPeer peer = OutboundPeer.stalling()) {
            ReceiverStreamClient.Plan plan = new ReceiverStreamClient.Plan(peer.url("/.well-known/ssf-configuration"),
                    "https://tx.example", "aud", List.of("urn:e"), null, null);
            Exception e = assertThrows(Exception.class, () -> ReceiverStreamClient.ensure(
                    ReceiverStreamClient.httpTransport(ReceiverBearer.fixed("t"), http(1 << 20), SHORT), plan));
            assertFalse(e instanceof ReceiverStreamClient.Misconfigured, e.toString());
            assertTrue(e instanceof OutboundHttpException, e.toString());
        }
    }

    // ─────────────────────────────── the caps ───────────────────────────────

    @Test
    void eachCallReadsNoMoreThanItsCap() throws Exception {
        try (OutboundPeer big = OutboundPeer.plain(OutboundPeer.oversize(200, 70 * 1024));
             OutboundPeer huge = OutboundPeer.plain(OutboundPeer.oversize(200, 300 * 1024))) {
            OutboundHttpException jwks = assertThrows(OutboundHttpException.class,
                    () -> JwksHttpSource.of(big.url("/jwks"), 60, false).keys(true));
            assertEquals(OutboundHttpException.Reason.BODY_TOO_LARGE, jwks.reason());
            OutboundHttpException stream = assertThrows(OutboundHttpException.class,
                    () -> ReceiverStreamClient.httpTransport(ReceiverBearer.fixed("t"), false).call("GET", huge.url("/s"), null));
            assertEquals(OutboundHttpException.Reason.BODY_TOO_LARGE, stream.reason());
            OutboundHttpException poll = assertThrows(OutboundHttpException.class, () -> PollReceiverClient.httpTransport(
                    () -> big.url("/poll"), ReceiverBearer.fixed("t"), http(64 * 1024), SHORT).poll("{}"));
            assertEquals(OutboundHttpException.Reason.BODY_TOO_LARGE, poll.reason());
        }
    }

    // ─────────────────────────────── the requests ───────────────────────────────

    @Test
    void thePollAndStreamCallsCarryTheBearerAndJson() throws Exception {
        try (OutboundPeer peer = OutboundPeer.plain(OutboundPeer.answer(200, "{\"sets\":{}}"))) {
            assertEquals("{\"sets\":{}}", PollReceiverClient.httpTransport(() -> peer.url("/poll"), ReceiverBearer.fixed("t"),
                    http(1 << 20), SHORT).poll("{\"maxEvents\":1}"));
            OutboundPeer.Recorded poll = peer.requests.poll(1, TimeUnit.SECONDS);
            assertEquals("POST /poll HTTP/1.1", poll.requestLine());
            assertEquals("Bearer t", poll.header("Authorization"));
            assertEquals("application/json", poll.header("Content-Type"));
            assertEquals("{\"maxEvents\":1}", poll.body());

            ReceiverStreamClient.httpTransport(ReceiverBearer.fixed(" "), http(1 << 20), SHORT)
                    .call("PATCH", peer.url("/ssf/streams"), "{\"stream_id\":\"s\"}");
            OutboundPeer.Recorded patch = peer.requests.poll(1, TimeUnit.SECONDS);
            assertEquals("PATCH /ssf/streams HTTP/1.1", patch.requestLine());
            assertEquals(null, patch.header("Authorization"), "a blank token sends no header");
            ReceiverStreamClient.httpTransport(ReceiverBearer.fixed(null), http(1 << 20), SHORT)
                    .call("DELETE", peer.url("/ssf/streams?stream_id=s"), null);
            OutboundPeer.Recorded delete = peer.requests.poll(1, TimeUnit.SECONDS);
            assertEquals("DELETE /ssf/streams?stream_id=s HTTP/1.1", delete.requestLine());
            assertEquals(null, delete.header("Content-Type"));
        }
    }

    // ─────────────────────────────── TLS ───────────────────────────────

    /**
     * A transmitter whose certificate a CA made for this run signed, trusted by that CA alone, answers each call; one
     * whose certificate names another host is refused in the handshake, with the reason TLS.
     */
    @Test
    void theTransmittersCertificateMustNameItsHost() throws Exception {
        OutboundPeer.TestCa ca = OutboundPeer.TestCa.get();
        OutboundHttp trusting = http(TlsTrust.caCertificates(List.of(ca.ca)), 1 << 20);
        String keys = "{\"keys\":[]}";
        try (OutboundPeer right = OutboundPeer.tls(ca.server("localhost"), OutboundPeer.answer(200, keys));
             OutboundPeer wrong = OutboundPeer.tls(ca.server("other.test"), OutboundPeer.answer(200, keys))) {
            assertEquals(List.of(), JwksHttpSource.of(right.url("/jwks"), 60, trusting, Duration.ofSeconds(5)).keys(true));
            assertEquals(keys, PollReceiverClient.httpTransport(() -> right.url("/poll"), ReceiverBearer.fixed("t"), trusting,
                    Duration.ofSeconds(5)).poll("{}"));
            assertEquals(keys, ReceiverStreamClient.httpTransport(ReceiverBearer.fixed("t"), trusting, Duration.ofSeconds(5))
                    .call("GET", right.url("/ssf/streams"), null));

            for (Executable call : List.<Executable>of(
                    () -> JwksHttpSource.of(wrong.url("/jwks"), 60, trusting, Duration.ofSeconds(5)).keys(true),
                    () -> PollReceiverClient.httpTransport(() -> wrong.url("/poll"), ReceiverBearer.fixed("t"), trusting,
                            Duration.ofSeconds(5)).poll("{}"),
                    () -> ReceiverStreamClient.httpTransport(ReceiverBearer.fixed("t"), trusting, Duration.ofSeconds(5))
                            .call("GET", wrong.url("/ssf/streams"), null))) {
                OutboundHttpException e = assertThrows(OutboundHttpException.class, call);
                assertEquals(OutboundHttpException.Reason.TLS, e.reason(), e.getMessage());
            }
            OutboundHttpException untrusted = assertThrows(OutboundHttpException.class,
                    () -> JwksHttpSource.of(right.url("/jwks"), 60, false).keys(true));
            assertEquals(OutboundHttpException.Reason.TLS, untrusted.reason(), "the JVM's store does not hold the test CA");
        }
    }

    /** The receiver's peer may be internal by design: a loopback transmitter over http is reached, pinned. */
    @Test
    void theReceiversRulesAllowAnInternalTransmitter() throws Exception {
        assertEquals("127.0.0.1", PollReceiverClient.receiverPolicy().check("http://127.0.0.1:1/x").addresses().get(0)
                .getHostAddress());
        OutboundHttpException e = assertThrows(OutboundHttpException.class,
                () -> PollReceiverClient.receiverPolicy().check("https://user:pw@tx.example/"));
        assertEquals(OutboundHttpException.Reason.REFUSED_URL, e.reason(), "credentials in the URL are still refused");
    }
}
