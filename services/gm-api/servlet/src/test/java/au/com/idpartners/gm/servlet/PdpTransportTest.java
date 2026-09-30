/*
 * gm-api's PDP call through platform's OutboundHttp: pdpTimeoutMs bounds the whole exchange however the PDP stalls,
 * the answer is capped, and the PDP's certificate must name its host.
 */
package au.com.idpartners.gm.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class PdpTransportTest {

    private static final int SHORT_MS = 600;

    /** Runs {@code call}, which must be an unavailable PDP about {@code deadlineMs} in, naming one of {@code reasons}. */
    private static PdpClient.PdpUnavailableException failsAt(int deadlineMs, Executable call,
            OutboundHttpException.Reason... reasons) {
        long started = System.nanoTime();
        PdpClient.PdpUnavailableException e = assertThrows(PdpClient.PdpUnavailableException.class, call);
        long elapsedMs = (System.nanoTime() - started) / 1_000_000;
        assertTrue(elapsedMs >= deadlineMs - 50 && elapsedMs < deadlineMs + 1_500,
                "gave up after " + elapsedMs + " ms against a " + deadlineMs + " ms deadline");
        OutboundHttpException cause = assertInstanceOf(OutboundHttpException.class, e.getCause());
        assertTrue(List.of(reasons).contains(cause.reason()), e.getMessage());
        assertTrue(e.getMessage().contains(": " + cause.reason() + ": "), "the reason is in the message: " + e.getMessage());
        return e;
    }

    @Test
    void aPdpThatNeverAnswersIsUnavailableAtPdpTimeoutMs() throws Exception {
        try (OutboundPeer pdp = OutboundPeer.stalling()) {
            failsAt(SHORT_MS, () -> new PdpClient(pdp.url(""), null, SHORT_MS).evaluate(Map.of()),
                    OutboundHttpException.Reason.HEADER_TIMEOUT, OutboundHttpException.Reason.DEADLINE);
            assertEquals("closed", pdp.closed());
        }
    }

    /** Before, pdpTimeoutMs bounded each read, so a PDP sending a byte every 100 ms held the request without end. */
    @Test
    void aPdpThatDribblesIsUnavailableAtPdpTimeoutMs() throws Exception {
        try (OutboundPeer pdp = OutboundPeer.dribbling(200)) {
            failsAt(SHORT_MS, () -> new PdpClient(pdp.url(""), null, SHORT_MS).search(Map.of()),
                    OutboundHttpException.Reason.DEADLINE);
            assertEquals("closed", pdp.closed());
            assertEquals("POST /access/v1/search/resource HTTP/1.1", pdp.requests.poll(1, TimeUnit.SECONDS).requestLine());
        }
    }

    /** Zero once meant no timeout; there is no unbounded wait any more, so it is the 10 s default. */
    @Test
    void aTimeoutOfZeroOrBelowIsTheDefault() throws Exception {
        assertEquals(10_000, PdpClient.DEFAULT_TIMEOUT_MS);
        try (OutboundPeer pdp = OutboundPeer.plain(OutboundPeer.answer(200, "{\"decision\":true}"))) {
            assertEquals(Map.of("decision", true), new PdpClient(pdp.url(""), null, 0).evaluate(Map.of()));
            assertEquals(Map.of("decision", true), new PdpClient(pdp.url(""), null, -1).evaluate(Map.of()));
        }
    }

    /**
     * A pdpTimeoutMs above platform's 10 s head default holds: a PDP that answers after 10.5 s is still heard when the
     * timeout is 12 s. (Before this was fixed, the head default cut every call off at 10 s.)
     */
    @Test
    void aTimeoutAboveThePlatformHeadDefaultHolds() throws Exception {
        try (OutboundPeer pdp = OutboundPeer.plain((n, request, out, socket) -> {
            Thread.sleep(10_500);
            OutboundPeer.write(out, 200, "", "{\"decision\":true}");
        })) {
            assertEquals(Map.of("decision", true), new PdpClient(pdp.url(""), null, 12_000).evaluate(Map.of()));
        }
    }

    /** A blank pdpToken, like none, sends no Authorization header. */
    @Test
    void aBlankTokenSendsNoAuthorization() throws Exception {
        try (OutboundPeer pdp = OutboundPeer.plain(OutboundPeer.answer(200, "{}"))) {
            assertEquals(Map.of(), new PdpClient(pdp.url(""), " ", 2000).evaluate(Map.of()));
            assertEquals(null, pdp.requests.poll(1, TimeUnit.SECONDS).header("Authorization"));
        }
    }

    @Test
    void anAnswerOverTheCapIsAnUnavailablePdp() throws Exception {
        try (OutboundPeer pdp = OutboundPeer.plain(OutboundPeer.oversize(200, 300 * 1024))) {
            PdpClient.PdpUnavailableException e = assertThrows(PdpClient.PdpUnavailableException.class,
                    () -> new PdpClient(pdp.url(""), null, 2000).evaluate(Map.of()));
            assertEquals(OutboundHttpException.Reason.BODY_TOO_LARGE, ((OutboundHttpException) e.getCause()).reason());
        }
    }

    /** The configured PDP may be internal and plaintext; a URL that climbs out of it, or none at all, is not reached. */
    @Test
    void onlyTheConfiguredPdpIsExempt() throws Exception {
        try (OutboundPeer pdp = OutboundPeer.plain(OutboundPeer.answer(200, "{}"))) {
            assertEquals(Map.of(), new PdpClient(pdp.url("/pdp"), null, 2000).evaluate(Map.of()));
            PdpClient.PdpUnavailableException none = assertThrows(PdpClient.PdpUnavailableException.class,
                    () -> new PdpClient(null, null, 2000).evaluate(Map.of()));
            assertEquals(OutboundHttpException.Reason.REFUSED_URL, ((OutboundHttpException) none.getCause()).reason());
            PdpClient.PdpUnavailableException malformed = assertThrows(PdpClient.PdpUnavailableException.class,
                    () -> new PdpClient("http://pdp example", null, 2000).evaluate(Map.of()));
            assertInstanceOf(IllegalArgumentException.class, malformed.getCause());
            assertEquals(1, pdp.requests.size());
        }
    }

    /**
     * TLS: a PDP whose certificate a CA made for this run signed, trusted by that CA alone, answers; one whose
     * certificate names another host is refused in the handshake.
     */
    @Test
    void thePdpsCertificateMustNameItsHost() throws Exception {
        OutboundPeer.TestCa ca = OutboundPeer.TestCa.get();
        TlsTrust trust = TlsTrust.caCertificates(List.of(ca.ca));
        try (OutboundPeer right = OutboundPeer.tls(ca.server("localhost"), OutboundPeer.answer(200, "{}"));
             OutboundPeer wrong = OutboundPeer.tls(ca.server("other.test"), OutboundPeer.answer(200, "{}"))) {
            assertEquals(Map.of(), new PdpClient(right.url(""), "pdp-credential", 5000, trust).evaluate(Map.of()));
            assertEquals("Bearer pdp-credential", right.requests.poll(1, TimeUnit.SECONDS).header("Authorization"));
            PdpClient.PdpUnavailableException e = assertThrows(PdpClient.PdpUnavailableException.class,
                    () -> new PdpClient(wrong.url(""), null, 5000, trust).evaluate(Map.of()));
            assertEquals(OutboundHttpException.Reason.TLS, ((OutboundHttpException) e.getCause()).reason(), e.getMessage());
            PdpClient.PdpUnavailableException untrusted = assertThrows(PdpClient.PdpUnavailableException.class,
                    () -> new PdpClient(right.url(""), null, 5000).evaluate(Map.of()));
            assertEquals(OutboundHttpException.Reason.TLS, ((OutboundHttpException) untrusted.getCause()).reason(),
                    "the JVM's store does not hold the test CA");
        }
    }
}
