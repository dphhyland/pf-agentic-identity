package com.pingidentity.ps.oidf.platform.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException.Reason;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** HostBulkhead: places per origin, a wait bounded by the caller's deadline, and every place given back. */
class HostBulkheadTest {

    private static final String A = "https://a.example:443";
    private static final String B = "https://b.example:443";

    private static Deadline millis(long millis) {
        return Deadline.after(Duration.ofMillis(millis));
    }

    @Test
    void aBulkheadHasAtLeastOnePlace() {
        assertThrows(IllegalArgumentException.class, () -> new HostBulkhead(0));
        assertEquals(HostBulkhead.DEFAULT_MAX_PER_ORIGIN, HostBulkhead.withDefaults().maxPerOrigin());
        assertEquals(32, HostBulkhead.DEFAULT_MAX_PER_ORIGIN);
        assertEquals(1, new HostBulkhead(1).maxPerOrigin());
    }

    @Test
    void aFullOriginRefusesAtTheDeadlineAndLeavesNothingBehind() throws Exception {
        HostBulkhead bulkhead = new HostBulkhead(2);
        Bulkhead.Permit first = bulkhead.enter(A, millis(1000));
        Bulkhead.Permit second = bulkhead.enter(A, millis(1000));
        assertEquals(2, bulkhead.inFlight(A));

        long started = System.nanoTime();
        OutboundHttpException e = assertThrows(OutboundHttpException.class, () -> bulkhead.enter(A, millis(150)));
        long waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
        assertEquals(Reason.BULKHEAD_FULL, e.reason());
        assertTrue(e.getMessage().contains(A) && e.getMessage().contains("2 places"), e.getMessage());
        assertTrue(waited >= 140, "waited for a place until the deadline, " + waited + " ms");
        assertEquals(2, bulkhead.inFlight(A), "the refused request no longer counts");

        first.close();
        second.close();
        assertEquals(0, bulkhead.inFlight(A));
        assertEquals(0, bulkhead.origins(), "an origin with nothing in flight leaves the table");
        assertTrue(bulkhead.toString().contains("2 per origin"), bulkhead.toString());
    }

    @Test
    void anExpiredDeadlineTakesAFreePlaceButNeverWaits() throws Exception {
        HostBulkhead bulkhead = new HostBulkhead(1);
        Deadline expired = Deadline.after(Duration.ZERO);
        try (Bulkhead.Permit held = bulkhead.enter(A, expired)) {
            assertEquals(1, bulkhead.inFlight(A));
            assertEquals(Reason.BULKHEAD_FULL, assertThrows(OutboundHttpException.class, () -> bulkhead.enter(A, expired)).reason());
        }
        assertEquals(0, bulkhead.origins());
    }

    @Test
    void originsCountSeparately() throws Exception {
        HostBulkhead bulkhead = new HostBulkhead(1);
        try (Bulkhead.Permit a = bulkhead.enter(A, millis(100)); Bulkhead.Permit b = bulkhead.enter(B, millis(100))) {
            assertEquals(1, bulkhead.inFlight(A));
            assertEquals(1, bulkhead.inFlight(B));
            assertEquals(2, bulkhead.origins());
            assertEquals(0, bulkhead.inFlight("https://c.example:443"));
        }
        assertEquals(0, bulkhead.origins());
    }

    @Test
    void closingAPermitTwiceGivesBackOnePlace() throws Exception {
        HostBulkhead bulkhead = new HostBulkhead(1);
        Bulkhead.Permit permit = bulkhead.enter(A, millis(100));
        permit.close();
        permit.close();
        try (Bulkhead.Permit next = bulkhead.enter(A, millis(100))) {
            assertEquals(Reason.BULKHEAD_FULL, assertThrows(OutboundHttpException.class, () -> bulkhead.enter(A, millis(50))).reason(),
                    "a second close must not have made a second place");
        }
        assertEquals(0, bulkhead.origins());
    }

    @Test
    void closingAPermitTwiceWhileAnotherIsHeldLeavesTheOtherCounted() throws Exception {
        // With a second request to the same origin inside, a second close that gave back again would free two places
        // and count the holder out, dropping the entry while it is still inside and letting max + 1 requests in.
        HostBulkhead bulkhead = new HostBulkhead(2);
        try (Bulkhead.Permit held = bulkhead.enter(A, millis(100))) {
            Bulkhead.Permit twice = bulkhead.enter(A, millis(100));
            twice.close();
            twice.close();
            assertEquals(1, bulkhead.inFlight(A), "the holder still counts");
            assertEquals(1, bulkhead.origins());
            try (Bulkhead.Permit next = bulkhead.enter(A, millis(100))) {
                assertEquals(2, bulkhead.inFlight(A));
                assertEquals(Reason.BULKHEAD_FULL, assertThrows(OutboundHttpException.class, () -> bulkhead.enter(A, millis(50))).reason(),
                        "two places, both taken: the double close made no third");
            }
        }
        assertEquals(0, bulkhead.origins());
    }

    @Test
    void aWaitingRequestGetsThePlaceWhenItIsGivenBack() throws Exception {
        HostBulkhead bulkhead = new HostBulkhead(1);
        Bulkhead.Permit held = bulkhead.enter(A, millis(1000));
        CompletableFuture<Bulkhead.Permit> waiting = CompletableFuture.supplyAsync(() -> {
            try {
                return bulkhead.enter(A, millis(5000));
            } catch (OutboundHttpException e) {
                throw new IllegalStateException(e);
            }
        });
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (bulkhead.inFlight(A) < 2 && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertEquals(2, bulkhead.inFlight(A), "one holds, one waits");
        held.close();
        waiting.get(5, TimeUnit.SECONDS).close();
        assertEquals(0, bulkhead.origins());
    }

    @Test
    void anInterruptedWaitIsARefusalThatKeepsTheInterrupt() throws Exception {
        HostBulkhead bulkhead = new HostBulkhead(1);
        try (Bulkhead.Permit held = bulkhead.enter(A, millis(1000))) {
            AtomicReference<Object> outcome = new AtomicReference<>();
            CountDownLatch done = new CountDownLatch(1);
            Thread waiter = new Thread(() -> {
                try {
                    bulkhead.enter(A, millis(10_000));
                    outcome.set("entered");
                } catch (OutboundHttpException e) {
                    outcome.set(e.reason() + " interrupted=" + Thread.currentThread().isInterrupted());
                }
                done.countDown();
            });
            waiter.start();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (bulkhead.inFlight(A) < 2 && System.nanoTime() < deadline) {
                Thread.onSpinWait();
            }
            waiter.interrupt();
            assertTrue(done.await(5, TimeUnit.SECONDS));
            assertEquals("BULKHEAD_FULL interrupted=true", outcome.get());
            assertEquals(1, bulkhead.inFlight(A));
        }
        assertEquals(0, bulkhead.origins());
    }

    @Test
    void outboundHttpGivesThePlaceBackWhenTheExchangeFails() throws Exception {
        HostBulkhead bulkhead = new HostBulkhead(1);
        AddressPolicy local = AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true).build();
        OutboundHttp http = OutboundHttp.builder(local).bulkhead(bulkhead).build();
        int closedPort;
        try (ServerSocket probe = new ServerSocket(0)) {
            closedPort = probe.getLocalPort();
        }
        String refused = "http://127.0.0.1:" + closedPort + "/";
        assertEquals(Reason.CONNECT_FAILED,
                assertThrows(OutboundHttpException.class, () -> http.get(refused, "*/*", millis(2000))).reason());
        assertEquals(0, bulkhead.origins(), "a failed connect gives its place back");

        try (TestServer server = TestServer.plain(TestServer.raw("HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n"))) {
            String url = "http://127.0.0.1:" + server.port() + "/";
            assertEquals(Reason.MALFORMED_RESPONSE,
                    assertThrows(OutboundHttpException.class, () -> http.get(url, "*/*", millis(2000))).reason());
            assertEquals(0, bulkhead.origins(), "a malformed response gives its place back");
            server.handler(TestServer.ok("fine"));
            assertEquals("fine", http.get(url, "*/*", millis(2000)).bodyText(), "and the one place is free again");
            assertEquals(0, bulkhead.origins());
        }
    }

    @Test
    void outboundHttpRefusesWhenTheOriginIsFullWithoutConnecting() throws Exception {
        HostBulkhead bulkhead = new HostBulkhead(1);
        AddressPolicy local = AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true).build();
        OutboundHttp http = OutboundHttp.builder(local).bulkhead(bulkhead).build();
        try (TestServer server = TestServer.plain(TestServer.ok("fine"))) {
            String url = "http://127.0.0.1:" + server.port() + "/";
            try (Bulkhead.Permit held = bulkhead.enter("http://127.0.0.1:" + server.port(), millis(1000))) {
                assertEquals(Reason.BULKHEAD_FULL,
                        assertThrows(OutboundHttpException.class, () -> http.get(url, "*/*", millis(100))).reason());
            }
            assertEquals(0, server.accepted.get(), "a refused request never connects");
            assertEquals("fine", http.get(url, "*/*", millis(2000)).bodyText());
        }
    }
}
