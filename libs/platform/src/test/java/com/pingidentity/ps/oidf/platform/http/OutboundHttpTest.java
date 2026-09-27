package com.pingidentity.ps.oidf.platform.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException.Reason;
import com.pingidentity.ps.oidf.platform.http.OutboundRequest.Method;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** OutboundHttp over plain HTTP against a local server: methods, statuses, framing, limits and deadlines. */
class OutboundHttpTest {

    private static final AddressPolicy LOCAL = AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true).build();

    private static OutboundHttp client() {
        return OutboundHttp.builder(LOCAL).build();
    }

    private static String url(TestServer server) {
        return "http://127.0.0.1:" + server.port() + "/path/x?q=1&r=%20";
    }

    private static Deadline seconds(long seconds) {
        return Deadline.after(Duration.ofSeconds(seconds));
    }

    private static OutboundHttpException refused(TestServer.Handler handler) throws Exception {
        try (TestServer server = TestServer.plain(handler)) {
            return assertThrows(OutboundHttpException.class, () -> client().get(url(server), "*/*", seconds(5)));
        }
    }

    private static OutboundResponse fetch(TestServer.Handler handler) throws Exception {
        try (TestServer server = TestServer.plain(handler)) {
            return client().get(url(server), "*/*", seconds(5));
        }
    }

    @Test
    void getReturnsStatusHeadersAndBodyAndSendsTheFramingHeaders() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.ok("hello"))) {
            OutboundResponse response = client().get(url(server), "application/json", seconds(5));
            assertEquals(200, response.status());
            assertEquals("OK", response.reason());
            assertTrue(response.successful());
            assertEquals("hello", response.bodyText());
            assertEquals("text/plain", response.header("content-type").orElseThrow());
            assertEquals(List.of("text/plain"), response.headers("Content-Type"));
            assertTrue(response.header("X-Absent").isEmpty());
            assertEquals("127.0.0.1", response.remoteAddress().getAddress().getHostAddress());
            assertTrue(response.toString().contains("200"));
            TestServer.Recorded request = server.take();
            assertEquals("GET /path/x?q=1&r=%20 HTTP/1.1", request.requestLine());
            assertEquals("127.0.0.1:" + server.port(), request.header("Host"));
            assertEquals("close", request.header("Connection"));
            assertEquals("application/json", request.header("Accept"));
            assertEquals("pf-agentic-identity", request.header("User-Agent"));
            assertNull(request.header("Content-Length"));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"POST", "PUT", "PATCH", "DELETE"})
    void everyMethodCarriesHeadersAndABody(String name) throws Exception {
        try (TestServer server = TestServer.plain(TestServer.echo())) {
            OutboundRequest request = OutboundRequest.builder(Method.valueOf(name), URI.create(url(server)))
                    .header("X-Trace", "abc").header("User-Agent", "custom/1").body("text/plain", "payload").build();
            OutboundResponse response = client().send(request, seconds(5));
            assertEquals(200, response.status());
            assertEquals(name.toLowerCase(java.util.Locale.ROOT), response.header("X-Method").orElseThrow());
            TestServer.Recorded recorded = server.take();
            assertEquals("abc", recorded.header("X-Trace"));
            assertEquals("custom/1", recorded.header("User-Agent"));
            assertEquals("7", recorded.header("Content-Length"));
            assertEquals("text/plain", recorded.header("Content-Type"));
            assertEquals("payload", new String(recorded.body(), StandardCharsets.UTF_8));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"POST", "PUT", "PATCH"})
    void aBodilessPostPutOrPatchSaysItsLengthIsZero(String name) throws Exception {
        try (TestServer server = TestServer.plain(TestServer.echo())) {
            client().send(OutboundRequest.builder(Method.valueOf(name), URI.create(url(server))).build(), seconds(5));
            assertEquals("0", server.take().header("Content-Length"));
        }
    }

    @Test
    void aBodilessDeleteSendsNoLength() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.echo())) {
            client().send(OutboundRequest.builder(Method.DELETE, URI.create(url(server))).build(), seconds(5));
            assertNull(server.take().header("Content-Length"));
        }
    }

    @Test
    void nonAsciiInThePathAndQueryIsSentAsPercentEncodedUtf8() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.echo())) {
            client().get("http://127.0.0.1:" + server.port() + "/\u00e9t\u00e9/\u010d?q=\u00e9", "*/*", seconds(5));
            assertEquals("GET /%C3%A9t%C3%A9/%C4%8D?q=%C3%A9 HTTP/1.1", server.take().requestLine());
        }
    }

    @Test
    void aPathlessUrlAsksForTheRoot() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.echo())) {
            client().get("http://127.0.0.1:" + server.port(), "*/*", seconds(5));
            assertEquals("GET / HTTP/1.1", server.take().requestLine());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 302, 400, 404, 500, 503})
    void anyStatusIsReturnedNotThrownAndRedirectsAreNotFollowed(int status) throws Exception {
        try (TestServer server = TestServer.plain(TestServer.raw("HTTP/1.1 " + status + " Whatever\r\nLocation: http://127.0.0.1:1/\r\n"
                + "Content-Length: 4\r\n\r\nnope"))) {
            OutboundResponse response = client().get(url(server), "*/*", seconds(5));
            assertEquals(status, response.status());
            assertFalse(response.successful());
            assertEquals("nope", response.bodyText());
            assertEquals(1, server.accepted.get());
        }
    }

    @Test
    void aStatusBelowTwoHundredIsNotSuccessful() throws Exception {
        assertFalse(new OutboundResponse(199, "", List.of(), new byte[0], null).successful());
    }

    @ParameterizedTest
    @ValueSource(ints = {204, 304})
    void noBodyIsReadForNoContentOrNotModifiedEvenWhenTheServerLeavesTheConnectionOpen(int status) throws Exception {
        OutboundResponse response = fetch((request, out) -> {
            TestServer.write(out, "HTTP/1.1 " + status + " X\r\nETag: \"1\"\r\n\r\n");
            Thread.sleep(3000);
        });
        assertEquals(status, response.status());
        assertEquals(0, response.body().length);
    }

    @Test
    void aZeroLengthBodyIsEmpty() throws Exception {
        assertEquals(0, fetch(TestServer.raw("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")).body().length);
    }

    @Test
    void anEmptyReasonPhraseIsEmpty() throws Exception {
        assertEquals("", fetch(TestServer.raw("HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n")).reason());
    }

    @Test
    void anHttp10ResponseDelimitedByCloseIsRead() throws Exception {
        OutboundResponse response = fetch(TestServer.raw("HTTP/1.0 200 OK\r\n\r\nuntil close"));
        assertEquals("until close", response.bodyText());
    }

    @Test
    void aDeclaredLengthOverTheCapIsRefusedBeforeTheBodyIsRead() throws Exception {
        OutboundHttpException e = refused((request, out) -> {
            TestServer.write(out, "HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n");
            Thread.sleep(3000);
        });
        assertEquals(Reason.BODY_TOO_LARGE, e.reason());
        assertTrue(e.getMessage().contains("declares"), e.getMessage());
    }

    @Test
    void aRequestCapOverridesTheClientCap() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.ok("0123456789"))) {
            OutboundRequest request = OutboundRequest.builder(Method.GET, URI.create(url(server))).maxBodyBytes(9).build();
            assertEquals(Reason.BODY_TOO_LARGE, assertThrows(OutboundHttpException.class,
                    () -> client().send(request, seconds(5))).reason());
        }
        try (TestServer server = TestServer.plain(TestServer.ok("0123456789"))) {
            OutboundHttp small = OutboundHttp.builder(LOCAL).maxBodyBytes(10).build();
            assertEquals("0123456789", small.get(url(server), "*/*", seconds(5)).bodyText());
        }
    }

    @Test
    void aChunkedBodyOverTheCapIsRefusedAsItPassesIt() throws Exception {
        StringBuilder chunks = new StringBuilder("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        for (int i = 0; i < 70; i++) {
            chunks.append("1000\r\n").append("x".repeat(4096)).append("\r\n");
        }
        chunks.append("0\r\n\r\n");
        assertEquals(Reason.BODY_TOO_LARGE, refused(TestServer.raw(chunks.toString())).reason());
    }

    @Test
    void aBodyThatKeepsComingIsRefusedAtTheCapWithoutWaitingForTheDeadline() throws Exception {
        for (String framing : new String[] {"Transfer-Encoding: chunked\r\n", "Content-Length: 99999\r\n", ""}) {
            boolean chunked = framing.startsWith("Transfer");
            try (TestServer server = TestServer.plain((request, out) -> {
                TestServer.write(out, "HTTP/1.1 200 OK\r\n" + framing + "\r\n");
                String piece = "z".repeat(4000);
                for (int i = 0; i < 25; i++) {
                    TestServer.write(out, chunked ? Integer.toHexString(piece.length()) + "\r\n" + piece + "\r\n" : piece);
                }
                Thread.sleep(4000);
            })) {
                OutboundHttp small = OutboundHttp.builder(LOCAL).maxBodyBytes(50_000).build();
                long start = System.nanoTime();
                OutboundHttpException e = assertThrows(OutboundHttpException.class,
                        () -> small.get(url(server), "*/*", seconds(3)));
                long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;
                assertEquals(Reason.BODY_TOO_LARGE, e.reason(), framing);
                assertTrue(elapsedMillis < 1000, framing + " took " + elapsedMillis + " ms");
            }
        }
    }

    @Test
    void aCloseDelimitedBodyOverTheCapIsRefused() throws Exception {
        assertEquals(Reason.BODY_TOO_LARGE, refused(TestServer.raw("HTTP/1.1 200 OK\r\n\r\n" + "y".repeat(300 * 1024))).reason());
    }

    @Test
    void aLengthLongerThanTheBodyIsATruncatedResponse() throws Exception {
        OutboundHttpException e = refused(TestServer.raw("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly ten.."));
        assertEquals(Reason.MALFORMED_RESPONSE, e.reason());
    }

    @Test
    void aLengthShorterThanTheBodyReadsOnlyTheDeclaredBytes() throws Exception {
        assertEquals("short", fetch(TestServer.raw("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nshort and then some")).bodyText());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: 5 5\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 abc OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 99 Low\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 700 High\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.5 200 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/0.9 200 OK\r\nContent-Length: 0\r\n\r\n",
        "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        "hello world\r\n\r\n",
        "",
        "HTTP/1.1 200 OK\r\nNo colon here\r\nContent-Length: 0\r\n\r\n",
        // Followed by a well-formed 200, so only the explicit refusal of a 101 can make this fail.
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffffff\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloX\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-5\r\nhello\r\n0\r\n\r\n",
    })
    void aMalformedOrTruncatedResponseIsRefused(String raw) throws Exception {
        OutboundHttpException e = refused(TestServer.raw(raw));
        assertEquals(Reason.MALFORMED_RESPONSE, e.reason(), () -> e.getMessage() + " for " + raw.replace("\r\n", "|"));
    }

    @Test
    void chunkedWithExtensionsAndTrailersIsRead() throws Exception {
        OutboundResponse response = fetch(TestServer.raw("HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n"
                + "5;name=value\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n"));
        assertEquals("hello world", response.bodyText());
    }

    @Test
    void tooManyHeadersAreRefused() throws Exception {
        StringBuilder head = new StringBuilder("HTTP/1.1 200 OK\r\n");
        for (int i = 0; i <= OutboundHttp.MAX_HEADER_COUNT; i++) {
            head.append("X-").append(i).append(": v\r\n");
        }
        assertEquals(Reason.MALFORMED_RESPONSE, refused(TestServer.raw(head + "Content-Length: 0\r\n\r\n")).reason());
    }

    @Test
    void exactlyTheMostHeadersIsAccepted() throws Exception {
        StringBuilder head = new StringBuilder("HTTP/1.1 200 OK\r\n");
        for (int i = 1; i < OutboundHttp.MAX_HEADER_COUNT; i++) {
            head.append("X-").append(i).append(": v\r\n");
        }
        assertEquals(OutboundHttp.MAX_HEADER_COUNT, fetch(TestServer.raw(head + "Content-Length: 0\r\n\r\n")).headers().size());
    }

    @Test
    void aHeaderLineOverTheLimitIsRefused() throws Exception {
        assertEquals(Reason.MALFORMED_RESPONSE, refused(TestServer.raw("HTTP/1.1 200 OK\r\nX-Big: "
                + "a".repeat(OutboundHttp.MAX_LINE_LENGTH) + "\r\nContent-Length: 0\r\n\r\n")).reason());
    }

    @Test
    void aStatusLineOverTheLimitIsRefused() throws Exception {
        assertEquals(Reason.MALFORMED_RESPONSE, refused(TestServer.raw("HTTP/1.1 200 "
                + "a".repeat(OutboundHttp.MAX_LINE_LENGTH) + "\r\nContent-Length: 0\r\n\r\n")).reason());
    }

    @Test
    void interimResponsesAreSkipped() throws Exception {
        OutboundResponse response = fetch(TestServer.raw("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
                + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
        assertEquals(200, response.status());
        assertEquals("ok", response.bodyText());
    }

    @Test
    void tooManyInterimResponsesAreRefused() throws Exception {
        String interim = "HTTP/1.1 100 Continue\r\n\r\n".repeat(OutboundHttp.MAX_INTERIM_RESPONSES + 1);
        assertEquals(Reason.MALFORMED_RESPONSE,
                refused(TestServer.raw(interim + "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")).reason());
    }

    @Test
    void theMostInterimResponsesAreAccepted() throws Exception {
        String interim = "HTTP/1.1 100 Continue\r\n\r\n".repeat(OutboundHttp.MAX_INTERIM_RESPONSES);
        assertEquals(200, fetch(TestServer.raw(interim + "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")).status());
    }

    @Test
    void aBodySentOneByteAtATimeStopsAtTheTotalDeadline() throws Exception {
        try (TestServer server = TestServer.plain((request, out) -> {
            TestServer.write(out, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
            for (int i = 0; i < 100; i++) {
                Thread.sleep(200);
                TestServer.write(out, "x");
            }
        })) {
            long start = System.nanoTime();
            OutboundHttpException e = assertThrows(OutboundHttpException.class,
                    () -> client().get(url(server), "*/*", Deadline.after(Duration.ofMillis(1200))));
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;
            assertEquals(Reason.DEADLINE, e.reason(), e.getMessage());
            assertTrue(elapsedMillis >= 1100 && elapsedMillis < 2000, "took " + elapsedMillis + " ms");
        }
    }

    @Test
    void headersSentOneByteAtATimeStopAtTheHeaderDeadline() throws Exception {
        try (TestServer server = TestServer.plain((request, out) -> {
            for (char c : "HTTP/1.1 200 OK\r\nX-Slow: yes\r\nContent-Length: 0\r\n\r\n".toCharArray()) {
                Thread.sleep(100);
                TestServer.write(out, String.valueOf(c));
            }
        })) {
            OutboundRequest request = OutboundRequest.builder(Method.GET, URI.create(url(server)))
                    .headerTimeout(Duration.ofMillis(700)).build();
            long start = System.nanoTime();
            OutboundHttpException e = assertThrows(OutboundHttpException.class, () -> client().send(request, seconds(10)));
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;
            assertEquals(Reason.HEADER_TIMEOUT, e.reason(), e.getMessage());
            assertTrue(elapsedMillis < 1500, "took " + elapsedMillis + " ms");
        }
    }

    @Test
    void aHeaderTimeoutThatOutlastsTheTotalIsReportedAsTheDeadline() throws Exception {
        try (TestServer server = TestServer.plain((request, out) -> Thread.sleep(3000))) {
            OutboundHttpException e = assertThrows(OutboundHttpException.class,
                    () -> client().get(url(server), "*/*", Deadline.after(Duration.ofMillis(500))));
            assertEquals(Reason.DEADLINE, e.reason());
        }
    }

    @Test
    void theClientHeaderTimeoutAppliesWhenTheRequestSetsNone() throws Exception {
        try (TestServer server = TestServer.plain((request, out) -> Thread.sleep(3000))) {
            OutboundHttp impatient = OutboundHttp.builder(LOCAL).headerTimeout(Duration.ofMillis(300))
                    .connectTimeout(Duration.ofSeconds(1)).build();
            assertEquals(Reason.HEADER_TIMEOUT, assertThrows(OutboundHttpException.class,
                    () -> impatient.get(url(server), "*/*", seconds(5))).reason());
        }
    }

    @Test
    void aDeadlineThatHasAlreadyPassedSendsNothing() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.ok("x"))) {
            OutboundHttpException e = assertThrows(OutboundHttpException.class,
                    () -> client().get(url(server), "*/*", Deadline.after(Duration.ZERO)));
            assertEquals(Reason.DEADLINE, e.reason());
            assertEquals(0, server.accepted.get());
        }
    }

    @Test
    void aDeadlineSpentResolvingSendsNothing() throws Exception {
        AtomicInteger clock = new AtomicInteger();
        Deadline deadline = Deadline.after(Duration.ofNanos(10), () -> clock.getAndAdd(5));
        AddressPolicy slow = AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true)
                .resolver(host -> new InetAddress[] {InetAddress.getByName("127.0.0.1")}).build();
        OutboundHttpException e = assertThrows(OutboundHttpException.class,
                () -> OutboundHttp.builder(slow).build().get("http://slow.test:1/", "*/*", deadline));
        assertEquals(Reason.DEADLINE, e.reason());
        assertTrue(e.getMessage().contains("resolving"), e.getMessage());
    }

    @Test
    void aClosedPortIsAConnectFailure() throws Exception {
        int port;
        try (TestServer server = TestServer.plain(TestServer.ok("x"))) {
            port = server.port();
        }
        OutboundHttpException e = assertThrows(OutboundHttpException.class,
                () -> client().get("http://127.0.0.1:" + port + "/", "*/*", seconds(5)));
        assertEquals(Reason.CONNECT_FAILED, e.reason());
    }

    @Test
    void theNextCheckedAddressIsTriedWhenOneRefuses() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.ok("second"))) {
            AddressPolicy two = AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true)
                    .resolver(host -> new InetAddress[] {InetAddress.getByName("::1"), InetAddress.getByName("127.0.0.1")})
                    .build();
            OutboundResponse response = OutboundHttp.builder(two).build().get("http://two.test:" + server.port() + "/", "*/*", seconds(5));
            assertEquals("second", response.bodyText());
        }
    }

    @Test
    void aConnectDeadlineAlreadySpentIsAConnectTimeout() throws Exception {
        AddressPolicy.Target target = LOCAL.check("http://127.0.0.1:9/");
        OutboundHttpException e = assertThrows(OutboundHttpException.class,
                () -> client().connect(target, Deadline.after(Duration.ZERO), seconds(5)));
        assertEquals(Reason.CONNECT_TIMEOUT, e.reason());
        OutboundHttpException total = assertThrows(OutboundHttpException.class,
                () -> client().connect(target, Deadline.after(Duration.ZERO), Deadline.after(Duration.ZERO)));
        assertEquals(Reason.DEADLINE, total.reason());
    }

    @Test
    void aBudgetIsSpentOneRequestAtATime() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.ok("x"))) {
            Budget budget = Budget.of(Duration.ofSeconds(5), 1);
            OutboundRequest request = OutboundRequest.get(url(server)).build();
            assertEquals(200, client().send(request, budget).status());
            OutboundHttpException e = assertThrows(OutboundHttpException.class, () -> client().send(request, budget));
            assertEquals(Reason.BUDGET_EXHAUSTED, e.reason());
            assertEquals(1, server.accepted.get());
        }
    }

    @Test
    void theBulkheadIsAskedForTheOriginAndItsPermitIsGivenBack() throws Exception {
        List<String> origins = new ArrayList<>();
        AtomicInteger closed = new AtomicInteger();
        Bulkhead counting = (origin, deadline) -> {
            origins.add(origin);
            return closed::incrementAndGet;
        };
        try (TestServer server = TestServer.plain(TestServer.raw("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ntruncated"
                .substring(0, 40)))) {
            OutboundHttp http = OutboundHttp.builder(LOCAL).bulkhead(counting).build();
            assertThrows(OutboundHttpException.class, () -> http.get(url(server), "*/*", seconds(5)));
            assertEquals(List.of("http://127.0.0.1:" + server.port()), origins);
            assertEquals(1, closed.get());
        }
    }

    @Test
    void aFullBulkheadRefusesWithoutConnecting() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.ok("x"))) {
            Bulkhead full = (origin, deadline) -> {
                throw new OutboundHttpException(Reason.BULKHEAD_FULL, "full");
            };
            OutboundHttp http = OutboundHttp.builder(LOCAL).bulkhead(full).build();
            assertEquals(Reason.BULKHEAD_FULL, assertThrows(OutboundHttpException.class,
                    () -> http.get(url(server), "*/*", seconds(5))).reason());
            assertEquals(0, server.accepted.get());
            Bulkhead.NONE.enter("x", seconds(1)).close();
        }
    }

    @Test
    void aRefusedUrlNeverConnects() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.ok("x"))) {
            OutboundHttp strict = OutboundHttp.builder(AddressPolicy.builder().allowHttp(true).build()).build();
            OutboundHttpException e = assertThrows(OutboundHttpException.class,
                    () -> strict.get(url(server), "*/*", seconds(5)));
            assertEquals(Reason.REFUSED_ADDRESS, e.reason());
            assertEquals(0, server.accepted.get());
            assertEquals(Reason.REFUSED_URL, assertThrows(OutboundHttpException.class,
                    () -> strict.get("http://bad host/", "*/*", seconds(5))).reason());
        }
    }

    @Test
    void theConnectionGoesToTheAddressTheCheckSawAndTheNameIsResolvedOnce() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.ok("pinned"))) {
            AtomicInteger lookups = new AtomicInteger();
            InetAddress checked = InetAddress.getByName("127.0.0.1");
            InetAddress rebound = InetAddress.getByName("10.0.0.1");
            AddressPolicy policy = AddressPolicy.builder().allowHttp(true)
                    .publicAddress(address -> address.equals(checked))
                    .resolver(host -> new InetAddress[] {lookups.getAndIncrement() == 0 ? checked : rebound})
                    .build();
            OutboundResponse response = OutboundHttp.builder(policy).build()
                    .get("http://rebind.test:" + server.port() + "/", "*/*", seconds(5));
            assertEquals("pinned", response.bodyText());
            assertEquals(checked, response.remoteAddress().getAddress());
            assertEquals(1, lookups.get());
            assertEquals("rebind.test:" + server.port(), server.take().header("Host"));
        }
    }

    @Test
    void aNameWithAnyUncheckedAddressIsRefusedBeforeConnecting() throws Exception {
        try (TestServer server = TestServer.plain(TestServer.ok("x"))) {
            InetAddress checked = InetAddress.getByName("127.0.0.1");
            AddressPolicy policy = AddressPolicy.builder().allowHttp(true)
                    .publicAddress(address -> address.equals(checked))
                    .resolver(host -> new InetAddress[] {checked, InetAddress.getByName("10.0.0.1")})
                    .build();
            OutboundHttpException e = assertThrows(OutboundHttpException.class, () -> OutboundHttp.builder(policy).build()
                    .get("http://rebind.test:" + server.port() + "/", "*/*", seconds(5)));
            assertEquals(Reason.REFUSED_ADDRESS, e.reason());
            assertTrue(e.getMessage().contains("10.0.0.1"), e.getMessage());
            assertEquals(0, server.accepted.get());
        }
    }

    @Test
    void aFailureOfAnyOtherKindIsIo() {
        AddressPolicy.Target target = new AddressPolicy.Target(URI.create("http://h/"), false, "h", 80, List.of());
        OutboundHttpException e = OutboundHttp.failure(new IOException("broken pipe"), new DeadlineSocket(seconds(1)),
                seconds(1), target);
        assertEquals(Reason.IO, e.reason());
    }

    @Test
    void peerTextIsClippedAndMadePrintable() {
        assertEquals("a?b", OutboundHttp.LogText.clip("a\nb"));
        assertEquals("x".repeat(80) + "...", OutboundHttp.LogText.clip("x".repeat(81)));
        assertEquals("x".repeat(80), OutboundHttp.LogText.clip("x".repeat(80)));
    }

    @Test
    void theBuilderRefusesNonsense() {
        OutboundHttp.Builder builder = OutboundHttp.builder(LOCAL);
        assertThrows(IllegalArgumentException.class, () -> builder.connectTimeout(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> builder.headerTimeout(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class, () -> builder.maxBodyBytes(-1));
        assertThrows(IllegalArgumentException.class, () -> builder.userAgent("bad\r\nagent"));
        assertThrows(NullPointerException.class, () -> OutboundHttp.builder(null));
        assertEquals(LOCAL, builder.userAgent("ua/1").build().policy());
    }

    @Test
    void aMalformedUrlIsRefused() {
        assertEquals(Reason.REFUSED_URL, assertThrows(OutboundHttpException.class,
                () -> client().get("http://[bad", "*/*", seconds(1))).reason());
    }

    @Test
    void bodiesAreCopied() throws Exception {
        byte[] body = "abc".getBytes(StandardCharsets.UTF_8);
        OutboundResponse response = new OutboundResponse(200, "OK", List.of(), body, null);
        response.body()[0] = 'z';
        assertArrayEquals(body, response.body());
    }
}
