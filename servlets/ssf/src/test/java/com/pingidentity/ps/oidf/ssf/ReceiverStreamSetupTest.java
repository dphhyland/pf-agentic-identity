/*
 * H-SSF-1: the receiver creates or finds its own stream at the transmitter, in step with its settings, and its calls
 * carry a token that is fetched again after a 401.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.signals.SetVerifier;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

class ReceiverStreamSetupTest {

    private static final String ISS = "https://tx.example.com";
    private static final String META = ISS + "/.well-known/ssf-configuration";
    private static final String STREAMS = ISS + "/ssf/streams";
    private static final String AUD = "rx-client";
    private static final String POLL = DeliveryMethod.POLL.urn();
    private static final String PUSH = DeliveryMethod.PUSH.urn();

    /** One call the fake transmitter took. */
    private record Call(String method, String url, Map<String, Object> body) {
    }

    /** A fake transmitter: metadata, a list of streams, and what create and update answer. */
    private static final class Transmitter implements ReceiverStreamClient.HttpJson {
        final List<Call> calls = new ArrayList<>();
        String metadata = "{\"issuer\":\"" + ISS + "\",\"configuration_endpoint\":\"" + STREAMS
                + "\",\"critical_subject_members\":[\"session\",7]}";
        String list = "[]";
        String written;

        @Override
        public String call(String method, String url, String bodyJson) throws Exception {
            calls.add(new Call(method, url, bodyJson == null ? null : JsonUtil.parseJson(bodyJson)));
            if (url.equals(META)) {
                return this.metadata;
            }
            if ("GET".equals(method)) {
                return this.list;
            }
            return "DELETE".equals(method) ? "" : this.written;
        }
    }

    private static String stream(String id, String iss, Object aud, String method, String endpoint) {
        return "{\"stream_id\":\"" + id + "\",\"iss\":\"" + iss + "\",\"aud\":" + JsonUtil.toJson(Map.of("a", aud)).substring(5,
                JsonUtil.toJson(Map.of("a", aud)).length() - 1) + ",\"delivery\":{\"method\":\"" + method + "\""
                + (endpoint == null ? "" : ",\"endpoint_url\":\"" + endpoint + "\"") + "}}";
    }

    private static ReceiverStreamClient.Plan poll() {
        return new ReceiverStreamClient.Plan(META, ISS, AUD, List.of(SsfEventTypes.CAEP_SESSION_REVOKED), null, null);
    }

    private static ReceiverStreamClient.Plan push() {
        return new ReceiverStreamClient.Plan(META, ISS, AUD, List.of(SsfEventTypes.CAEP_SESSION_REVOKED),
                "https://me.example.com/ssf/receiver/events", "s3cret");
    }

    /** SSF 1.0 §8.1.1.1: the receiver creates its stream; the response's iss is the transmitter's. */
    @Test
    @Requirement("SSF §8.1.1.1")
    void aPollStreamIsCreatedWhenTheReceiverHasNone() throws Exception {
        Transmitter tx = new Transmitter();
        tx.written = stream("s-1", ISS, AUD, POLL, ISS + "/ssf/poll?stream_id=s-1");
        ReceiverStreamClient.Setup setup = ReceiverStreamClient.ensure(tx, poll());
        assertEquals("s-1", setup.streamId());
        assertEquals(ISS + "/ssf/poll?stream_id=s-1", setup.pollUrl());
        assertEquals(Set.of("session"), setup.criticalSubjectMembers());
        Call create = tx.calls.get(2);
        assertEquals("POST", create.method());
        assertEquals(STREAMS, create.url());
        assertEquals(Map.of("method", POLL), create.body().get("delivery"));
        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED), create.body().get("events_requested"));
        assertTrue(!create.body().containsKey("aud"), "aud is the transmitter's to supply");
    }

    /** SSF 1.0 §8.1.1.2-§8.1.1.3: an existing stream is found in the receiver's list and updated in place. */
    @Test
    @Requirement("SSF §8.1.1.3")
    void anExistingPushStreamIsFoundAndBroughtIntoStep() throws Exception {
        Transmitter tx = new Transmitter();
        tx.metadata = "{\"issuer\":\"" + ISS + "\",\"configuration_endpoint\":\"" + STREAMS + "\"}";
        tx.list = "[" + stream("s-poll", ISS, AUD, POLL, null) + ",{\"stream_id\":\"odd\",\"delivery\":\"x\"},"
                + stream("s-other", ISS, AUD, PUSH, "https://elsewhere.example.com/events") + ","
                + stream("s-push", ISS, AUD, PUSH, "https://me.example.com/ssf/receiver/events") + ",7]";
        tx.written = stream("s-push", ISS, List.of("other", AUD), PUSH, "https://me.example.com/ssf/receiver/events");
        ReceiverStreamClient.Setup setup = ReceiverStreamClient.ensure(tx, push());
        assertEquals("s-push", setup.streamId());
        assertNull(setup.pollUrl(), "a push stream is not polled");
        assertEquals(Set.of(), setup.criticalSubjectMembers());
        Call update = tx.calls.get(2);
        assertEquals("PATCH", update.method());
        assertEquals("s-push", update.body().get("stream_id"));
        assertEquals(Map.of("method", PUSH, "endpoint_url", "https://me.example.com/ssf/receiver/events",
                "authorization_header", "Bearer s3cret"), update.body().get("delivery"));
    }

    @Test
    void anExistingPollStreamIsUpdatedWithItsEventsOnly() throws Exception {
        Transmitter tx = new Transmitter();
        tx.list = stream("s-1", ISS, AUD, POLL, ISS + "/poll");
        tx.written = stream("s-1", ISS, AUD, POLL, ISS + "/poll");
        assertEquals(ISS + "/poll", ReceiverStreamClient.ensure(tx, poll()).pollUrl());
        Call update = tx.calls.get(2);
        assertEquals("PATCH", update.method());
        assertTrue(!update.body().containsKey("delivery"), "a poll stream's endpoint is the transmitter's");
    }

    /** SSF 1.0 §7.2.4: "The "issuer" value returned MUST be identical to the Issuer URL". */
    @Test
    @Requirement("SSF §7.2.4")
    void aTransmitterWhoseMetadataIsNotTheReceiversIsMisconfigured() {
        Transmitter tx = new Transmitter();
        tx.metadata = "{\"issuer\":\"https://evil.example.com\",\"configuration_endpoint\":\"" + STREAMS + "\"}";
        assertEquals("the transmitter's configuration names issuer https://evil.example.com, not " + ISS + " (SSF 1.0 §7.2.4)",
                assertThrows(ReceiverStreamClient.Misconfigured.class, () -> ReceiverStreamClient.ensure(tx, poll())).getMessage());
        tx.metadata = "{\"issuer\":\"" + ISS + "\"}";
        assertThrows(ReceiverStreamClient.Misconfigured.class, () -> ReceiverStreamClient.ensure(tx, poll()));
        assertEquals(1 + 1, tx.calls.size(), "nothing was created");
    }

    /** A stream created and then refused is deleted again: never a half-set-up stream. */
    @Test
    @Requirement("SSF §8.1.1.1")
    void aStreamCreatedUnderAnotherIssuerOrAudienceIsDeletedAgain() {
        for (String written : List.of(stream("s-9", "https://evil.example.com", AUD, POLL, ISS + "/poll"),
                stream("s-9", ISS, "someone-else", POLL, ISS + "/poll"), stream("s-9", ISS, List.of("a", "b"), POLL, ISS + "/poll"))) {
            Transmitter tx = new Transmitter();
            tx.written = written;
            assertThrows(ReceiverStreamClient.Misconfigured.class, () -> ReceiverStreamClient.ensure(tx, poll()), written);
            Call last = tx.calls.get(tx.calls.size() - 1);
            assertEquals("DELETE", last.method());
            assertEquals(STREAMS + "?stream_id=s-9", last.url());
        }
    }

    @Test
    void aFoundStreamThatNoLongerMatchesIsNotDeleted() {
        Transmitter tx = new Transmitter();
        tx.list = stream("s-1", ISS, AUD, POLL, ISS + "/poll");
        tx.written = stream("s-1", ISS, "someone-else", POLL, ISS + "/poll");
        assertThrows(ReceiverStreamClient.Misconfigured.class, () -> ReceiverStreamClient.ensure(tx, poll()));
        assertEquals("PATCH", tx.calls.get(tx.calls.size() - 1).method());
    }

    @Test
    void anAnswerWithNoStreamIdOrNoPollUrlIsRefused() {
        Transmitter tx = new Transmitter();
        tx.written = "{\"iss\":\"" + ISS + "\"}";
        assertEquals("the transmitter answered with no stream_id: [iss]",
                assertThrows(IllegalStateException.class, () -> ReceiverStreamClient.ensure(tx, poll())).getMessage());
        tx.written = "{\"stream_id\":\" \"}";
        assertThrows(IllegalStateException.class, () -> ReceiverStreamClient.ensure(tx, poll()));
        tx.written = stream("s-2", ISS, AUD, POLL, null);
        assertEquals("the transmitter's poll stream s-2 names no endpoint_url to poll",
                assertThrows(ReceiverStreamClient.Misconfigured.class, () -> ReceiverStreamClient.ensure(tx, poll())).getMessage());
        tx.written = "{\"stream_id\":\"s-3\",\"iss\":\"" + ISS + "\",\"aud\":\"" + AUD + "\",\"delivery\":\"x\"}";
        assertThrows(ReceiverStreamClient.Misconfigured.class, () -> ReceiverStreamClient.ensure(tx, poll()));
    }

    @Test
    void theReceiversStreamIsSetUpOnceAndHandsOnItsCriticalMembers() throws Exception {
        Transmitter tx = new Transmitter();
        tx.written = stream("s-1", ISS, AUD, POLL, ISS + "/poll");
        SsfReceiverService receiver = new SsfReceiverService(new SetVerifier(ISS, null, refresh -> List.of()));
        SsfConfiguration config = new SsfConfiguration.Builder().issuer("https://op.example.com").receiverExpectedIssuer(ISS)
                .receiverAudience(AUD).receiverEndpointAuthToken("s3cret").receiverPollToken("pt")
                .receiverTransmitterConfigurationUrl(META).build();
        ReceiverStream managed = new ReceiverStream(tx, ReceiverStream.plan(config), receiver);
        assertNull(managed.pollUrl());
        assertNull(managed.setup());
        ReceiverStreamClient.Setup first = managed.ensure();
        assertSame(first, managed.ensure());
        assertEquals(3, tx.calls.size(), "once");
        assertEquals(ISS + "/poll", managed.pollUrl());
        assertEquals(Set.of("session"), receiver.criticalSubjectMembers());
        assertEquals(SsfConfiguration.RECEIVER_DEFAULT_EVENTS, ReceiverStream.plan(config).events());
    }

    /** RFC 6750 §3.1: a 401 is a token the server will not take; the receiver fetches another and asks once more. */
    @Test
    @Requirement("RFC6750 §3.1")
    void aCallAnswered401IsMadeOnceMoreWithAFreshToken() throws Exception {
        AtomicInteger issued = new AtomicInteger();
        List<String> presented = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/token", exchange -> {
            byte[] b = ("{\"access_token\":\"t" + issued.incrementAndGet() + "\",\"token_type\":\"Bearer\",\"expires_in\":3600}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, b.length);
            exchange.getResponseBody().write(b);
            exchange.close();
        });
        server.createContext("/tx", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            presented.add(auth);
            exchange.getRequestBody().readAllBytes();
            boolean stale = "Bearer t1".equals(auth) || "Bearer t3".equals(auth);
            byte[] b = (stale ? "{}" : "{\"sets\":{}}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(stale ? 401 : 200, b.length);
            exchange.getResponseBody().write(b);
            exchange.close();
        });
        server.start();
        try {
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            SsfConfiguration config = new SsfConfiguration.Builder().issuer("https://op.example.com")
                    .receiverTokenEndpoint(base + "/token").receiverClientId("rx").receiverClientSecret("s").build();
            ClientCredentialsToken token = ClientCredentialsToken.of(config, ClientCredentialsToken.httpTransport(false),
                    Clock.systemUTC());

            assertEquals("{\"sets\":{}}", PollReceiverClient.httpTransport(() -> base + "/tx", token, false).poll("{}"));
            assertEquals(List.of("Bearer t1", "Bearer t2"), presented);
            token.rejected("t2");
            assertEquals("{\"sets\":{}}", ReceiverStreamClient.httpTransport(token, false).call("GET", base + "/tx", null));
            assertEquals(List.of("Bearer t1", "Bearer t2", "Bearer t3", "Bearer t4"), presented);
            assertNull(PollReceiverClient.httpTransport(() -> null, token, false).poll("{}"), "nowhere to poll yet");

            ReceiverBearer stale = ReceiverBearer.fixed("t1");
            assertThrows(IllegalStateException.class, () -> PollReceiverClient.httpTransport(() -> base + "/tx", stale, false)
                    .poll("{}"), "a static token cannot be replaced, so the 401 stands");
            assertThrows(IllegalStateException.class, () -> ReceiverStreamClient.httpTransport(stale, false)
                    .call("POST", base + "/tx", "{}"));
            assertEquals("{\"sets\":{}}", PollReceiverClient.httpTransport(() -> base + "/tx", ReceiverBearer.fixed(null), false)
                    .poll("{}"), "no token: no Authorization header");
            assertEquals(null, presented.get(presented.size() - 1));
        } finally {
            server.stop(0);
        }
    }

    /** configure() builds the managed stream when its URL is set, and polls only a poll stream or a named poll URL. */
    @Test
    void theTransmitterBuildsTheManagedStreamAndPollsOnlyWhatIsPolled() {
        SsfConfiguration.Builder base = new SsfConfiguration.Builder().issuer("https://op.example.com").receiverExpectedIssuer(ISS)
                .receiverAudience(AUD).receiverEndpointAuthToken("s3cret");
        try {
            SsfSupport.resetForTests();
            SsfSupport.configure(base.receiverTransmitterConfigurationUrl(META).receiverPollToken("pt")
                    .receiverPushEndpointUrl("https://me.example.com/ssf/receiver/events").build());
            assertTrue(SsfSupport.receiverStream() != null, "managed");
            SsfSupport.startReceiverPolling(); // a push stream: nothing to poll, nothing started
            SsfSupport.resetForTests();
            SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com").receiverExpectedIssuer(ISS)
                    .receiverAudience(AUD).receiverEndpointAuthToken("s3cret").receiverPollUrl(ISS + "/poll").build());
            assertNull(SsfSupport.receiverStream(), "a named poll URL is not a managed stream");
            SsfSupport.resetForTests();
            SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com").receiverExpectedIssuer(ISS)
                    .receiverAudience(AUD).receiverEndpointAuthToken("s3cret").receiverTokenEndpoint("https://as.example.com/t")
                    .receiverClientId("rx").receiverClientSecret("s").build());
            assertNull(SsfSupport.receiverStream());
            assertTrue(SsfSupport.receiverBearer(SsfSupport.configuration()) instanceof ClientCredentialsToken);
        } finally {
            SsfSupport.resetForTests();
        }
        assertNull(SsfSupport.receiverStream(), "nothing published");
    }
}
