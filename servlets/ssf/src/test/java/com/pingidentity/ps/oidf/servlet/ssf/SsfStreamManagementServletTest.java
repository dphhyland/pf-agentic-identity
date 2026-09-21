/*
 * The Stream Management API as a receiver sees it: methods, where stream_id travels, statuses, bodies.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.DeliveryMethod;
import com.pingidentity.ps.oidf.ssf.InMemorySsfStore;
import com.pingidentity.ps.oidf.ssf.SetMinter;
import com.pingidentity.ps.oidf.ssf.SetPublisher;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfEventTypes;
import com.pingidentity.ps.oidf.ssf.StreamManagementService;
import com.pingidentity.ps.oidf.ssf.StreamStatus;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * {@link StreamManagementServiceTest} covers what the service decides. This covers what only the servlet
 * decides, which is most of what a receiver written against the specification trips over: a method the
 * container answered before the servlet saw it, a {@code stream_id} looked for in the wrong place, a
 * status one digit off. Driven through {@code handle}, past authentication, so it needs no PingFederate.
 */
class SsfStreamManagementServletTest {

    private static final AuthContext RECEIVER = AuthContext.active("receiver-client", Set.of("ssf.manage"));
    private static final AuthContext OTHER = AuthContext.active("another-receiver", Set.of("ssf.manage"));
    private static final String ABSENT = "00000000-0000-4000-8000-00000000dead";

    private InMemorySsfStore store;
    private StreamManagementService svc;

    @BeforeEach
    void setUp() {
        store = new InMemorySsfStore();
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        OutboundUrlPolicy everythingIsPublic = OutboundUrlPolicy.from(Map.<String, String>of()::get).withResolver(host -> {
            try {
                return new InetAddress[] { InetAddress.getByName("93.184.216.34") };
            }
            catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        });
        svc = new StreamManagementService(store, new SetMinter("RS256", new GeneratedKey()), cfg, SetPublisher.NOOP,
                everythingIsPublic);
    }

    // ─────────────────────────────── create and read ───────────────────────────────

    @Test
    @Requirement("SSF §8.1.1.1")
    void aCreateThatNamesNoAudienceSucceedsAndIsAddressedToTheCaller() throws Exception {
        Exchange x = call("POST", "/ssf/streams", null,
                "{\"delivery\":{\"method\":\"" + DeliveryMethod.POLL.urn() + "\"},"
                        + "\"events_requested\":[\"" + SsfEventTypes.CAEP_SESSION_REVOKED + "\"]}");

        verify(x.resp).setStatus(201);
        assertEquals("receiver-client", x.json().get("aud"));
    }

    @Test
    @Requirement("SSF §8.1.1.2")
    void readingWithoutAStreamIdReturnsAListAndAnEmptyOneWhenThereAreNone() throws Exception {
        assertEquals("[]", call("GET", "/ssf/streams", null, null).body());

        String id = createPollStream();
        String listed = call("GET", "/ssf/streams", null, null).body();

        assertTrue(listed.startsWith("[{") && listed.endsWith("}]"), "a bare array, not {\"streams\":[...]}: " + listed);
        assertTrue(listed.contains(id));
    }

    // ─────────────────────────────── update and replace ───────────────────────────────

    @Test
    @Requirement("SSF §8.1.1.3")
    void anUpdateFindsItsStreamInTheBody() throws Exception {
        String id = createPollStream();

        Exchange x = call("PATCH", "/ssf/streams", null, "{\"stream_id\":\"" + id + "\",\"events_requested\":[\""
                + SsfEventTypes.CAEP_CREDENTIAL_CHANGE + "\"]}");

        verify(x.resp).setStatus(200);
        assertEquals(List.of(SsfEventTypes.CAEP_CREDENTIAL_CHANGE), x.json().get("events_delivered"));
        assertEquals("https://op.example.com", x.json().get("iss"), "a receiver MUST check it, so it must be there");
    }

    @Test
    @Requirement("SSF §8.1.1.3")
    void anUpdateOfAnUnknownStreamIsNotFoundRatherThanMalformed() throws Exception {
        verify(call("PATCH", "/ssf/streams", null, "{\"stream_id\":\"no-such-stream\"}").resp).setStatus(404);
    }

    /** Not what the specification describes; kept so a caller written against the old servlet still works. */
    @Test
    void anUpdateStillAcceptsTheStreamIdAsAQueryParameter() throws Exception {
        String id = createPollStream();

        verify(call("PATCH", "/ssf/streams", id, "{\"events_requested\":[]}").resp).setStatus(200);
        verify(call("PATCH", "/ssf/streams", null, "{\"events_requested\":[]}").resp).setStatus(400);
    }

    @Test
    @Requirement("SSF §8.1.1.4")
    void aReplacementIsServedAndAnswersEachFailureWithItsOwnStatus() throws Exception {
        String id = createPollStream();
        String delivery = "\"delivery\":{\"method\":\"" + DeliveryMethod.POLL.urn() + "\"}";

        Exchange ok = call("PUT", "/ssf/streams", null, "{\"stream_id\":\"" + id + "\"," + delivery + "}");
        verify(ok.resp).setStatus(200);
        assertEquals(List.of(), ok.json().get("events_delivered"), "replaced, not merged");

        verify(call("PUT", "/ssf/streams", null, "{\"stream_id\":\"no-such-stream\"," + delivery + "}").resp).setStatus(404);
        verify(call("PUT", "/ssf/streams", null, ";{ broken").resp).setStatus(400);
        verify(call("PUT", "/ssf/streams", id, "{" + delivery + "}").resp).setStatus(400); // body, never the query
    }

    /**
     * {@code handle} cannot show this one: before {@code doPut} existed the request never reached it. The
     * container's own {@code doPut} answered 405 to a caller nobody had authenticated.
     */
    @Test
    @Requirement("SSF §8.1.1.4")
    void putReachesTheServletInsteadOfTheContainersDefault() throws Exception {
        assertNotNull(SsfStreamManagementServlet.class.getDeclaredMethod("doPut",
                HttpServletRequest.class, HttpServletResponse.class));
    }

    // ─────────────────────────────── subjects and verification ───────────────────────────────

    @Test
    @Requirement({"SSF §8.1.3.2", "SSF §8.1.3.3"})
    void addingASubjectAnswers200AndRemovingOne204BothEmpty() throws Exception {
        String id = createPollStream();
        String body = "{\"stream_id\":\"" + id + "\",\"subject\":{\"format\":\"email\",\"email\":\"alice@example.com\"}}";

        Exchange added = call("POST", "/ssf/subjects:add", null, body);
        verify(added.resp).setStatus(200);
        Exchange removed = call("POST", "/ssf/subjects:remove", null, body);
        verify(removed.resp).setStatus(204);

        verify(added.resp, never()).getWriter();
        verify(removed.resp, never()).getWriter();
    }

    @Test
    @Requirement("SSF §8.1.4.2")
    void triggeringVerificationAnswers204WithNoBodyAndQueuesTheSet() throws Exception {
        String id = createPollStream();

        Exchange x = call("POST", "/ssf/verify", null, "{\"stream_id\":\"" + id + "\",\"state\":\"s-1\"}");

        verify(x.resp).setStatus(204);
        verify(x.resp, never()).getWriter();
        assertEquals(1, ((Map<?, ?>) svc.poll(id, null, 10, true, RECEIVER).get("sets")).size());
    }

    // ─────────────────────────────── whose stream it is ───────────────────────────────

    /** One per-stream request, addressed to whichever stream id it is given. */
    private interface Route {
        Exchange send(AuthContext as, String streamId) throws Exception;
    }

    /**
     * The service decides who is admitted ({@code StreamOwnershipTest}); this is what a receiver sees of it.
     * Every per-stream endpoint is walked, because the fault this closes was never in one of them - it was
     * that none of them asked. To a second receiver a stream must answer 404, and the same 404 - status and
     * body - as an id nobody has, since SSF words that error as no stream with that id "for this Event
     * Receiver" and a 403 would confirm the id is real. Each is then sent by the owner, as the control.
     */
    @Test
    @Requirement({"SSF §8.1.1.2", "SSF §8.1.1.3", "SSF §8.1.1.4", "SSF §8.1.1.5", "SSF §8.1.2.1", "SSF §8.1.2.2",
            "SSF §8.1.3.2", "SSF §8.1.3.3", "SSF §8.1.4.2"})
    void aStreamThatIsAnotherReceiversAnswersEveryEndpointAsOneThatDoesNotExist() throws Exception {
        String poll = "\"delivery\":{\"method\":\"" + DeliveryMethod.POLL.urn() + "\"}";
        String alice = "\"subject\":{\"format\":\"email\",\"email\":\"alice@example.com\"}";
        Map<String, Route> routes = new LinkedHashMap<>();
        routes.put("read", (as, id) -> callAs(as, "GET", "/ssf/streams", id, null));
        routes.put("update", (as, id) -> callAs(as, "PATCH", "/ssf/streams", null, "{\"stream_id\":\"" + id + "\"}"));
        routes.put("update by query", (as, id) -> callAs(as, "PATCH", "/ssf/streams", id, "{}"));
        routes.put("replace", (as, id) -> callAs(as, "PUT", "/ssf/streams", null, "{\"stream_id\":\"" + id + "\"," + poll + "}"));
        routes.put("read status", (as, id) -> callAs(as, "GET", "/ssf/status", id, null));
        routes.put("set status", (as, id) -> callAs(as, "POST", "/ssf/status", null,
                "{\"stream_id\":\"" + id + "\",\"status\":\"paused\"}"));
        routes.put("add subject", (as, id) -> callAs(as, "POST", "/ssf/subjects:add", null, "{\"stream_id\":\"" + id + "\"," + alice + "}"));
        routes.put("remove subject", (as, id) -> callAs(as, "POST", "/ssf/subjects:remove", null,
                "{\"stream_id\":\"" + id + "\"," + alice + "}"));
        routes.put("verify", (as, id) -> callAs(as, "POST", "/ssf/verify", null, "{\"stream_id\":\"" + id + "\"}"));
        routes.put("poll", (as, id) -> pollAs(as, id, "{\"maxEvents\":10}"));
        routes.put("delete", (as, id) -> callAs(as, "DELETE", "/ssf/streams", id, null)); // last: it ends the stream

        String id = createPollStream();
        for (Map.Entry<String, Route> route : routes.entrySet()) {
            Exchange theirs = route.getValue().send(OTHER, id);
            Exchange nobodys = route.getValue().send(OTHER, ABSENT);

            verify(theirs.resp).setStatus(404);
            verify(nobodys.resp).setStatus(404);
            assertEquals(nobodys.body().replace(ABSENT, "<id>"), theirs.body().replace(id, "<id>"), route.getKey());
        }
        assertEquals(StreamStatus.ENABLED, store.getStream(id).orElseThrow().status(), "and none of it was applied");

        for (Map.Entry<String, Route> route : routes.entrySet()) {
            int status = route.getValue().send(RECEIVER, id).status();
            assertEquals(2, status / 100, route.getKey() + " from the owner answered " + status);
        }
        assertTrue(store.getStream(id).isEmpty(), "control: the owner's requests were served, the delete among them");
    }

    @Test
    @Requirement("SSF §8.1.1.2")
    void aReceiverIsListedItsOwnStreamsAndNotAnotherReceivers() throws Exception {
        String mine = createPollStream();

        assertEquals("[]", callAs(OTHER, "GET", "/ssf/streams", null, null).body(),
                "the list used to be how a receiver learned every other receiver's stream ids");
        assertTrue(call("GET", "/ssf/streams", null, null).body().contains(mine)); // control
    }

    /**
     * RFC 7662 makes {@code client_id} OPTIONAL, so a token can be active, carry the scope and name nobody.
     * There is then no one for a stream to belong to, and SSF has a status for that.
     */
    @Test
    @Requirement("SSF §8.1.1.1")
    void aTokenThatNamesNoClientIsForbiddenToCreateAStream() throws Exception {
        String body = "{\"delivery\":{\"method\":\"" + DeliveryMethod.POLL.urn() + "\"}}";

        Exchange x = callAs(AuthContext.active(null, Set.of("ssf.manage")), "POST", "/ssf/streams", null, body);

        verify(x.resp).setStatus(403);
        assertEquals("access_denied", x.json().get("error"));
        assertTrue(store.listStreams().isEmpty());
        verify(call("POST", "/ssf/streams", null, body).resp).setStatus(201); // control: the body was never the problem
    }

    /**
     * Untagged, as in {@code StreamOwnershipTest}: no clause confines a poll to the stream's own receiver.
     * Here for what the service test cannot show - that the poll servlet passes on who is asking at all.
     * It used to authenticate the caller and then throw the answer away.
     */
    @Test
    void anotherReceiversPollNeitherReadsNorAcknowledgesAStreamsEvents() throws Exception {
        String id = createPollStream();
        call("POST", "/ssf/verify", null, "{\"stream_id\":\"" + id + "\"}");
        String jti = store.peek(id, 1).get(0).jti();

        Exchange theirs = pollAs(OTHER, id, "{\"ack\":[\"" + jti + "\"],\"maxEvents\":10}");

        verify(theirs.resp).setStatus(404);
        assertFalse(theirs.body().contains(jti));
        assertEquals(1, store.peek(id, 10).size(), "an acknowledgement deletes, and this one must not have");

        Exchange mine = pollAs(RECEIVER, id, "{\"maxEvents\":10}"); // control
        verify(mine.resp).setStatus(200);
        assertTrue(((Map<?, ?>) mine.json().get("sets")).containsKey(jti));
    }

    // ─────────────────────────────── harness ───────────────────────────────

    private String createPollStream() throws Exception {
        return (String) call("POST", "/ssf/streams", null,
                "{\"delivery\":{\"method\":\"" + DeliveryMethod.POLL.urn() + "\"},\"events_requested\":[\""
                        + SsfEventTypes.CAEP_SESSION_REVOKED + "\"]}").json().get("stream_id");
    }

    private Exchange call(String method, String path, String streamIdParam, String body) throws Exception {
        return callAs(RECEIVER, method, path, streamIdParam, body);
    }

    private Exchange pollAs(AuthContext auth, String streamIdParam, String body) throws Exception {
        return callAs(auth, "POST", "/ssf/poll", streamIdParam, body);
    }

    private Exchange callAs(AuthContext auth, String method, String path, String streamIdParam, String body)
            throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn(method);
        when(req.getServletPath()).thenReturn(path);
        when(req.getParameter("stream_id")).thenReturn(streamIdParam);
        when(req.getInputStream()).thenReturn(new BytesInputStream(body == null ? "" : body));
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(sink));

        if ("/ssf/poll".equals(path)) {
            SsfPollServlet.handle(req, resp, svc, auth);
        } else {
            SsfStreamManagementServlet.handle(req, resp, svc, auth);
        }
        return new Exchange(resp, sink);
    }

    private static final class Exchange {
        final HttpServletResponse resp;
        private final ByteArrayOutputStream sink;

        Exchange(HttpServletResponse resp, ByteArrayOutputStream sink) {
            this.resp = resp;
            this.sink = sink;
        }

        String body() {
            return this.sink.toString(StandardCharsets.UTF_8);
        }

        int status() {
            ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
            verify(this.resp).setStatus(status.capture());
            return status.getValue();
        }

        Map<String, Object> json() throws Exception {
            return JsonUtil.parseJson(body());
        }
    }

    private static final class BytesInputStream extends ServletInputStream {
        private final ByteArrayInputStream in;

        BytesInputStream(String body) {
            this.in = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public int read() {
            return this.in.read();
        }

        @Override
        public boolean isFinished() {
            return this.in.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener listener) {
        }
    }

    private static final class GeneratedKey implements SigningKeyProvider {
        private final RsaJsonWebKey jwk;

        GeneratedKey() {
            try {
                this.jwk = RsaJwkGenerator.generateJwk(2048);
                this.jwk.setKeyId("servlet-test-key");
            }
            catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public String keyId() {
            return this.jwk.getKeyId();
        }

        @Override
        public RSAPrivateKey privateKey() {
            return (RSAPrivateKey) this.jwk.getRsaPrivateKey();
        }

        @Override
        public RSAPublicKey publicKey() {
            return this.jwk.getRsaPublicKey();
        }
    }
}
