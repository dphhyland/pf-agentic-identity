/*
 * /ssf/events:emit as a caller sees it: statuses, bodies, and the scope it takes.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.DeliveryMethod;
import com.pingidentity.ps.oidf.ssf.InMemorySsfStore;
import com.pingidentity.ps.oidf.ssf.SetMinter;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfEmitService;
import com.pingidentity.ps.oidf.ssf.SsfEventEmitter;
import com.pingidentity.ps.oidf.ssf.SsfEventTypes;
import com.pingidentity.ps.oidf.ssf.Stream;
import com.pingidentity.ps.oidf.ssf.StreamStatus;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
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
 * {@link com.pingidentity.ps.oidf.ssf.SsfEmitServiceTest} covers what is signed and for whom. This covers the
 * endpoint: the statuses each outcome maps to. {@link com.pingidentity.ps.oidf.ssf.EmitProvisionerGateTest}
 * drives the real servlet to show which scope it takes.
 */
class SsfEventEmitServletTest {

    private static final AuthContext PROVISIONER = AuthContext.active("operator", Set.of("ssf.provision"));
    private static final AuthContext RECEIVER = AuthContext.active("receiver-a", Set.of("ssf.manage"));
    private static final String GOOD = "{\"event_type\":\"" + SsfEventTypes.CAEP_SESSION_REVOKED
            + "\",\"subject\":{\"format\":\"email\",\"email\":\"alice@example.com\"}}";

    private InMemorySsfStore store;
    private SsfEmitService svc;

    @BeforeEach
    void setUp() throws Exception {
        store = new InMemorySsfStore();
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .provisionerScope("ssf.provision").defaultSubjects("ALL").build();
        RsaJsonWebKey key = RsaJwkGenerator.generateJwk(2048);
        key.setKeyId("k");
        svc = new SsfEmitService(store, new SsfEventEmitter(store, new SetMinter("RS256",
                new com.pingidentity.ps.oidf.jose.SigningKeyProvider() {
                    @Override
                    public String keyId() {
                        return "k";
                    }

                    @Override
                    public java.security.interfaces.RSAPrivateKey privateKey() {
                        return key.getRsaPrivateKey();
                    }

                    @Override
                    public java.security.interfaces.RSAPublicKey publicKey() {
                        return key.getRsaPublicKey();
                    }
                }), cfg), cfg);
        stream("s1");
    }

    private void stream(String id) {
        store.createStream(Stream.builder().id(id).audience("https://receiver/" + id).ownerClientId("receiver-a")
                .deliveryMethod(DeliveryMethod.POLL).eventsRequested(SsfEventTypes.CAEP_INTEROP)
                .eventsDelivered(SsfEventTypes.CAEP_INTEROP).status(StreamStatus.ENABLED).build());
    }

    // ─────────────────────────────── through the seam ───────────────────────────────

    @Test
    void aRaisedEventAnswers200WithTheFanOut() throws Exception {
        Exchange x = call("POST", GOOD, PROVISIONER);

        assertEquals(200, x.status());
        assertEquals(1L, x.json().get("count"));
        assertEquals(SsfEventTypes.CAEP_SESSION_REVOKED, x.json().get("event_type"));
        assertEquals(1, store.peek("s1", 10).size());
    }

    @Test
    void onlyPostIsServed() throws Exception {
        assertEquals(405, call("GET", null, PROVISIONER).status());
        assertEquals(405, call("PUT", GOOD, PROVISIONER).status());
    }

    @Test
    void aBodyTheTransmitterWillNotSignIs400() throws Exception {
        Exchange notJson = call("POST", "{not json", PROVISIONER);
        assertEquals(400, notJson.status());
        assertEquals("invalid_request", notJson.json().get("error"));

        Exchange opaque = call("POST", "{\"event_type\":\"" + SsfEventTypes.CAEP_SESSION_REVOKED
                + "\",\"subject\":{\"format\":\"opaque\",\"id\":\"x\"}}", PROVISIONER);
        assertEquals(400, opaque.status());
        assertTrue(((String) opaque.json().get("error_description")).contains("opaque"));
        assertEquals(0, store.peek("s1", 10).size());
    }

    @Test
    void aReceiverTokenIs403AndAnUnknownStreamIs404() throws Exception {
        Exchange forbidden = call("POST", GOOD, RECEIVER);
        assertEquals(403, forbidden.status());
        assertEquals("access_denied", forbidden.json().get("error"));

        Exchange absent = call("POST", GOOD.substring(0, GOOD.length() - 1) + ",\"stream_id\":\"nope\"}", PROVISIONER);
        assertEquals(404, absent.status());
        assertEquals("not_found", absent.json().get("error"));
    }

    private Exchange call(String method, String body, AuthContext auth) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn(method);
        when(req.getInputStream()).thenReturn(new BytesInputStream(body == null ? "" : body));
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(sink));

        SsfEventEmitServlet.handle(req, resp, svc, auth);
        return new Exchange(resp, sink);
    }

    private static final class Exchange {
        final HttpServletResponse resp;
        private final ByteArrayOutputStream sink;

        Exchange(HttpServletResponse resp, ByteArrayOutputStream sink) {
            this.resp = resp;
            this.sink = sink;
        }

        int status() {
            ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
            verify(this.resp).setStatus(status.capture());
            return status.getValue();
        }

        Map<String, Object> json() throws Exception {
            return JsonUtil.parseJson(this.sink.toString(StandardCharsets.UTF_8));
        }
    }

    private static final class BytesInputStream extends ServletInputStream {
        private final ByteArrayInputStream bytes;

        BytesInputStream(String body) {
            this.bytes = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public int read() {
            return this.bytes.read();
        }

        @Override
        public boolean isFinished() {
            return this.bytes.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener listener) {
        }
    }
}
