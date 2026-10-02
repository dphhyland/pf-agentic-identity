/*
 * F-0246: a received SET carrying exp or sub is refused; a critical subject member the receiver cannot act on is discarded.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.servlet.ssf.SsfReceiverServlet;
import com.pingidentity.ps.oidf.signals.SetMinter;
import com.pingidentity.ps.oidf.signals.SetVerifier;
import com.pingidentity.ps.oidf.signals.SubjectId;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ReceiverClaimsTest {

    private static final String ISS = "https://tx.example.com";
    private static final String AUD = "https://me.example.com";

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("tx-key");
    private HttpServer jwks;
    private final List<Event> events = new CopyOnWriteArrayList<>();

    @BeforeEach
    void serveTheTransmittersKeys() throws Exception {
        SsfSupport.resetForTests();
        Events.reset();
        Events.configure(events::add);
        RsaJsonWebKey jwk = new RsaJsonWebKey(keys.publicKey());
        jwk.setKeyId(keys.keyId());
        byte[] body = new JsonWebKeySet(List.<JsonWebKey>of(jwk)).toJson().getBytes(StandardCharsets.UTF_8);
        jwks = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        jwks.createContext("/jwks", exchange -> {
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        jwks.start();
        SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com")
                .receiverExpectedIssuer(ISS).receiverAudience(AUD).receiverEndpointAuthToken("s3cret")
                .receiverJwksUrl("http://127.0.0.1:" + jwks.getAddress().getPort() + "/jwks").build());
    }

    @AfterEach
    void stop() {
        Events.reset();
        SsfSupport.resetForTests();
        jwks.stop(0);
    }

    /** A signed SET with {@code extra} claims beside the ones every SET carries. */
    private String set(String jti, Map<String, Object> subject, Map<String, Object> extra) throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISS);
        claims.put("aud", AUD);
        claims.put("jti", jti);
        claims.put("iat", SetMinter.nowSeconds());
        claims.put("sub_id", subject);
        claims.put("events", Map.of(SsfEventTypes.CAEP_SESSION_REVOKED, Map.of("event_timestamp", 1L)));
        claims.putAll(extra);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(JsonUtil.toJson(claims));
        jws.setAlgorithmHeaderValue("RS256");
        jws.setHeader("typ", "secevent+jwt");
        jws.setKeyIdHeaderValue(keys.keyId());
        jws.setKey(keys.privateKey());
        return jws.getCompactSerialization();
    }

    private static Map<String, Object> email() {
        return SubjectId.email("bob@example.com").toMap();
    }

    @Test
    @Requirement("SSF §4.1.7")
    void aSetCarryingExpIsRefusedNamingTheClaim() throws Exception {
        String jws = set("j-exp", email(), Map.of("exp", SetMinter.nowSeconds() + 3600));
        SetVerifier.SetVerificationException e = assertThrows(SetVerifier.SetVerificationException.class,
                () -> SsfSupport.receiverService().receive(jws));
        assertEquals("invalid_request", e.errorCode());
        assertEquals("the SET carries the \"exp\" claim, which SSF 1.0 §4.1.7 forbids in SETs", e.getMessage());
        assertEquals(List.of("ssf.receiver.set_refused/invalid_request"), counted(), "counted under its error code");
    }

    @Test
    @Requirement("SSF §4.1.2")
    void aSetCarryingSubIsRefusedNamingTheClaim() throws Exception {
        String jws = set("j-sub", email(), Map.of("sub", "bob"));
        SetVerifier.SetVerificationException e = assertThrows(SetVerifier.SetVerificationException.class,
                () -> SsfSupport.receiverService().receive(jws));
        assertEquals("invalid_request", e.errorCode());
        assertEquals("the SET carries the JWT \"sub\" claim, which SSF 1.0 §4.1.2 forbids in SETs (the subject is sub_id)",
                e.getMessage());
        assertEquals(List.of("ssf.receiver.set_refused/invalid_request"), counted(), "counted under its error code");
    }

    /** The receiver's failure events, as code/reason. */
    private List<String> counted() {
        return events.stream().filter(Event::isFailure).map(ev -> ev.code() + "/" + ev.reason()).toList();
    }

    /** RFC 8935 §2.3: 400, err and description, and a Content-Language. */
    @Test
    @Requirement("RFC8935 §2.3")
    void thePushEndpointAnswersTheRefusal400WithItsErrorAndLanguage() throws Exception {
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        HttpServletResponse resp = post(set("j-exp-push", email(), Map.of("exp", 1L)), sink);
        verify(resp).setStatus(400);
        verify(resp).setHeader("Content-Language", "en-US");
        Map<String, Object> body = JsonUtil.parseJson(sink.toString(StandardCharsets.UTF_8));
        assertEquals("invalid_request", body.get("err"));
        assertTrue(((String) body.get("description")).contains("\"exp\""), body.toString());

        verify(post(set("j-ok-push", email(), Map.of()), new ByteArrayOutputStream())).setStatus(202);
    }

    @Test
    void aPayloadThatCannotBeReadIsLeftToTheVerifier() {
        SetVerifier.SetVerificationException e = assertThrows(SetVerifier.SetVerificationException.class,
                () -> SsfSupport.receiverService().receive("not-a-jws"));
        assertTrue(e.getMessage().startsWith("not a compact JWS"), e.getMessage());
        assertThrows(SetVerifier.SetVerificationException.class,
                () -> SsfSupport.receiverService().receive("a.!!!.c"));
    }

    /** SSF 1.0 §3.6: "An SSF Receiver MUST discard any event that contains a Subject with a Critical member that it is unable to process". */
    @Test
    @Requirement("SSF §3.6")
    void anEventWhoseCriticalMemberTheReceiverDoesNotActOnIsDiscarded() throws Exception {
        SsfReceiverService receiver = SsfSupport.receiverService();
        assertEquals(Set.of(), receiver.criticalSubjectMembers());
        receiver.criticalSubjectMembers(Set.of("session", "user"));
        Map<String, Object> withSession = SubjectId.complex(Map.of("user", SubjectId.email("bob@example.com"),
                "session", SubjectId.opaque("s-1"))).toMap();
        Map<String, Object> userOnly = SubjectId.complex(Map.of("user", SubjectId.email("bob@example.com"))).toMap();
        assertEquals(SsfReceiverService.Outcome.DISCARDED, receiver.receive(set("j-crit", withSession, Map.of())));
        assertEquals(List.of("ssf.receiver.set_discarded/critical_subject_member"), counted());
        assertEquals(SsfReceiverService.Outcome.ACCEPTED, receiver.receive(set("j-user", userOnly, Map.of())),
                "a critical member the handlers act on is processed");
        assertEquals(SsfReceiverService.Outcome.ACCEPTED, receiver.receive(set("j-simple", email(), Map.of())));
        assertEquals(Set.of(), SsfReceiverService.unprocessedCriticalMembers(null, Set.of("session")));
    }

    private static HttpServletResponse post(String jws, ByteArrayOutputStream sink) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getHeader("Authorization")).thenReturn("Bearer s3cret");
        when(req.getContentType()).thenReturn("application/secevent+jwt");
        ByteArrayInputStream in = new ByteArrayInputStream(jws.getBytes(StandardCharsets.UTF_8));
        when(req.getInputStream()).thenReturn(new ServletInputStream() {
            @Override
            public int read() {
                return in.read();
            }

            @Override
            public boolean isFinished() {
                return in.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
                throw new UnsupportedOperationException();
            }
        });
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(sink, true));
        new SsfReceiverServlet().service(req, resp);
        return resp;
    }
}
