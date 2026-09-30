/*
 * /ssf/scim/v2/Users as a SCIM client sees it: methods, statuses, the Location header, and the RFC 7644 error schema.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.servlet.ssf.SsfScimSubjectServlet;
import com.pingidentity.ps.oidf.servlet.ssf.SsfScimSubjectServletAccess;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * {@link ScimSubjectServiceTest} covers what the service decides; this covers the servlet's part, driven through
 * {@code service} with a fake introspection, as {@link ScimProvisionerGateTest} is. RFC 7644 §3.12: "implementers MUST
 * return the errors in the body of the response in a JSON format", with the schema
 * {@code urn:ietf:params:scim:api:messages:2.0:Error} and {@code status} as a string.
 */
class ScimEndpointTest {

    private static final String ALICE = "email:alice@example.com";
    private static final Map<String, AuthContext> TOKENS = Map.of(
            "receiver", AuthContext.active("receiver-a", Set.of("ssf.manage")),
            "provisioner", AuthContext.active("scim-provisioner", Set.of("ssf.provision")));

    @BeforeEach
    void configure() {
        SsfSupport.resetForTests();
        SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com").provisionerScope("ssf.provision").build());
        SsfSupport.installReceiverAuthenticator(token -> {
            if ("broken".equals(token)) {
                throw new ReceiverAuthException("introspection is down");
            }
            return TOKENS.getOrDefault(token, AuthContext.inactive());
        });
        SsfSupport.store().createStream(Stream.builder().id("s1").audience("receiver-a").ownerClientId("receiver-a")
                .deliveryMethod(DeliveryMethod.POLL).eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED))
                .eventsDelivered(List.of(SsfEventTypes.CAEP_SESSION_REVOKED)).status(StreamStatus.ENABLED).build());
        // a stream that does not deliver the RISC events, so nothing here is signed (with a key only PingFederate has)
    }

    @AfterEach
    void reset() {
        SsfSupport.resetForTests();
    }

    private record Exchange(HttpServletResponse resp, ByteArrayOutputStream sink) {
        int status() {
            ArgumentCaptor<Integer> status = ArgumentCaptor.forClass(Integer.class);
            verify(this.resp).setStatus(status.capture());
            return status.getValue();
        }

        Map<String, Object> json() throws Exception {
            return JsonUtil.parseJson(this.sink.toString(StandardCharsets.UTF_8));
        }
    }

    private static Exchange call(String token, String method, String pathInfo, Map<String, String> params, String body)
            throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn(method);
        when(req.getHeader("Authorization")).thenReturn(token == null ? null : "Bearer " + token);
        when(req.getPathInfo()).thenReturn(pathInfo);
        for (Map.Entry<String, String> p : params.entrySet()) {
            when(req.getParameter(p.getKey())).thenReturn(p.getValue());
        }
        ByteArrayInputStream in = new ByteArrayInputStream((body == null ? "" : body).getBytes(StandardCharsets.UTF_8));
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
            }
        });
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(sink, true, StandardCharsets.UTF_8));
        new SsfScimSubjectServlet().service(req, resp);
        return new Exchange(resp, sink);
    }

    private static Exchange call(String method, String pathInfo, String body) throws Exception {
        return call("provisioner", method, pathInfo, Map.of(), body);
    }

    private static final String ALICE_JSON = "{\"userName\":\"alice\",\"emails\":[{\"value\":\"alice@example.com\"}],"
            + "\"" + ScimSubjectService.SSF_EXT + "\":{\"streams\":[\"s1\"]}}";

    private static void assertScimError(Exchange x, int status, String scimType) throws Exception {
        assertEquals(status, x.status());
        Map<String, Object> body = x.json();
        assertEquals(List.of(ScimException.ERROR_SCHEMA), body.get("schemas"), body.toString());
        assertEquals(Integer.toString(status), body.get("status"));
        assertEquals(scimType, body.get("scimType"));
        verify(x.resp()).setContentType("application/scim+json");
    }

    @Test
    @Requirement({"RFC7644 §3.3", "RFC7644 §3.4.1", "RFC7644 §3.5.1", "RFC7644 §3.5.2", "RFC7644 §3.6"})
    void eachMethodAnswersItsStatus() throws Exception {
        Exchange created = call("POST", null, ALICE_JSON);
        assertEquals(201, created.status());
        verify(created.resp()).setHeader("Location", "https://op.example.com/ssf/scim/v2/Users/email:alice@example.com");
        verify(created.resp()).setContentType("application/scim+json");

        Exchange read = call("GET", "/" + ALICE, null);
        assertEquals(200, read.status());
        assertEquals(ALICE, read.json().get("id"));

        Exchange listed = call("provisioner", "GET", "/", Map.of("filter", "userName eq \"alice\"", "startIndex", "1",
                "count", " 5 "), null);
        assertEquals(200, listed.status());
        assertEquals(1, ((Number) listed.json().get("totalResults")).intValue());

        assertEquals(200, call("PUT", "/" + ALICE, ALICE_JSON).status());
        assertEquals(200, call("PATCH", "/" + ALICE, "{\"Operations\":[{\"op\":\"replace\",\"path\":\"active\",\"value\":false}]}")
                .status());
        Exchange deleted = call("DELETE", "/" + ALICE, null);
        assertEquals(204, deleted.status());
        verify(deleted.resp(), never()).getWriter();
    }

    @Test
    @Requirement("RFC7644 §3.12")
    void everyRefusalIsInTheScimErrorSchema() throws Exception {
        assertScimError(call("GET", "/" + ALICE, null), 404, null);
        assertScimError(call("provisioner", "GET", null, Map.of("filter", "userName gt \"a\""), null), 400, "invalidFilter");
        assertScimError(call("provisioner", "GET", null, Map.of("count", "ten"), null), 400, "invalidValue");
        assertScimError(call("POST", null, "{ not json"), 400, "invalidSyntax");
        assertScimError(call("POST", "/" + ALICE, ALICE_JSON), 405, null);
        assertScimError(call("PUT", null, ALICE_JSON), 405, null);
        assertScimError(call("PATCH", "/", "{}"), 405, null);
        assertScimError(call("DELETE", null, null), 405, null);
        call("POST", null, ALICE_JSON);
        assertScimError(call("POST", null, ALICE_JSON), 409, "uniqueness");
    }

    @Test
    void aMethodScimDoesNotUseIs405InTheErrorSchema() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("OPTIONS");
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(sink, true, StandardCharsets.UTF_8));
        SsfScimSubjectServletAccess.handle(req, resp, SsfSupport.scimSubjectService(), TOKENS.get("provisioner"));
        assertScimError(new Exchange(resp, sink), 405, null);
    }

    /** Token validation's refusals too: the status and WWW-Authenticate stand, the body is SCIM's. */
    @Test
    @Requirement({"RFC7644 §3.12", "RFC6750 §3.1"})
    void theTokenRefusalsAreInTheScimErrorSchemaWithTheirHeaders() throws Exception {
        Exchange none = call(null, "GET", "/" + ALICE, Map.of(), null);
        assertScimError(none, 401, null);
        assertEquals("missing bearer token", none.json().get("detail"));
        verify(none.resp()).setHeader("WWW-Authenticate", "Bearer");

        Exchange inactive = call("expired", "GET", "/" + ALICE, Map.of(), null);
        assertScimError(inactive, 401, null);
        verify(inactive.resp()).setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");

        assertScimError(call("receiver", "GET", "/" + ALICE, Map.of(), null), 403, null);
        assertScimError(call("broken", "GET", "/" + ALICE, Map.of(), null), 503, null);
    }

    /** The container decodes the path; the id is read as it is, so a {@code +} is a plus and not a space. */
    @Test
    void anIdIsReadFromThePathAsTheContainerDecodedIt() throws Exception {
        call("POST", null, "{\"emails\":[{\"value\":\"alice+tag@example.com\"}]}");
        Exchange read = call("GET", "/email:alice+tag@example.com", null);
        assertEquals(200, read.status());
        assertTrue(read.json().get("id").toString().contains("+tag"));
    }

    @Test
    void anUnexpectedFailureIs500WithoutItsMessage() throws Exception {
        ScimSubjectService failing = mock(ScimSubjectService.class);
        when(failing.get(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any()))
                .thenThrow(new IllegalStateException("jdbc:postgresql://secret-host/db refused"));
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/" + ALICE);
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(sink, true, StandardCharsets.UTF_8));
        SsfScimSubjectServletAccess.handle(req, resp, failing, TOKENS.get("provisioner"));
        Exchange x = new Exchange(resp, sink);
        assertScimError(x, 500, null);
        assertTrue(!sink.toString(StandardCharsets.UTF_8).contains("secret-host"));
    }
}
