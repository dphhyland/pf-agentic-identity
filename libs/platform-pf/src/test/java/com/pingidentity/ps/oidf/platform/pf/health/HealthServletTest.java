/*
 * Live and ready answer anyone with the status alone; the detail and info answer only the admin bearer, and 404 otherwise.
 */
package com.pingidentity.ps.oidf.platform.pf.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.json.Json;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HealthServletTest {

    private static final String TOKEN = "s3cret-admin-token";

    /** What the servlet did to a response. */
    static final class Answer {
        int status = 200;
        Integer error;
        final Map<String, String> headers = new LinkedHashMap<>();
        String contentType;
        int contentLength = -1;
        final ByteArrayOutputStream body = new ByteArrayOutputStream();

        String text() {
            return this.body.toString(StandardCharsets.UTF_8);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> json() {
            return (Map<String, Object>) Json.parse(this.text());
        }
    }

    private static HttpServletRequest request(String method, String path, String authorization) {
        return (HttpServletRequest) Proxy.newProxyInstance(HealthServletTest.class.getClassLoader(), new Class<?>[] {HttpServletRequest.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "getMethod" -> method;
                    case "getServletPath" -> path;
                    case "getHeader" -> "Authorization".equalsIgnoreCase((String) args[0]) ? authorization : null;
                    case "toString" -> method + " " + path;
                    default -> null;
                });
    }

    private static HttpServletResponse response(Answer answer) {
        ServletOutputStream out = new ServletOutputStream() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener listener) {
            }

            @Override
            public void write(int b) {
                answer.body.write(b);
            }
        };
        return (HttpServletResponse) Proxy.newProxyInstance(HealthServletTest.class.getClassLoader(), new Class<?>[] {HttpServletResponse.class},
                (proxy, m, args) -> {
                    switch (m.getName()) {
                        case "setStatus" -> answer.status = (Integer) args[0];
                        case "sendError" -> answer.error = (Integer) args[0];
                        case "setHeader" -> answer.headers.put((String) args[0], (String) args[1]);
                        case "setContentType" -> answer.contentType = (String) args[0];
                        case "setContentLength" -> answer.contentLength = (Integer) args[0];
                        case "getOutputStream" -> {
                            return out;
                        }
                        default -> { }
                    }
                    return null;
                });
    }

    private static ServletConfig config() {
        ServletContext context = (ServletContext) Proxy.newProxyInstance(HealthServletTest.class.getClassLoader(),
                new Class<?>[] {ServletContext.class}, (proxy, m, args) -> null);
        return (ServletConfig) Proxy.newProxyInstance(HealthServletTest.class.getClassLoader(), new Class<?>[] {ServletConfig.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "getServletContext" -> context;
                    case "getServletName" -> "HealthServlet";
                    case "getInitParameterNames" -> Collections.emptyEnumeration();
                    default -> null;
                });
    }

    private static HealthServlet servlet(String propertyToken, String envToken) throws Exception {
        Map<String, Object> versions = new LinkedHashMap<>();
        versions.put("agentic-identity", "0.5.0-TEST");
        versions.put("commit", null);
        versions.put("pingfederate", "13.1.3.0");
        HealthServlet servlet = new HealthServlet(name -> HealthAccess.TOKEN_PROPERTY.equals(name) ? propertyToken : null,
                name -> switch (name) {
                    case HealthAccess.TOKEN_ENV -> envToken;
                    case "OIDF_DEPLOYMENT_PROFILE" -> "development";
                    default -> null;
                }, () -> versions);
        servlet.init(config());
        return servlet;
    }

    private static Answer call(HealthServlet servlet, String method, String path, String authorization) throws Exception {
        Answer answer = new Answer();
        servlet.service(request(method, path, authorization), response(answer));
        return answer;
    }

    @Test
    void liveIsUpAndSaysNothingElse() throws Exception {
        Answer a = call(servlet(null, null), "GET", HealthServlet.LIVE, null);
        assertEquals(200, a.status);
        assertEquals("{\"status\":\"UP\"}", a.text());
        assertEquals("application/json", a.contentType);
        assertEquals("no-store", a.headers.get("Cache-Control"));
        assertEquals(a.text().length(), a.contentLength);
    }

    @Test
    void readyFollowsTheComponentsAndSaysNothingElse() throws Exception {
        HealthServlet servlet = servlet(null, null);
        ComponentParts.Part part = Startup.begin(Startup.HOSTING, "HealthServletTestPart");
        Answer starting = call(servlet, "GET", HealthServlet.READY, null);
        assertEquals(503, starting.status, "an enabled component that is starting is not ready");
        assertEquals("{\"status\":\"DOWN\"}", starting.text());

        part.degraded("slow store");
        Answer degraded = call(servlet, "GET", HealthServlet.READY, null);
        assertEquals(200, degraded.status, "degraded counts as ready");
        assertEquals("{\"status\":\"UP\"}", degraded.text());

        part.failedConfig("no authority");
        assertEquals(503, call(servlet, "GET", HealthServlet.READY, null).status);

        part.ready();
        assertEquals(200, call(servlet, "GET", HealthServlet.READY, null).status);
        part.disabled();
        assertEquals(200, call(servlet, "GET", HealthServlet.READY, null).status, "a disabled component does not count");
    }

    @Test
    void theDetailAndInfoAre404WithoutTheBearer() throws Exception {
        for (HealthServlet servlet : List.of(servlet(null, null), servlet(TOKEN, null))) {
            for (String path : List.of(HealthServlet.DETAIL, HealthServlet.INFO)) {
                for (String auth : new String[] {null, "Bearer wrong", "Basic " + TOKEN, "Bearer " + TOKEN + "x", "Bearer"}) {
                    for (String method : List.of("GET", "HEAD", "POST", "DELETE")) {
                        Answer a = call(servlet, method, path, auth);
                        assertEquals(404, a.error, method + " " + path + " with " + auth);
                        assertEquals("", a.text());
                        assertTrue(a.headers.isEmpty(), "nothing says the path exists: " + a.headers);
                    }
                }
            }
        }
        Answer noTokenConfigured = call(servlet(null, null), "GET", HealthServlet.DETAIL, "Bearer " + TOKEN);
        assertEquals(404, noTokenConfigured.error, "with no token configured nobody is authorised");
    }

    @Test
    void aPathTheServletDoesNotNameIs404WithOrWithoutTheBearer() throws Exception {
        // A wildcard mapping, a forward or a named dispatch could bring another servlet path here: it fails closed.
        HealthServlet servlet = servlet(TOKEN, null);
        java.util.Arrays.asList("/agentic-identity", "/agentic-identity/health/", "/agentic-identity/health/other", "", null)
                .forEach(path -> {
                    for (String auth : new String[] {null, "Bearer " + TOKEN}) {
                        try {
                            Answer a = call(servlet, "GET", path, auth);
                            assertEquals(404, a.error, path + " with " + auth);
                            assertEquals("", a.text(), path + " with " + auth);
                        } catch (Exception e) {
                            throw new AssertionError(e);
                        }
                    }
                });
        // Each layer on its own: the access check turns an unnamed path away before the method check does...
        assertEquals(404, call(servlet, "POST", "/agentic-identity", null).error, "an unnamed path is not open");
        assertEquals(405, call(servlet, "POST", "/agentic-identity", "Bearer " + TOKEN).error);
        // ...and answer() serves nothing it does not name, whoever got the request that far.
        Answer direct = new Answer();
        servlet.answer("/agentic-identity", false, response(direct));
        assertEquals(404, direct.error);
        assertEquals("", direct.text());
    }

    @Test
    void theDetailAnswersTheBearerWithEveryComponentAndTheReadinessCode() throws Exception {
        HealthServlet servlet = servlet(null, TOKEN);
        ComponentParts.Part part = Startup.begin(Startup.SSF_RECEIVER, "HealthServletDetailPart");
        part.failedConfig("receiverAudience must be set");

        Answer a = call(servlet, "GET", HealthServlet.DETAIL, "bearer " + TOKEN);

        assertNull(a.error);
        assertEquals(503, a.status);
        Map<String, Object> body = a.json();
        assertEquals("DOWN", body.get("status"));
        assertEquals("development", body.get("profile"));
        assertEquals("13.1.3.0", ((Map<?, ?>) body.get("versions")).get("pingfederate"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> components = (List<Map<String, Object>>) body.get("components");
        Map<String, Object> receiver = components.stream().filter(c -> "SSF_RECEIVER".equals(c.get("name"))).findFirst().orElseThrow();
        assertEquals("FAILED_CONFIG", receiver.get("state"));
        assertEquals("HealthServletDetailPart: receiverAudience must be set", receiver.get("reason"));
        assertEquals(true, receiver.get("enabled"));
        List<?> parts = (List<?>) receiver.get("parts");
        assertEquals("HealthServletDetailPart", ((Map<?, ?>) parts.get(0)).get("name"));
        part.ready();
        assertEquals(200, call(servlet, "GET", HealthServlet.DETAIL, "Bearer " + TOKEN).status);
    }

    @Test
    void infoAnswersTheBearerWithTheVersions() throws Exception {
        Answer a = call(servlet(TOKEN, "a different token"), "GET", HealthServlet.INFO, "Bearer " + TOKEN);
        assertEquals(200, a.status);
        assertEquals("{\"agentic-identity\":\"0.5.0-TEST\",\"commit\":null,\"pingfederate\":\"13.1.3.0\"}", a.text());
    }

    @Test
    void onlyGetAndHeadAreServedAndHeadHasNoBody() throws Exception {
        HealthServlet servlet = servlet(TOKEN, null);
        Answer post = call(servlet, "POST", HealthServlet.LIVE, null);
        assertEquals(405, post.error);
        assertEquals("GET, HEAD", post.headers.get("Allow"));
        Answer authorisedPut = call(servlet, "PUT", HealthServlet.INFO, "Bearer " + TOKEN);
        assertEquals(405, authorisedPut.error, "an authorised caller learns the method is wrong");
        Answer head = call(servlet, "HEAD", HealthServlet.LIVE, null);
        assertEquals(200, head.status);
        assertEquals("", head.text());
        assertEquals("{\"status\":\"UP\"}".length(), head.contentLength);
    }

    @Test
    void theDefaultServletReadsTheProcesssTokenAndThisJarsVersions() throws Exception {
        HealthServlet servlet = new HealthServlet();
        servlet.init(config());
        assertEquals(404, call(servlet, "GET", HealthServlet.INFO, "Bearer " + TOKEN).error);
        assertFalse(call(servlet, "GET", HealthServlet.LIVE, null).text().isEmpty());
    }
}
