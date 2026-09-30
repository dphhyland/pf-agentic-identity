/*
 * Live and ready answer anyone with the status alone; the detail and info are operator routes with oidf.health.read.
 */
package com.pingidentity.ps.oidf.platform.pf.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.json.Json;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorAuthenticator;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorScopes;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorTestKit;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
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
        final List<String> challenges = new ArrayList<>();
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
        return request(method, path, authorization, null);
    }

    private static HttpServletRequest request(String method, String path, String authorization, String dpop) {
        Map<String, Object> attributes = new HashMap<>();
        return (HttpServletRequest) Proxy.newProxyInstance(HealthServletTest.class.getClassLoader(), new Class<?>[] {HttpServletRequest.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "getMethod" -> method;
                    case "getServletPath", "getRequestURI" -> path;
                    case "getHeader" -> "Authorization".equalsIgnoreCase((String) args[0]) ? authorization : null;
                    case "getHeaders" -> Collections.enumeration("Authorization".equals(args[0])
                            ? (authorization == null ? List.of() : List.of(authorization))
                            : "DPoP".equals(args[0]) && dpop != null ? List.of(dpop) : List.<String>of());
                    case "getRemoteAddr" -> "192.0.2.44";
                    case "getAttribute" -> attributes.get((String) args[0]);
                    case "setAttribute" -> attributes.put((String) args[0], args[1]);
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
                        case "addHeader" -> answer.challenges.add((String) args[1]);
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

    private static HealthServlet servlet(OperatorAuthenticator authenticator) throws Exception {
        Map<String, Object> versions = new LinkedHashMap<>();
        versions.put("agentic-identity", "0.5.0-TEST");
        versions.put("commit", null);
        versions.put("pingfederate", "13.1.3.0");
        HealthServlet servlet = new HealthServlet(() -> authenticator,
                name -> "OIDF_DEPLOYMENT_PROFILE".equals(name) ? "development" : null, () -> versions);
        servlet.init(config());
        return servlet;
    }

    /** Development, no PingFederate token settings, and the static bearer {@link #TOKEN}. */
    private static HealthServlet developmentWithStaticBearer() throws Exception {
        return servlet(OperatorTestKit.unconfigured(DeploymentProfile.DEVELOPMENT).withStaticBearer(TOKEN));
    }

    private static Answer call(HealthServlet servlet, String method, String path, String authorization) throws Exception {
        return call(servlet, method, path, authorization, null);
    }

    private static Answer call(HealthServlet servlet, String method, String path, String authorization, String dpop)
            throws Exception {
        Answer answer = new Answer();
        servlet.service(request(method, path, authorization, dpop), response(answer));
        return answer;
    }

    @Test
    void liveIsUpAndSaysNothingElse() throws Exception {
        Answer a = call(developmentWithStaticBearer(), "GET", HealthServlet.LIVE, null);
        assertEquals(200, a.status);
        assertEquals("{\"status\":\"UP\"}", a.text());
        assertEquals("application/json", a.contentType);
        assertEquals("no-store", a.headers.get("Cache-Control"));
        assertEquals(a.text().length(), a.contentLength);
    }

    @Test
    void readyFollowsTheComponentsAndSaysNothingElse() throws Exception {
        HealthServlet servlet = developmentWithStaticBearer();
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
    void theDetailAndInfoRefuseACallerWithoutACredentialWithTheChallenge() throws Exception {
        HealthServlet servlet = developmentWithStaticBearer();
        for (String path : List.of(HealthServlet.DETAIL, HealthServlet.INFO)) {
            for (String auth : new String[] {null, "Bearer wrong", "Basic " + TOKEN, "Bearer " + TOKEN + "x"}) {
                Answer a = call(servlet, "GET", path, auth);
                assertTrue(a.status == 401 || a.status == 400 || a.status == 429, path + " with " + auth + ": " + a.status);
                assertEquals("", a.text());
                if (a.status != 429) {
                    assertTrue(a.challenges.stream().anyMatch(c -> c.startsWith("DPoP ")), "the DPoP challenge: " + a.challenges);
                }
            }
        }
    }

    @Test
    void theStaticBearerOpensTheDetailInDevelopmentOnly() throws Exception {
        assertEquals(200, call(developmentWithStaticBearer(), "GET", HealthServlet.INFO, "Bearer " + TOKEN).status);
        HealthServlet production = servlet(OperatorTestKit.unconfigured(DeploymentProfile.PRODUCTION).withStaticBearer(TOKEN));
        Answer refused = call(production, "GET", HealthServlet.INFO, "Bearer " + TOKEN);
        assertEquals(503, refused.status, "production never accepts the static bearer, and refuses while it is set");
        assertEquals("", refused.text());
        OperatorTestKit kit = new OperatorTestKit();
        HealthServlet productionOAuth = servlet(kit.authenticator(DeploymentProfile.PRODUCTION).withStaticBearer(TOKEN));
        String token = kit.token(OperatorScopes.HEALTH_READ);
        assertEquals(503, call(productionOAuth, "GET", HealthServlet.INFO, "DPoP " + token,
                kit.proof(token, "GET", HealthServlet.INFO)).status, "even a good token, while the static bearer is set");
    }

    @Test
    void aProductionTokenNeedsTheHealthScopeAndItsProof() throws Exception {
        OperatorTestKit kit = new OperatorTestKit();
        HealthServlet servlet = servlet(kit.authenticator(DeploymentProfile.PRODUCTION));
        String token = kit.token(OperatorScopes.HEALTH_READ);
        Answer ok = call(servlet, "GET", HealthServlet.INFO, "DPoP " + token, kit.proof(token, "GET", HealthServlet.INFO));
        assertEquals(200, ok.status);
        assertEquals("{\"agentic-identity\":\"0.5.0-TEST\",\"commit\":null,\"pingfederate\":\"13.1.3.0\"}", ok.text());

        String admin = kit.token(OperatorScopes.ADMIN_READ);
        Answer lacking = call(servlet, "GET", HealthServlet.DETAIL, "DPoP " + admin, kit.proof(admin, "GET", HealthServlet.DETAIL));
        assertEquals(403, lacking.status, "oidf.admin.read does not read health");
        assertTrue(lacking.challenges.get(0).contains("scope=\"oidf.health.read\""), lacking.challenges.toString());

        String unbound = kit.bearerToken(OperatorScopes.HEALTH_READ);
        assertEquals(401, call(servlet, "GET", HealthServlet.INFO, "Bearer " + unbound).status,
                "production refuses a token bound to nothing");
    }

    @Test
    void aPathTheServletDoesNotNameIs404WithOrWithoutTheBearer() throws Exception {
        // A wildcard mapping, a forward or a named dispatch could bring another servlet path here: it fails closed.
        HealthServlet servlet = developmentWithStaticBearer();
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
        assertEquals(405, call(servlet, "POST", "/agentic-identity", "Bearer " + TOKEN).error);
        // answer() serves nothing it does not name, whoever got the request that far.
        Answer direct = new Answer();
        servlet.answer("/agentic-identity", false, response(direct));
        assertEquals(404, direct.error);
        assertEquals("", direct.text());
    }

    @Test
    void theDetailAnswersWithEveryComponentAndTheReadinessCode() throws Exception {
        HealthServlet servlet = developmentWithStaticBearer();
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
    void onlyGetAndHeadAreServedBeforeAnyTokenAndHeadHasNoBody() throws Exception {
        HealthServlet servlet = developmentWithStaticBearer();
        Answer post = call(servlet, "POST", HealthServlet.LIVE, null);
        assertEquals(405, post.error);
        assertEquals("GET, HEAD", post.headers.get("Allow"));
        Answer put = call(servlet, "PUT", HealthServlet.INFO, null);
        assertEquals(405, put.error, "the method is refused before a token is looked at");
        assertTrue(put.challenges.isEmpty());
        Answer head = call(servlet, "HEAD", HealthServlet.LIVE, null);
        assertEquals(200, head.status);
        assertEquals("", head.text());
        assertEquals("{\"status\":\"UP\"}".length(), head.contentLength);
        Answer headInfo = call(servlet, "HEAD", HealthServlet.INFO, "Bearer " + TOKEN);
        assertEquals(200, headInfo.status);
        assertEquals("", headInfo.text());
    }

    @Test
    void theDefaultServletAsksThisWebappsAuthenticator() throws Exception {
        HealthServlet servlet = new HealthServlet();
        servlet.init(config());
        // No operator settings and no static bearer in this JVM: production, and nothing can be authenticated.
        assertEquals(503, call(servlet, "GET", HealthServlet.INFO, "Bearer " + TOKEN).status);
        assertFalse(call(servlet, "GET", HealthServlet.LIVE, null).text().isEmpty());
    }

    @Test
    void aWarThatCannotLoadTheAuthenticatorFailsClosed() throws Exception {
        Map<String, Object> versions = Map.of("agentic-identity", "0.6.0-TEST");
        HealthServlet servlet = new HealthServlet(() -> {
            throw new NoClassDefFoundError("com/pingidentity/ps/oidf/rs/JwksSource");
        }, name -> null, () -> versions);
        Answer a = call(servlet, "GET", HealthServlet.INFO, "Bearer " + TOKEN);
        assertEquals(503, a.status);
        assertEquals("", a.text());
        assertEquals("no-store", a.headers.get("Cache-Control"));
        assertEquals(200, call(servlet, "GET", HealthServlet.LIVE, null).status, "live and ready need no authenticator");
    }

    @Test
    void theRouteTableNamesTheDetailAndInfoForGetAndHeadOnly() {
        for (String path : List.of(HealthServlet.DETAIL, HealthServlet.INFO)) {
            for (String method : List.of("GET", "HEAD")) {
                assertEquals(OperatorScopes.HEALTH_READ, HealthServlet.ROUTES.match(method, path).orElseThrow().scope());
            }
            assertTrue(HealthServlet.ROUTES.match("POST", path).isEmpty());
        }
        assertTrue(HealthServlet.ROUTES.match("GET", HealthServlet.LIVE).isEmpty(), "live is open");
        assertTrue(HealthServlet.ROUTES.match("GET", HealthServlet.READY).isEmpty(), "ready is open");
    }
}
