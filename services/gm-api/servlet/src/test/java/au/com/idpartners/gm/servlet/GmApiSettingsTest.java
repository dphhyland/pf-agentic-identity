package au.com.idpartners.gm.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.metrics.MetricSnapshot;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import com.pingidentity.ps.oidf.platform.metrics.SeriesSnapshot;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.sun.net.httpserver.HttpServer;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * gm-api's settings through its catalogue (plan item ST-5): strict, init-param first and then the environment, and the
 * PDP reached over https unless the profile is development (PR-3), refused at init as FAILED_CONFIG. And the gm events
 * (O-2): each decision GrantOperations reaches is emitted, catalogued and counted.
 */
class GmApiSettingsTest {

    private final List<Event> events = new CopyOnWriteArrayList<>();
    private HttpServer server;

    @BeforeEach
    void capture() {
        Events.reset();
        Events.configure(e -> {
            if (e.component().equals(GrantOperations.EVENTS)) {
                this.events.add(e);
            }
        });
    }

    @AfterEach
    void forget() {
        Events.reset();
        if (this.server != null) {
            this.server.stop(0);
        }
    }

    private static Function<String, String> env(String... pairs) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put(pairs[i], pairs[i + 1]);
        }
        return map::get;
    }

    private static Function<String, String> development() {
        return env(DeploymentProfile.SETTING, "development");
    }

    // ---- settings -----------------------------------------------------------------------------------------------------

    @Test
    void theInitParamWinsOverTheEnvironmentAndEachIsReadStrictly() throws Exception {
        McpServlet.ServletConfigs cfg = McpServlet.ServletConfigs.from(
                env("AUTHZEN_BASE_URL", "https://env.example", "AUTHZEN_BEARER_TOKEN", "t0k", "GM_AUDIENCE", "https://env/aud"),
                env("pdpUrl", "https://pdp.example", "pdpTimeoutMs", "2500"));
        assertEquals("https://pdp.example", cfg.pdpUrl());
        assertEquals("t0k", cfg.pdpToken(), "no init-param, so the variable");
        assertEquals("https://env/aud", cfg.audience());
        assertEquals(2500, cfg.pdpTimeoutMs());

        McpServlet.ServletConfigs defaults = McpServlet.ServletConfigs.from(env("AUTHZEN_BASE_URL", "https://env.example"), env());
        assertEquals("https://env.example", defaults.pdpUrl());
        assertNull(defaults.pdpToken());
        assertEquals(10_000, defaults.pdpTimeoutMs());

        SettingRefused timeout = assertThrows(SettingRefused.class, () -> McpServlet.ServletConfigs.from(
                env(), env("pdpUrl", "https://pdp.example", "pdpTimeoutMs", "ten seconds")));
        assertTrue(timeout.getMessage().contains("pdpTimeoutMs"), timeout.getMessage());
        SettingRefused url = assertThrows(SettingRefused.class, () -> McpServlet.ServletConfigs.from(env(), env("pdpUrl", "pdp.example")));
        assertTrue(url.getMessage().contains("pdpUrl"), url.getMessage());
        ServletException missing = assertThrows(ServletException.class, () -> McpServlet.ServletConfigs.from(env(), env()));
        assertTrue(missing.getMessage().contains("pdpUrl"), missing.getMessage());
    }

    @Test
    void thePdpMustBeHttpsUnlessTheProfileIsDevelopment() throws Exception {
        for (Function<String, String> production : List.of(env(), env(DeploymentProfile.SETTING, "production"))) {
            ServletException refused = assertThrows(ServletException.class,
                    () -> McpServlet.ServletConfigs.from(production, env("pdpUrl", "http://pdp.example:9099")));
            assertTrue(refused.getMessage().contains("pdpUrl") && refused.getMessage().contains("https"), refused.getMessage());
            assertTrue(!refused.getMessage().contains("pdp.example"), "the URL itself is not repeated");
        }
        assertEquals("http://pdp.example:9099",
                McpServlet.ServletConfigs.from(development(), env("pdpUrl", "http://pdp.example:9099")).pdpUrl());
        assertEquals("https://pdp.example", McpServlet.ServletConfigs.from(env(), env("pdpUrl", "https://pdp.example")).pdpUrl());
        assertEquals("HTTPS://pdp.example", McpServlet.ServletConfigs.from(env(), env("pdpUrl", "HTTPS://pdp.example")).pdpUrl(),
                "the scheme in any case");
    }

    @Test
    void anHttpPdpInProductionLeavesGmApiFailedConfigNamingPdpUrl() {
        assumeTrue(DeploymentProfile.current().isProduction(), "this JVM runs under the development profile");
        ServletConfig config = (ServletConfig) Proxy.newProxyInstance(ServletConfig.class.getClassLoader(),
                new Class<?>[] {ServletConfig.class}, (proxy, m, args) -> switch (m.getName()) {
                    case "getServletName" -> "gm-api-test";
                    case "getInitParameter" -> Map.of("pdpUrl", "http://host.docker.internal:9099", "audience",
                            "https://gm-api.demo/grants").get((String) args[0]);
                    default -> null;
                });
        assertThrows(ServletException.class, () -> new GrantsServlet().init(config));
        assertEquals(ComponentState.FAILED_CONFIG, Components.status(GrantsServlet.COMPONENT).orElseThrow().state());
        assertTrue(Components.status(GrantsServlet.COMPONENT).orElseThrow().reason().contains("pdpUrl"),
                Components.status(GrantsServlet.COMPONENT).orElseThrow().reason());
    }

    @Test
    void theMetadataServletReadsItsTwoSettingsStrictly() {
        assertEquals("https://as.example",
                McpServlet.ServletConfigs.settings(env(), env("issuer", " https://as.example ")).string("issuer"));
        SettingRefused endpoint = assertThrows(SettingRefused.class, () -> McpServlet.ServletConfigs.settings(env(),
                env("grantManagementEndpoint", "not a url")).url("grantManagementEndpoint"));
        assertTrue(endpoint.getMessage().contains("grantManagementEndpoint"), endpoint.getMessage());
    }

    // ---- events -------------------------------------------------------------------------------------------------------

    private GrantOperations opsAnswering(String body) throws Exception {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.createContext("/", ex -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(bytes);
            }
        });
        this.server.start();
        return new GrantOperations(new PfTokenVerifier((com.pingidentity.access.JwksEndpointKeyAccessor) null, "aud"),
                new PdpClient("http://127.0.0.1:" + this.server.getAddress().getPort(), null, 2000));
    }

    private static GrantView grant() {
        return new GrantView("grant-123", "alice", "acme", List.of(GrantEvaluator.SCOPE_EVALUATE),
                System.currentTimeMillis() + 86_400_000L, List.of(Map.of("type", "account_information")));
    }

    private static long counted(String code, String outcome) {
        for (MetricSnapshot metric : Metrics.snapshot()) {
            if (metric.getName().equals("oidf_events_total")) {
                for (SeriesSnapshot series : metric.getSeries()) {
                    if (series.getLabelValues().contains(code) && series.getLabelValues().contains(outcome)) {
                        return (long) series.getValue();
                    }
                }
            }
        }
        return 0L;
    }

    @Test
    void aPdpAnswerIsEmittedAndCountedAsGmGrantEvaluated() throws Exception {
        long before = counted(GrantOperations.EVALUATED, "success");
        GrantOperations ops = opsAnswering("{\"decision\":false,\"context\":{\"id\":\"subject_not_entitled\","
                + "\"reason_user\":{\"en\":\"no\"}}}");
        ops.evaluate(grant(), new TokenClaims("alice", "acme", "grant-123", List.of(GrantEvaluator.SCOPE_EVALUATE)),
                "account", "111", "read_balance", null, null);

        assertEquals(1, this.events.size(), String.valueOf(this.events));
        Event e = this.events.get(0);
        assertEquals(GrantOperations.EVALUATED, e.code());
        assertEquals(Event.Outcome.SUCCESS, e.outcome());
        assertEquals(Map.of("grant_id", "grant-123", "client_id", "acme", "decision", "deny", "reason_id", "subject_not_entitled"),
                e.fields());
        assertTrue(e.audit());
        assertEquals(before + 1, counted(GrantOperations.EVALUATED, "success"));
    }

    @Test
    void anAuthorizationServerRefusalIsEmittedAndCountedAsGmGrantRefused() throws Exception {
        long before = counted(GrantOperations.REFUSED, "failure");
        GrantOperations ops = opsAnswering("{\"decision\":true}");
        ops.evaluate(grant(), new TokenClaims("alice", "someone-else", "grant-123", List.of(GrantEvaluator.SCOPE_EVALUATE)),
                "account", "111", "read_balance", null, null);
        ops.evaluate(null, new TokenClaims("alice", "acme", null, List.of(GrantEvaluator.SCOPE_EVALUATE)),
                "account", "111", "read_balance", null, null);

        assertEquals(2, this.events.size(), String.valueOf(this.events));
        Event notYours = this.events.get(0);
        assertEquals(GrantOperations.REFUSED, notYours.code());
        assertEquals(Event.Outcome.FAILURE, notYours.outcome());
        assertEquals(GrantEvaluator.Refusal.NOT_YOUR_GRANT.code, notYours.reason());
        assertEquals(Map.of("grant_id", "grant-123", "client_id", "someone-else", "reason_id", "unauthorized"), notYours.fields());
        assertEquals(Map.of("client_id", "acme", "reason_id", "grant_not_found"), this.events.get(1).fields(),
                "no grant, so no grant_id");
        assertEquals(before + 2, counted(GrantOperations.REFUSED, "failure"));
    }
}
