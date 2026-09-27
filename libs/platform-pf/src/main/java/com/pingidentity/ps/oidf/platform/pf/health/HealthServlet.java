/*
 * /agentic-identity/health/{live,ready}, /agentic-identity/health and /agentic-identity/info.
 */
package com.pingidentity.ps.oidf.platform.pf.health;

import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Health;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.json.Json;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * The health endpoints (plan item O-4), mapped by annotation in whichever war holds platform-pf's jar in
 * {@code WEB-INF/lib} - {@code pf-runtime.war}, where {@code assemble-pf-runtime-war.sh} merges it, so on
 * PingFederate's runtime port - and answering from that war's own component registry. The engine's copy of the jar
 * in {@code server/default/deploy} is never scanned for annotations and never serves a request.
 *
 * <ul>
 *   <li>{@value #LIVE}: 200 {@code {"status":"UP"}} whenever this webapp answers.</li>
 *   <li>{@value #READY}: 200 {@code {"status":"UP"}}, or 503 {@code {"status":"DOWN"}} when an enabled component is
 *       not ready ({@link Health#readiness}).</li>
 *   <li>{@value #DETAIL}: each component's state and reason, its parts, the profile and the versions, with the
 *       readiness status and code; {@value #INFO}: the versions.</li>
 * </ul>
 *
 * <p>Live and ready are open and say nothing but the status. The detail and info answer only a caller presenting
 * the static admin bearer token ({@link HealthAccess}); anyone else - a wrong token, no token, or a deployment with no
 * token configured - gets the container's 404 for every method, as if nothing were mapped there. S8b (Phase 3) moves
 * them behind the operator scope {@code oidf.health.read}. Only GET and HEAD are served; any other method is 405.
 * Every answer is JSON and {@code Cache-Control: no-store}.
 */
@WebServlet(urlPatterns = {HealthServlet.LIVE, HealthServlet.READY, HealthServlet.DETAIL, HealthServlet.INFO})
public class HealthServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    public static final String LIVE = "/agentic-identity/health/live";
    public static final String READY = "/agentic-identity/health/ready";
    public static final String DETAIL = "/agentic-identity/health";
    public static final String INFO = "/agentic-identity/info";

    private final transient Function<String, String> systemProperties;
    private final transient Function<String, String> environment;
    private final transient Supplier<Map<String, Object>> versions;
    private transient String token;

    public HealthServlet() {
        this(System::getProperty, System::getenv, () -> BuildInfo.read(HealthServlet.class.getClassLoader()));
    }

    HealthServlet(Function<String, String> systemProperties, Function<String, String> environment,
            Supplier<Map<String, Object>> versions) {
        this.systemProperties = systemProperties;
        this.environment = environment;
        this.versions = versions;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        this.token = HealthAccess.resolveToken(this.systemProperties, this.environment);
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getServletPath();
        boolean restricted = DETAIL.equals(path) || INFO.equals(path);
        if (restricted && !HealthAccess.isAuthorized(this.token, req.getHeader("Authorization"))) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        String method = req.getMethod();
        if (!"GET".equals(method) && !"HEAD".equals(method)) {
            resp.setHeader("Allow", "GET, HEAD");
            resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }
        this.answer(path, "HEAD".equals(method), resp);
    }

    /** Writes the answer for {@code path}, one of the four mapped. */
    void answer(String path, boolean head, HttpServletResponse resp) throws IOException {
        if (LIVE.equals(path)) {
            write(resp, HttpServletResponse.SC_OK, Health.status(Health.Status.UP), head);
            return;
        }
        if (INFO.equals(path)) {
            write(resp, HttpServletResponse.SC_OK, this.versions.get(), head);
            return;
        }
        ComponentParts parts = Startup.parts();
        parts.refresh();
        List<ComponentStatus> components = Components.snapshot();
        Health.Status status = Health.readiness(components);
        int code = status == Health.Status.UP ? HttpServletResponse.SC_OK : HttpServletResponse.SC_SERVICE_UNAVAILABLE;
        if (READY.equals(path)) {
            write(resp, code, Health.status(status), head);
            return;
        }
        write(resp, code, Health.detail(components, parts.parts(), DeploymentProfile.of(this.environment).value(),
                this.versions.get()), head);
    }

    private static void write(HttpServletResponse resp, int code, Map<String, Object> body, boolean head) throws IOException {
        byte[] bytes = Json.write(body).getBytes(StandardCharsets.UTF_8);
        resp.setStatus(code);
        resp.setHeader("Cache-Control", "no-store");
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.setContentLength(bytes.length);
        if (!head) {
            resp.getOutputStream().write(bytes);
        }
    }
}
