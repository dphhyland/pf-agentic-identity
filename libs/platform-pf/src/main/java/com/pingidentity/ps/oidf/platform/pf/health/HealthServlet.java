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
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorAuthenticator;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorRoute;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorRoutes;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorScopes;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
 * <p>Live and ready are open and say nothing but the status. The detail and info are operator routes ({@link #ROUTES}):
 * each needs a PingFederate-issued access token with the scope {@code oidf.health.read}, checked by this webapp's
 * {@link OperatorAuthenticator} - DPoP-bound in production, and in development the static bearer as well - and a
 * refusal is the authenticator's 401, 403, 429 or 503 with its challenge (plan item S8b; finding F-0194 closed the
 * second copy of the static-bearer rule that lived here). Only GET and HEAD are served; any other method is 405, before
 * a token is looked at. Every answer is JSON and {@code Cache-Control: no-store}.
 */
@WebServlet(urlPatterns = {HealthServlet.LIVE, HealthServlet.READY, HealthServlet.DETAIL, HealthServlet.INFO})
public class HealthServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final PlatformLog LOG = PlatformLog.get(HealthServlet.class);

    public static final String LIVE = "/agentic-identity/health/live";
    public static final String READY = "/agentic-identity/health/ready";
    public static final String DETAIL = "/agentic-identity/health";
    public static final String INFO = "/agentic-identity/info";

    /** The detail's route: read, with {@code oidf.health.read}. */
    public static final OperatorRoute DETAIL_ROUTE = OperatorRoute.read("health.detail", OperatorScopes.HEALTH_READ);
    /** /agentic-identity/info's route: read, with {@code oidf.health.read}. */
    public static final OperatorRoute INFO_ROUTE = OperatorRoute.read("health.info", OperatorScopes.HEALTH_READ);

    /**
     * The operator routes this servlet serves, by method and servlet path: the table lives beside the paths it names
     * (platform-pf's own), and HealthRoutesTest holds it to the {@code @WebServlet} mapping.
     */
    public static final OperatorRoutes ROUTES = OperatorRoutes.builder()
            .route("GET", DETAIL, DETAIL_ROUTE).route("HEAD", DETAIL, DETAIL_ROUTE)
            .route("GET", INFO, INFO_ROUTE).route("HEAD", INFO, INFO_ROUTE)
            .build();

    private final transient Function<String, String> environment;
    private final transient Supplier<Map<String, Object>> versions;
    private final transient Supplier<OperatorAuthenticator> authenticator;

    public HealthServlet() {
        this(OperatorAuthenticator::shared, System::getenv, () -> BuildInfo.read(HealthServlet.class.getClassLoader()));
    }

    HealthServlet(Supplier<OperatorAuthenticator> authenticator, Function<String, String> environment,
            Supplier<Map<String, Object>> versions) {
        this.authenticator = authenticator;
        this.environment = environment;
        this.versions = versions;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getServletPath();
        String method = req.getMethod();
        boolean open = LIVE.equals(path) || READY.equals(path);
        if (!"GET".equals(method) && !"HEAD".equals(method)) {
            resp.setHeader("Allow", "GET, HEAD");
            resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }
        // Fails closed: only live and ready are open. Any other servlet path - the detail, info, or one a later
        // mapping or dispatch brings here - needs its route, and answer() serves nothing it does not name.
        if (!open) {
            Optional<OperatorRoute> route = ROUTES.match(method, path);
            if (route.isEmpty()) {
                resp.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }
            boolean authorised;
            try {
                authorised = this.authenticator.get().authorise(req, resp, route.get());
            } catch (LinkageError e) {
                // A war that bundles platform-pf without rs-validation (gm-api.war: platform-pf declares it optional)
                // cannot authenticate an operator, so the detail and info fail closed there.
                LOG.warn("The health detail and info answer 503 in this war: the operator authenticator cannot load"
                        + " (" + e + "); the war needs rs-validation beside platform-pf");
                resp.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                resp.setHeader("Cache-Control", "no-store");
                resp.setContentLength(0);
                return;
            }
            if (!authorised) {
                return;
            }
        }
        this.answer(path, "HEAD".equals(method), resp);
    }

    /** Writes the answer for {@code path}, one of the four mapped; any other path is the container's 404. */
    void answer(String path, boolean head, HttpServletResponse resp) throws IOException {
        if (!LIVE.equals(path) && !READY.equals(path) && !DETAIL.equals(path) && !INFO.equals(path)) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
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
