/*
 * SCIM 2.0 subject-management endpoint: provisioning flows drive SSF stream subjects.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.ScimException;
import com.pingidentity.ps.oidf.ssf.ScimSubjectService;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;

/**
 * A SCIM 2.0 {@code /Users} resource that maps provisioning to SSF stream membership (RFC 7644; plan item H-SSF-4).
 * {@code POST} creates a user with the {@code urn:ietf:params:scim:schemas:extension:ssf:2.0:Subject} extension
 * (carrying stream id(s)) and makes it a subject of those streams; {@code GET} reads one user or a filtered list;
 * {@code PUT} replaces a user; {@code PATCH} changes one; {@code active:false} or {@code DELETE} removes the subject
 * from every stream and emits a RISC {@code account-disabled}, and {@code active} back to true restores it and emits
 * {@code account-enabled}. Wire it as an inbound SCIM target in PF like any SCIM app. Its authority is its own: a bearer
 * token carrying {@code provisionerScope}, which is unset by default (the endpoint then refuses everyone) and is never
 * the receiver scope. A provisioner owns no streams and acts across every receiver's; a receiver cannot use this
 * endpoint at all, because a deprovision makes the transmitter sign an account-disabled about whichever subject the
 * caller names. Logic lives in {@link ScimSubjectService}.
 *
 * <p>Errors are in the RFC 7644 §3.12 error schema ({@link ScimException}), those of token validation included: the
 * 401, 403 and 503 {@link SsfHttp#authorizeProvisioner} writes are re-written in it, status and headers kept. The
 * component gate's own answers - 503 while SSF is starting or failed, an empty 404 while it is off - are the same on
 * every SSF surface and are left as they are.
 */
@WebServlet(urlPatterns = {"/ssf/scim/v2/Users", "/ssf/scim/v2/Users/*"})
public class SsfScimSubjectServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(SsfScimSubjectServlet.class);

    /** RFC 7644 §3.1: "SCIM uses a media type of "application/scim+json"". */
    static final String SCIM_JSON = "application/scim+json";

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        SsfHttp.bootstrap(config); // fail-soft: unconfigured SSF is disabled, not fatal
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if ("PATCH".equalsIgnoreCase(req.getMethod())) {
            dispatch(req, resp);
        } else {
            super.service(req, resp);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        dispatch(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        dispatch(req, resp);
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        dispatch(req, resp);
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        dispatch(req, resp);
    }

    private void dispatch(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (SsfHttp.gate(resp)) {
            return; // the transmitter is starting, failed, refused (503) or off (404)
        }
        SsfConfiguration cfg = SsfSupport.configuration();
        AuthContext auth = authorize(req, resp, cfg);
        if (auth == null) {
            return;
        }
        handle(req, resp, SsfSupport.scimSubjectService(), auth);
    }

    /**
     * {@link SsfHttp#authorizeProvisioner}, its refusal re-written in the SCIM error schema: the status and the headers
     * it set ({@code WWW-Authenticate}, {@code Cache-Control}) stand, its {@code error_description} is the
     * {@code detail}.
     */
    static AuthContext authorize(HttpServletRequest req, HttpServletResponse resp, SsfConfiguration cfg) throws IOException {
        Captured captured = new Captured(resp);
        AuthContext auth = SsfHttp.authorizeProvisioner(req, captured, cfg);
        if (auth == null) {
            Map<String, Object> oauth = captured.json();
            // Every refusal SsfHttp writes carries an error_description.
            writeScim(resp, captured.status, ScimException.body(captured.status, null,
                    java.util.Objects.toString(oauth.get("error_description"), null)));
        }
        return auth;
    }

    /** Everything after authentication, against a given service - the seam the servlet is tested through. */
    static void handle(HttpServletRequest req, HttpServletResponse resp, ScimSubjectService svc, AuthContext auth)
            throws IOException {
        String method = req.getMethod().toUpperCase();
        String id = idFromPath(req);
        try {
            switch (method) {
                case "GET":
                    if (id == null) {
                        writeScim(resp, 200, svc.query(req.getParameter("filter"), intParam(req, "startIndex"),
                                intParam(req, "count"), auth));
                    } else {
                        writeScim(resp, 200, svc.get(id, auth));
                    }
                    break;
                case "POST":
                    if (id != null) {
                        throw new ScimException(405, null, "POST creates a user at /Users; a user is changed with PUT or PATCH");
                    }
                    Map<String, Object> created = svc.create(body(req), auth);
                    resp.setHeader("Location", location(created));
                    writeScim(resp, 201, created);
                    break;
                case "PUT":
                    writeScim(resp, 200, svc.replace(requireId(id), body(req), auth));
                    break;
                case "PATCH":
                    writeScim(resp, 200, svc.patch(requireId(id), body(req), auth));
                    break;
                case "DELETE":
                    svc.delete(requireId(id), auth);
                    resp.setStatus(204);
                    break;
                default:
                    throw new ScimException(405, null, method + " is not supported here");
            }
        } catch (ScimException e) {
            writeScim(resp, e.status(), e.body());
        } catch (IllegalArgumentException e) {
            // A value the store or a stream refused, such as a stream deleted between the check and the write.
            writeScim(resp, 400, ScimException.body(400, "invalidValue", e.getMessage()));
        } catch (Exception e) {
            log.error((Object) "SSF SCIM error", e);
            writeScim(resp, 500, ScimException.body(500, null, "internal error; see the server log"));
        }
    }

    /** The request body; one that is not JSON is 400 {@code invalidSyntax}. */
    private static Map<String, Object> body(HttpServletRequest req) throws IOException {
        try {
            return SsfHttp.readBody(req);
        } catch (IllegalArgumentException e) {
            throw ScimException.badRequest("invalidSyntax", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static String location(Map<String, Object> resource) {
        return (String) ((Map<String, Object>) resource.get("meta")).get("location");
    }

    /**
     * The SCIM {@code id} a path addresses, or {@code null} for {@code /Users}. The container has decoded the path, so
     * it is read as it is; the {@code id} is the subject's canonical key.
     */
    private static String idFromPath(HttpServletRequest req) {
        String pathInfo = req.getPathInfo();
        return pathInfo == null || pathInfo.length() <= 1 ? null : pathInfo.substring(1);
    }

    private static String requireId(String id) {
        if (id == null) {
            throw new ScimException(405, null, "this method addresses one user: /Users/{id}");
        }
        return id;
    }

    /** An integer query parameter, or {@code null}; one that is not an integer is 400 {@code invalidValue}. */
    private static Integer intParam(HttpServletRequest req, String name) {
        String v = req.getParameter(name);
        if (v == null || v.isBlank()) {
            return null;
        }
        try {
            return Integer.valueOf(v.trim());
        } catch (NumberFormatException e) {
            throw ScimException.badRequest("invalidValue", name + " must be an integer");
        }
    }

    static void writeScim(HttpServletResponse resp, int status, Map<String, Object> body) throws IOException {
        resp.setStatus(status);
        resp.setContentType(SCIM_JSON);
        resp.setCharacterEncoding("UTF-8");
        resp.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(body));
        }
    }

    /** Holds back what {@link SsfHttp} writes, so it can be written again in the SCIM error schema; headers pass through. */
    private static final class Captured extends HttpServletResponseWrapper {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private int status = 200;

        Captured(HttpServletResponse response) {
            super(response);
        }

        @Override
        public void setStatus(int sc) {
            this.status = sc;
        }

        @Override
        public void setContentType(String type) {
            // the SCIM body sets its own
        }

        @Override
        public PrintWriter getWriter() {
            return new PrintWriter(this.bytes, true, StandardCharsets.UTF_8);
        }

        Map<String, Object> json() {
            try {
                return JsonUtil.parseJson(this.bytes.toString(StandardCharsets.UTF_8));
            } catch (Exception e) {
                return Map.of();
            }
        }
    }
}
