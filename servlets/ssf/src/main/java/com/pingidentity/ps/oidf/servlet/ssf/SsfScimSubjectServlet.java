/*
 * SCIM 2.0 subject-management endpoint: provisioning flows drive SSF stream subjects.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.ScimSubjectService;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import com.pingidentity.ps.oidf.ssf.StreamManagementService;
import com.pingidentity.ps.oidf.ssf.SubjectId;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A SCIM 2.0 {@code /Users} resource that maps provisioning to SSF stream membership. {@code POST}/{@code PUT}
 * a user with the {@code urn:ietf:params:scim:schemas:extension:ssf:2.0:Subject} extension (carrying stream
 * id(s)) to make it a subject of those streams; {@code active:false} or {@code DELETE} removes the subject from
 * every stream and emits a RISC {@code account-disabled}. Wire it as an inbound SCIM target in PF like any SCIM
 * app. Its authority is its own: a bearer token carrying {@code provisionerScope}, which is unset by default
 * (the endpoint then refuses everyone) and is never the receiver scope. A provisioner owns no streams and
 * acts across every receiver's; a receiver cannot use this endpoint at all, because a deprovision makes the
 * transmitter sign an account-disabled about whichever subject the caller names. Logic lives in
 * {@link ScimSubjectService}.
 */
@WebServlet(urlPatterns = {"/ssf/scim/v2/Users", "/ssf/scim/v2/Users/*"})
public class SsfScimSubjectServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(SsfScimSubjectServlet.class);

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
        SsfConfiguration cfg = SsfSupport.configuration();
        AuthContext auth = SsfHttp.authorizeProvisioner(req, resp, cfg);
        if (auth == null) {
            return;
        }
        ScimSubjectService svc = SsfSupport.scimSubjectService();
        String method = req.getMethod().toUpperCase();
        try {
            switch (method) {
                case "POST":
                    SsfHttp.writeJson(resp, 201, svc.provision(SsfHttp.readBody(req), auth));
                    break;
                case "PUT":
                    SsfHttp.writeJson(resp, 200, svc.provision(SsfHttp.readBody(req), auth));
                    break;
                case "PATCH":
                    handlePatch(req, resp, svc, auth);
                    break;
                case "DELETE":
                    svc.deprovision(subjectFromPath(req), auth);
                    resp.setStatus(204);
                    break;
                default:
                    SsfHttp.writeError(resp, 405, "method_not_allowed", method);
            }
        } catch (StreamManagementService.NotFoundException e) {
            SsfHttp.writeError(resp, 404, "not_found", e.getMessage());
        } catch (StreamManagementService.ForbiddenException e) {
            SsfHttp.writeError(resp, 403, "access_denied", e.getMessage());
        } catch (IllegalArgumentException e) {
            SsfHttp.writeError(resp, 400, "invalid_request", e.getMessage());
        } catch (Exception e) {
            log.error((Object) "SSF SCIM error", e);
            SsfHttp.writeError(resp, 500, "server_error", e.getMessage());
        }
    }

    /** Minimal SCIM PatchOp: {@code active:false} deprovisions; otherwise assign the referenced stream id(s). */
    @SuppressWarnings("unchecked")
    private void handlePatch(HttpServletRequest req, HttpServletResponse resp, ScimSubjectService svc, AuthContext auth)
            throws Exception {
        SubjectId subject = subjectFromPath(req);
        Map<String, Object> body = SsfHttp.readBody(req);
        Object operations = body.get("Operations");
        boolean disable = false;
        List<String> streams = new ArrayList<>();
        if (operations instanceof List) {
            for (Object o : (List<Object>) operations) {
                if (!(o instanceof Map)) {
                    continue;
                }
                Map<String, Object> op = (Map<String, Object>) o;
                String path = op.get("path") == null ? "" : op.get("path").toString();
                Object value = op.get("value");
                if ("active".equalsIgnoreCase(path) && isFalse(value)) {
                    disable = true;
                }
                if (value instanceof Map) {
                    Map<String, Object> v = (Map<String, Object>) value;
                    if (Boolean.FALSE.equals(v.get("active"))) {
                        disable = true;
                    }
                    collectStreams(v, streams);
                }
                if (path.contains("streams") && value instanceof List) {
                    for (Object s : (List<Object>) value) {
                        if (s != null) {
                            streams.add(s.toString());
                        }
                    }
                }
            }
        }
        if (disable) {
            svc.deprovision(subject, auth);
        } else {
            svc.assign(subject, streams, auth);
        }
        SsfHttp.writeJson(resp, 200, Map.of("id", subject.canonicalKey(), "active", !disable));
    }

    @SuppressWarnings("unchecked")
    private static void collectStreams(Map<String, Object> value, List<String> out) {
        Object direct = value.get("streams");
        if (direct instanceof List) {
            for (Object s : (List<Object>) direct) {
                if (s != null) {
                    out.add(s.toString());
                }
            }
        }
        Object ext = value.get(ScimSubjectService.SSF_EXT);
        if (ext instanceof Map) {
            collectStreams((Map<String, Object>) ext, out);
        }
    }

    private static boolean isFalse(Object v) {
        return Boolean.FALSE.equals(v) || "false".equalsIgnoreCase(String.valueOf(v));
    }

    /** The subject a path-addressed request targets: the SCIM {@code id} is the subject's canonical key. */
    private static SubjectId subjectFromPath(HttpServletRequest req) {
        String pathInfo = req.getPathInfo();
        if (pathInfo == null || pathInfo.length() <= 1) {
            throw new IllegalArgumentException("missing SCIM user id in path");
        }
        String id = URLDecoder.decode(pathInfo.substring(1), StandardCharsets.UTF_8);
        return SubjectId.fromCanonicalKey(id);
    }
}
