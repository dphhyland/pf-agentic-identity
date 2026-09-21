/*
 * SSF 1.0 Stream Management API (stream CRUD/status, subject add/remove, verification).
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.StreamManagementService;
import com.pingidentity.ps.oidf.ssf.SubjectId;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.IOException;
import java.util.Map;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The SSF Stream Management API: stream CRUD (POST/GET/PATCH/PUT/DELETE {@code /ssf/streams}), status get/set
 * ({@code /ssf/status}), subject add/remove ({@code /ssf/subjects:add|remove}), and verification
 * ({@code /ssf/verify}). Every request is authenticated with a receiver's OAuth bearer token — validated
 * against PingFederate and required to carry the configured {@code receiverScope} — via
 * {@link com.pingidentity.ps.oidf.ssf.ReceiverAuthenticator}. All logic lives in {@link StreamManagementService};
 * this servlet only marshals HTTP.
 */
@WebServlet(urlPatterns = {"/ssf/streams", "/ssf/status", "/ssf/subjects:add", "/ssf/subjects:remove", "/ssf/verify"})
public class SsfStreamManagementServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(SsfStreamManagementServlet.class);

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        if (SsfHttp.bootstrap(config)) { // fail-soft: unconfigured SSF is disabled, not fatal
            SsfSupport.startPushDelivery(); // background RFC 8935 delivery loop
        }
    }

    /** Route PATCH (not covered by HttpServlet) ourselves; everything else via the standard dispatch. */
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
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        dispatch(req, resp);
    }

    /** Without this the container answers PUT itself, with a 405 the receiver gets before it is authenticated. */
    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        dispatch(req, resp);
    }

    private void dispatch(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        SsfConfiguration cfg = SsfSupport.configuration();
        AuthContext auth = authorize(req, resp, cfg);
        if (auth == null) {
            return; // 401/403/503 already written
        }
        handle(req, resp, SsfSupport.streamService(), auth);
    }

    /** Everything after authentication, against a given service - the seam the servlet is tested through. */
    static void handle(HttpServletRequest req, HttpServletResponse resp, StreamManagementService svc, AuthContext auth)
            throws IOException {
        String path = req.getServletPath();
        String method = req.getMethod().toUpperCase();
        try {
            switch (path) {
                case "/ssf/streams":
                    handleStreams(req, resp, svc, method, auth);
                    break;
                case "/ssf/status":
                    handleStatus(req, resp, svc, method);
                    break;
                case "/ssf/subjects:add":
                    handleSubject(req, resp, svc, method, true);
                    break;
                case "/ssf/subjects:remove":
                    handleSubject(req, resp, svc, method, false);
                    break;
                case "/ssf/verify":
                    handleVerify(req, resp, svc, method);
                    break;
                default:
                    writeError(resp, 404, "not_found", "unknown endpoint");
            }
        } catch (StreamManagementService.NotFoundException e) {
            writeError(resp, 404, "not_found", e.getMessage());
        } catch (IllegalArgumentException | IllegalStateException e) {
            writeError(resp, 400, "invalid_request", e.getMessage());
        } catch (Exception e) {
            log.error((Object) "SSF stream management error", e);
            writeError(resp, 500, "server_error", e.getMessage());
        }
    }

    private static void handleStreams(HttpServletRequest req, HttpServletResponse resp, StreamManagementService svc,
                                      String method, AuthContext auth) throws Exception {
        switch (method) {
            case "POST":
                writeJson(resp, 201, svc.createStream(readBody(req), auth.clientId()));
                break;
            case "GET": {
                String id = req.getParameter("stream_id");
                if (id != null && !id.isBlank()) {
                    writeJson(resp, 200, svc.getStream(id));
                } else {
                    SsfHttp.writeJsonArray(resp, 200, svc.listStreams()); // SSF §8.1.1.2: a list, empty when none
                }
                break;
            }
            case "PATCH": {
                // SSF §8.1.1.3 puts stream_id in the body. The query parameter is what this servlet used
                // to require, and is still read for a caller that has not moved.
                Map<String, Object> body = readBody(req);
                String id = str(body, "stream_id");
                writeJson(resp, 200, svc.updateStream(id != null && !id.isBlank() ? id : requireParam(req, "stream_id"), body));
                break;
            }
            case "PUT": {
                Map<String, Object> body = readBody(req);
                writeJson(resp, 200, svc.replaceStream(reqStr(body, "stream_id"), body));
                break;
            }
            case "DELETE":
                svc.deleteStream(requireParam(req, "stream_id"));
                resp.setStatus(204);
                break;
            default:
                writeError(resp, 405, "method_not_allowed", method);
        }
    }

    private static void handleStatus(HttpServletRequest req, HttpServletResponse resp, StreamManagementService svc,
                                     String method) throws Exception {
        if ("GET".equals(method)) {
            writeJson(resp, 200, svc.getStatus(requireParam(req, "stream_id")));
        } else if ("POST".equals(method)) {
            Map<String, Object> body = readBody(req);
            writeJson(resp, 200, svc.setStatus(reqStr(body, "stream_id"), reqStr(body, "status"), str(body, "reason")));
        } else {
            writeError(resp, 405, "method_not_allowed", method);
        }
    }

    @SuppressWarnings("unchecked")
    private static void handleSubject(HttpServletRequest req, HttpServletResponse resp, StreamManagementService svc,
                                      String method, boolean add) throws Exception {
        if (!"POST".equals(method)) {
            writeError(resp, 405, "method_not_allowed", method);
            return;
        }
        Map<String, Object> body = readBody(req);
        String streamId = reqStr(body, "stream_id");
        Object subj = body.get("subject");
        if (!(subj instanceof Map)) {
            throw new IllegalArgumentException("missing required field: subject");
        }
        SubjectId subject = SubjectId.fromMap((Map<String, Object>) subj);
        // Both are empty responses, and they differ: SSF §8.1.3.2 answers an add with 200, §8.1.3.3 a
        // remove with 204.
        if (add) {
            svc.addSubject(streamId, subject);
            resp.setStatus(200);
        } else {
            svc.removeSubject(streamId, subject);
            resp.setStatus(204);
        }
    }

    private static void handleVerify(HttpServletRequest req, HttpServletResponse resp, StreamManagementService svc,
                                     String method) throws Exception {
        if (!"POST".equals(method)) {
            writeError(resp, 405, "method_not_allowed", method);
            return;
        }
        Map<String, Object> body = readBody(req);
        svc.verify(reqStr(body, "stream_id"), str(body, "state"));
        resp.setStatus(204); // SSF §8.1.4.2: empty. The SET is the answer, and it arrives by the stream.
    }

    // ─────────────────────────────── auth ───────────────────────────────

    private static AuthContext authorize(HttpServletRequest req, HttpServletResponse resp, SsfConfiguration cfg) throws IOException {
        return SsfHttp.authorize(req, resp, cfg);
    }

    // ─────────────────────────────── HTTP helpers ───────────────────────────────

    private static Map<String, Object> readBody(HttpServletRequest req) throws IOException {
        return SsfHttp.readBody(req);
    }

    private static String requireParam(HttpServletRequest req, String name) {
        String v = req.getParameter(name);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("missing required parameter: " + name);
        }
        return v;
    }

    private static String reqStr(Map<String, Object> body, String key) {
        Object v = body.get(key);
        if (!(v instanceof String) || ((String) v).isBlank()) {
            throw new IllegalArgumentException("missing required field: " + key);
        }
        return (String) v;
    }

    private static String str(Map<String, Object> body, String key) {
        Object v = body.get(key);
        return v instanceof String ? (String) v : null;
    }

    private static void writeJson(HttpServletResponse resp, int status, Map<String, Object> body) throws IOException {
        SsfHttp.writeJson(resp, status, body);
    }

    private static void writeError(HttpServletResponse resp, int status, String error, String description)
            throws IOException {
        SsfHttp.writeError(resp, status, error, description);
    }
}
