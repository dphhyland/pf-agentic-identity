/*
 * Operator endpoint: have the transmitter raise a CAEP/RISC event about a subject.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.EmitRequest;
import com.pingidentity.ps.oidf.ssf.SetMinter;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfEmitService;
import com.pingidentity.ps.oidf.ssf.SsfEventEmitter;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import com.pingidentity.ps.oidf.ssf.StreamManagementService;
import java.io.IOException;
import java.util.List;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * {@code POST /ssf/events:emit}: the transmitter's own events come from what it observes - a logout, an
 * audit entry, a SCIM deprovision. This is the way to raise one it did not observe: a device falling out
 * of compliance that another system knows about, or, in a conformance run, the three CAEP Interop events
 * the suite waits for. It takes the provisioner scope, not the receiver's, and answers 403 to everyone when
 * none is configured; {@link SsfEmitService} says why. The body is {@link EmitRequest}; the response lists
 * the streams a SET was enqueued for.
 */
@WebServlet(urlPatterns = "/ssf/events:emit")
public class SsfEventEmitServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(SsfEventEmitServlet.class);

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        SsfHttp.bootstrap(config); // fail-soft: unconfigured SSF is disabled, not fatal
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        SsfConfiguration cfg = SsfSupport.configuration();
        AuthContext auth = SsfHttp.authorizeProvisioner(req, resp, cfg);
        if (auth == null) {
            return;
        }
        handle(req, resp, SsfSupport.emitService(), auth);
    }

    /** Past authentication: the seam tests drive, with no PingFederate behind it. */
    static void handle(HttpServletRequest req, HttpServletResponse resp, SsfEmitService svc, AuthContext auth)
            throws IOException {
        if (!"POST".equalsIgnoreCase(req.getMethod())) {
            SsfHttp.writeError(resp, 405, "method_not_allowed", req.getMethod());
            return;
        }
        try {
            EmitRequest request = EmitRequest.parse(SsfHttp.readBody(req), SetMinter.nowSeconds());
            List<SsfEventEmitter.Emitted> emitted = svc.emit(request, auth);
            SsfHttp.writeJson(resp, 200, SsfEmitService.toJson(request.eventType(), emitted));
        } catch (StreamManagementService.NotFoundException e) {
            SsfHttp.writeError(resp, 404, "not_found", e.getMessage());
        } catch (StreamManagementService.ForbiddenException e) {
            SsfHttp.writeError(resp, 403, "access_denied", e.getMessage());
        } catch (IllegalArgumentException e) {
            SsfHttp.writeError(resp, 400, "invalid_request", e.getMessage());
        } catch (Exception e) {
            log.error((Object) "SSF emit error", e);
            SsfHttp.writeError(resp, 500, "server_error", e.getMessage());
        }
    }
}
