/*
 * SSF poll-delivery endpoint (RFC 8936).
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.StreamManagementService;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
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
 * Poll-based SET delivery per RFC 8936. A poll stream's transmitter-assigned URL is
 * {@code <issuer>/ssf/poll?stream_id=<id>}; the receiver POSTs the RFC 8936 request body
 * ({@code maxEvents}, {@code returnImmediately}, {@code ack}) there. The response is
 * {@code {"sets": {jti: <compact JWS>, …}, "moreAvailable": <bool>}}; acked jtis are deleted before the next
 * batch is returned. Authenticated with the same receiver bearer token as the management API.
 */
@WebServlet(urlPatterns = {"/ssf/poll"})
public class SsfPollServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(SsfPollServlet.class);

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            SsfSupport.installStoreFactory(new PfJdbcStoreFactory()); // JDBC store when dataStoreId is set
            SsfSupport.configure(SsfConfiguration.fromServletConfig(config));
        } catch (Exception e) {
            throw new ServletException("Failed to initialize SSF poll servlet", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        SsfConfiguration cfg = SsfSupport.configuration();
        if (SsfHttp.authorize(req, resp, cfg) == null) {
            return;
        }
        String streamId = req.getParameter("stream_id");
        if (streamId == null || streamId.isBlank()) {
            SsfHttp.writeError(resp, 400, "invalid_request", "missing required parameter: stream_id");
            return;
        }
        try {
            Map<String, Object> body = SsfHttp.readBody(req);
            List<String> acks = parseStringList(body.get("ack"));
            Integer maxEvents = parseInt(body.get("maxEvents"));
            boolean returnImmediately = !Boolean.FALSE.equals(body.get("returnImmediately"));
            StreamManagementService svc = SsfSupport.streamService();
            SsfHttp.writeJson(resp, 200, svc.poll(streamId, acks, maxEvents, returnImmediately));
        } catch (StreamManagementService.NotFoundException e) {
            SsfHttp.writeError(resp, 404, "not_found", e.getMessage());
        } catch (IllegalArgumentException e) {
            SsfHttp.writeError(resp, 400, "invalid_request", e.getMessage());
        } catch (Exception e) {
            log.error((Object) "SSF poll error", e);
            SsfHttp.writeError(resp, 500, "server_error", e.getMessage());
        }
    }

    private static List<String> parseStringList(Object raw) {
        List<String> out = new ArrayList<>();
        if (raw instanceof Iterable) {
            for (Object o : (Iterable<?>) raw) {
                if (o != null) {
                    out.add(o.toString());
                }
            }
        }
        return out;
    }

    private static Integer parseInt(Object raw) {
        if (raw instanceof Number) {
            return ((Number) raw).intValue();
        }
        if (raw instanceof String && !((String) raw).isBlank()) {
            try {
                return Integer.valueOf(((String) raw).trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}
