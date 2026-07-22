/*
 * RFC 8935 push-delivery RECEIVER endpoint: accepts inbound Security Event Tokens.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.SetVerifier;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfReceiverService;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;

/**
 * The receiver side of RFC 8935: a transmitter POSTs each SET here with
 * {@code Content-Type: application/secevent+jwt}. The SET is verified against the configured transmitter's
 * JWKS ({@code receiverExpectedIssuer} / {@code receiverJwksUrl}), duplicates are accepted idempotently, and
 * verified SETs are dispatched to the registered handlers. Responses per RFC 8935 §2.3–2.4: {@code 202} on
 * acceptance (including duplicates), {@code 400} with {@code {"err": "...", "description": "..."}} on
 * verification failure. When {@code receiverEndpointAuthToken} is configured, the POST must carry it as a
 * bearer token ({@code 401} otherwise).
 *
 * <p>{@code GET} serves a bounded recent-events summary for demos/inspection (same bearer when configured).
 * The receiver is active only when {@code receiverExpectedIssuer} is set; otherwise both methods return 404.
 */
@WebServlet(urlPatterns = {"/ssf/receiver/events"})
public class SsfReceiverServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(SsfReceiverServlet.class);

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        SsfHttp.bootstrap(config); // fail-soft: unconfigured SSF disables the endpoints
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        SsfReceiverService receiver = SsfSupport.receiverService();
        if (receiver == null) {
            SsfHttp.writeError(resp, 404, "not_found", "SSF receiver is not configured");
            return;
        }
        if (!endpointAuthorized(req, resp)) {
            return;
        }
        String contentType = req.getContentType();
        if (contentType == null || !contentType.toLowerCase().contains("secevent+jwt")) {
            writeRfc8935Error(resp, 400, "invalid_request", "Content-Type must be application/secevent+jwt");
            return;
        }
        String jws = new String(req.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        if (jws.isEmpty()) {
            writeRfc8935Error(resp, 400, "invalid_request", "empty request body");
            return;
        }
        try {
            SsfReceiverService.Outcome outcome = receiver.receive(jws);
            resp.setStatus(202); // duplicates ack the same way — delivery is idempotent
            if (outcome == SsfReceiverService.Outcome.DUPLICATE && log.isDebugEnabled()) {
                log.debug((Object) "duplicate SET acked");
            }
        } catch (SetVerifier.SetVerificationException e) {
            log.warn((Object) ("inbound SET rejected (" + e.errorCode() + "): " + e.getMessage()));
            writeRfc8935Error(resp, 400, e.errorCode(), e.getMessage());
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        SsfReceiverService receiver = SsfSupport.receiverService();
        if (receiver == null) {
            SsfHttp.writeError(resp, 404, "not_found", "SSF receiver is not configured");
            return;
        }
        if (!endpointAuthorized(req, resp)) {
            return;
        }
        SsfHttp.writeJson(resp, 200, Map.of("received", receiver.recentEvents()));
    }

    /** Bearer check for the push endpoint when {@code receiverEndpointAuthToken} is configured. */
    private boolean endpointAuthorized(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String required = SsfSupport.configuration().receiverEndpointAuthToken();
        if (required == null || required.isBlank()) {
            return true;
        }
        String header = req.getHeader("Authorization");
        if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)
                && required.equals(header.substring(7).trim())) {
            return true;
        }
        resp.setHeader("WWW-Authenticate", "Bearer");
        writeRfc8935Error(resp, 401, "authentication_failed", "missing or invalid bearer token");
        return false;
    }

    private static void writeRfc8935Error(HttpServletResponse resp, int status, String err, String description)
            throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("err", err);
        if (description != null) {
            body.put("description", description);
        }
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(body));
        }
    }
}
