/*
 * The operator's side of the CIBA simulator: record allow or deny for an auth_req_id.
 */
package com.pingidentity.ps.oidf.cibasim;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.Locale;
import java.util.function.Function;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * {@code POST /ciba-sim/decision?auth_req_id=...&action=allow|deny}: the shape the conformance suite's
 * {@code automated_ciba_approval_url} takes. It records the decision {@link SimOobAuthenticator} will
 * answer with on its next {@code check}.
 *
 * <p>It is an approval oracle with no authentication but the {@code auth_req_id} itself: on a server where
 * it is on, anyone who learns an {@code auth_req_id} can approve that request. So every request first asks
 * {@link SimulatorGate} - the switch, the deployment profile, the directory - and a refusal is a 404, the
 * answer the same URL gives on an image that does not carry this jar at all. Not a 503: nothing about a
 * refusal changes with time, and "try again later" would be a lie.
 */
@WebServlet(urlPatterns = "/ciba-sim/decision")
public class CibaSimDecisionServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Log LOGGER = LogFactory.getLog(CibaSimDecisionServlet.class);

    private final transient Function<String, String> env;
    private final transient Function<Path, DecisionStore> stores;

    public CibaSimDecisionServlet() {
        this(System::getenv, DecisionStore::at);
    }

    CibaSimDecisionServlet(Function<String, String> env, Function<Path, DecisionStore> stores) {
        this.env = env;
        this.stores = stores;
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        handle(req, resp);
    }

    /** The whole endpoint, past the container: the seam tests drive. */
    void handle(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String refusal = SimulatorGate.refusal(this.env);
        if (refusal != null) {
            LOGGER.warn((Object) ("CIBA simulator: decision endpoint refused - " + refusal));
            write(resp, 404, "{\"error\":\"not_found\"}");
            return;
        }
        String authReqId = req.getParameter("auth_req_id");
        DecisionStore.Decision decision = DecisionStore.Decision.parse(req.getParameter("action"));
        if (authReqId == null || authReqId.isBlank()) {
            write(resp, 400, "{\"error\":\"invalid_request\",\"error_description\":\"auth_req_id is required\"}");
            return;
        }
        if (decision == null) {
            write(resp, 400, "{\"error\":\"invalid_request\",\"error_description\":\"action must be allow or deny\"}");
            return;
        }
        String txId = this.stores.apply(SimulatorGate.directory(this.env)).record(authReqId, decision);
        LOGGER.info((Object) ("CIBA simulator: " + decision.name().toLowerCase(Locale.ROOT)
                + " recorded for transaction " + txId.substring(0, 12) + "…"));
        write(resp, 200, "{\"action\":\"" + decision.name().toLowerCase(Locale.ROOT) + "\",\"tx\":\"" + txId + "\"}");
    }

    private static void write(HttpServletResponse resp, int status, String json) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = resp.getWriter()) {
            out.write(json);
        }
    }
}
