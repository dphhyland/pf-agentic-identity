/*
 * The operator's side of the CIBA simulator: record allow or deny for an auth_req_id.
 */
package com.pingidentity.ps.oidf.cibasim;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.function.Function;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * {@code POST /ciba-sim/decision?auth_req_id=...&action=allow|deny}: the shape the conformance suite's
 * {@code automated_ciba_approval_url} takes. It records the decision {@link SimOobAuthenticator} will
 * answer with on its next {@code check}.
 *
 * <p>It is an approval oracle with no authentication but the {@code auth_req_id} itself, which is why it
 * answers 404 unless {@code OIDF_CIBA_SIM_ENABLED=true}: on a server where it is on, anyone who learns an
 * {@code auth_req_id} can approve that request. On a conformance rig the only party holding one is the
 * suite; anywhere else this stays off, and a deployment that turns it on has decided it is a rig.
 */
@WebServlet(urlPatterns = "/ciba-sim/decision")
public class CibaSimDecisionServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    static final String ENABLED_ENV = "OIDF_CIBA_SIM_ENABLED";
    private static final Log LOGGER = LogFactory.getLog(CibaSimDecisionServlet.class);

    private final DecisionStore store;
    private final boolean enabled;

    public CibaSimDecisionServlet() {
        this(DecisionStore.fromEnvironment(System::getenv), System::getenv);
    }

    CibaSimDecisionServlet(DecisionStore store, Function<String, String> env) {
        this.store = store;
        this.enabled = "true".equalsIgnoreCase(env.apply(ENABLED_ENV));
    }

    boolean isEnabledForTests() {
        return this.enabled;
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        handle(req, resp, this.store, this.enabled);
    }

    /** The whole endpoint, past the container: the seam tests drive. */
    static void handle(HttpServletRequest req, HttpServletResponse resp, DecisionStore store, boolean enabled)
            throws IOException {
        if (!enabled) {
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
        String txId = store.record(authReqId, decision);
        LOGGER.info((Object) ("CIBA simulator: " + decision.name().toLowerCase(java.util.Locale.ROOT)
                + " recorded for transaction " + txId.substring(0, 12) + "…"));
        write(resp, 200, "{\"action\":\"" + decision.name().toLowerCase(java.util.Locale.ROOT) + "\",\"tx\":\"" + txId + "\"}");
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
