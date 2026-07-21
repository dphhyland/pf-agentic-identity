/*
 * Attestation challenge endpoint (draft-ietf-oauth-attestation-based-client-auth Section 6.1).
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.common.AttestationChallengeService;
import com.pingidentity.ps.oidf.common.AttestationSupport;
import java.io.IOException;
import java.io.PrintWriter;
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
 * Issues server-provided attestation challenges. A client {@code POST}s here (no body required) and
 * receives {@code {"attestation_challenge": "...", "expires_in": N}} with {@code Cache-Control: no-store}.
 * The client echoes the value in the {@code challenge} claim of a Client Attestation PoP JWT (or the
 * {@code nonce} of a combined-mode DPoP proof); {@link com.pingidentity.ps.oidf.common.AttestationSupport}
 * shares the challenge store with the issuance-criteria hook that consumes it.
 *
 * <p>Advertised in OP metadata as {@code challenge_endpoint}.
 */
@WebServlet(urlPatterns = {"/federation/attestation-challenge"})
public class ClientAttestationChallengeServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(ClientAttestationChallengeServlet.class);

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        Integer challengeMax = ClientAttestationChallengeServlet.parseInt(config.getInitParameter("challengeCacheMaxEntries"));
        Long challengeTtl = ClientAttestationChallengeServlet.parseLong(config.getInitParameter("challengeTtlSeconds"));
        if (challengeMax != null || challengeTtl != null) {
            AttestationSupport.configureChallengeService(
                    challengeMax != null ? challengeMax : AttestationChallengeService.DEFAULT_MAX_ENTRIES,
                    challengeTtl != null ? challengeTtl : AttestationChallengeService.DEFAULT_TTL_SECONDS);
        }
        Integer replayMax = ClientAttestationChallengeServlet.parseInt(config.getInitParameter("replayCacheMaxEntries"));
        if (replayMax != null) {
            AttestationSupport.configureReplayCache(replayMax);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        AttestationChallengeService service = AttestationSupport.challengeService();
        String challenge = service.issue();
        resp.setStatus(200);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        resp.setHeader("Pragma", "no-cache");
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("attestation_challenge", challenge);
        body.put("expires_in", service.ttlSeconds());
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(body));
        }
    }

    private static Integer parseInt(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Integer.valueOf(raw.trim());
        } catch (NumberFormatException e) {
            log.warn((Object) ("Ignoring non-integer servlet parameter value: " + raw));
            return null;
        }
    }

    private static Long parseLong(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Long.valueOf(raw.trim());
        } catch (NumberFormatException e) {
            log.warn((Object) ("Ignoring non-integer servlet parameter value: " + raw));
            return null;
        }
    }
}
