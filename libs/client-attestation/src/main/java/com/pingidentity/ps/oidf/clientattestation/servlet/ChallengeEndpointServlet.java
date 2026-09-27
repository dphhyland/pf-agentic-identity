/*
 * A challenge endpoint: one HTTP method, one store namespace, a per-caller cap.
 */
package com.pingidentity.ps.oidf.clientattestation.servlet;

import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.clientattestation.ChallengeRateLimiter;
import com.pingidentity.ps.oidf.clientattestation.StoreNamespace;
import com.pingidentity.ps.oidf.clientattestation.StoreUnavailableException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;

/**
 * Issues attestation challenges for one surface. Two surfaces issue them, and each keeps its own, because a
 * challenge issued by one party must not be accepted by the other (CAS §4.1):
 *
 * <ul>
 *   <li>the authorization server: {@link ClientAttestationChallengeServlet}, {@code POST
 *       /federation/attestation-challenge} (ABCA-10 §6.1), issuing into {@code oidf:as:challenge:*}, which the
 *       token endpoint's verifier consumes;</li>
 *   <li>the client attestation service: {@code AttestationIssuanceChallengeServlet} in {@code attestation-issuer},
 *       {@code GET /federation/attestation/challenge} (CAS §4.1), issuing into {@code oidf:cas:challenge:*}, which
 *       the issuance endpoint's instance-key proof check consumes.</li>
 * </ul>
 *
 * <p>The endpoint's one method answers 200 {@code {"attestation_challenge": "...", "expires_in": N}} with
 * {@code Cache-Control: no-store}, 429 {@code slow_down} over the per-caller cap, and 503
 * {@code temporarily_unavailable} when the store could not record the challenge. Every other method, HEAD and
 * OPTIONS included, answers 405 with an {@code Allow} header naming the one method, and issues nothing: a HEAD
 * would write a challenge its response cannot carry, and a client calling one surface's endpoint with the other's
 * method most likely has the wrong endpoint.
 *
 * <p>Init-params, each read by the endpoint for its own namespace: {@code challengeCacheMaxEntries} and
 * {@code challengeTtlSeconds} (the size and lifetime of its challenges; with Redis only the lifetime applies), and
 * {@code challengeRateLimitPerWindow}, {@code challengeRateLimitWindowSeconds} and
 * {@code challengeRateLimitMaxCallers} (its per-caller cap). A value that is not an integer is ignored with a
 * warning and the default used.
 */
public abstract class ChallengeEndpointServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(ChallengeEndpointServlet.class);

    private final StoreNamespace namespace;
    private final String method;

    /**
     * Per-caller cap. The endpoint is unauthenticated by necessity - a client needs a challenge before it can
     * authenticate - and every call writes into a BOUNDED challenge cache, so an unmetered flood evicts legitimate
     * clients' challenges before they are redeemed. Those clients then fail against a challenge the server has
     * forgotten, which presents as intermittent attestation errors rather than as an attack. Each endpoint has its
     * own cap, over its own store.
     */
    private ChallengeRateLimiter rateLimiter = new ChallengeRateLimiter();

    /**
     * @param namespace the store the endpoint issues into
     * @param method    the one HTTP method it issues a challenge for, in upper case
     */
    protected ChallengeEndpointServlet(StoreNamespace namespace, String method) {
        this.namespace = Objects.requireNonNull(namespace, "namespace");
        this.method = Objects.requireNonNull(method, "method");
    }

    /** The store namespace this endpoint issues into. */
    public final StoreNamespace namespace() {
        return this.namespace;
    }

    /** The one HTTP method this endpoint issues a challenge for. */
    public final String method() {
        return this.method;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        Integer challengeMax = parseInt(config.getInitParameter("challengeCacheMaxEntries"));
        Long challengeTtl = parseLong(config.getInitParameter("challengeTtlSeconds"));
        if (challengeMax != null || challengeTtl != null) {
            AttestationSupport.configureChallengeService(this.namespace,
                    challengeMax != null ? challengeMax : AttestationChallengeService.DEFAULT_MAX_ENTRIES,
                    challengeTtl != null ? challengeTtl : AttestationChallengeService.DEFAULT_TTL_SECONDS);
        }
        Integer rateMax = parseInt(config.getInitParameter("challengeRateLimitPerWindow"));
        Long rateWindow = parseLong(config.getInitParameter("challengeRateLimitWindowSeconds"));
        Integer rateCallers = parseInt(config.getInitParameter("challengeRateLimitMaxCallers"));
        if (rateMax != null || rateWindow != null || rateCallers != null) {
            this.rateLimiter = new ChallengeRateLimiter(
                    rateMax != null ? rateMax : ChallengeRateLimiter.DEFAULT_MAX_PER_WINDOW,
                    rateWindow != null ? rateWindow : ChallengeRateLimiter.DEFAULT_WINDOW_SECONDS,
                    rateCallers != null ? rateCallers : ChallengeRateLimiter.DEFAULT_MAX_CALLERS);
        }
    }

    /** Test seam: drive the limiter directly rather than through servlet init parameters. */
    void setRateLimiterForTest(ChallengeRateLimiter limiter) {
        this.rateLimiter = limiter != null ? limiter : new ChallengeRateLimiter();
    }

    /** The endpoint's one method issues a challenge; any other is refused before the cap or the store is touched. */
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (this.method.equals(req.getMethod())) {
            this.issue(req, resp);
        } else {
            this.refuseMethod(req, resp);
        }
    }

    private void issue(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        long now = System.currentTimeMillis();
        String caller = req.getRemoteAddr();
        if (!this.rateLimiter.allow(caller, now)) {
            long retryAfter = this.rateLimiter.retryAfterSeconds(caller, now);
            resp.setHeader("Retry-After", String.valueOf(retryAfter));
            write(resp, 429, Map.of(
                    "error", "slow_down",
                    "error_description", "too many challenge requests; retry in " + retryAfter + "s"));
            log.warn((Object) ("challenge endpoint " + this.namespace.prefix() + " rate cap hit by " + caller));
            return;
        }
        AttestationChallengeService service = AttestationSupport.challengeService(this.namespace);
        String challenge;
        try {
            challenge = service.issue();
        } catch (StoreUnavailableException e) {
            // A challenge that was not recorded must not be handed out: it could never be consumed.
            log.error((Object) ("challenge endpoint " + this.namespace.prefix() + ": the challenge store is unavailable"), e);
            write(resp, 503, Map.of(
                    "error", "temporarily_unavailable",
                    "error_description", "the attestation challenge store is unavailable"));
            return;
        }
        resp.setHeader("Pragma", "no-cache");
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("attestation_challenge", challenge);
        body.put("expires_in", service.ttlSeconds());
        write(resp, 200, body);
    }

    private void refuseMethod(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setHeader("Allow", this.method);
        write(resp, 405, Map.of(
                "error", "invalid_request",
                "error_description", "this challenge endpoint takes " + this.method + ", not " + req.getMethod()));
    }

    private static void write(HttpServletResponse resp, int status, Map<String, Object> body) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
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
