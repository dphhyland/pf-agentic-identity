/*
 * A challenge endpoint: one HTTP method, one store namespace, a per-caller cap.
 */
package com.pingidentity.ps.oidf.clientattestation.servlet;

import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.clientattestation.ChallengeRateLimiter;
import com.pingidentity.ps.oidf.clientattestation.StoreNamespace;
import com.pingidentity.ps.oidf.clientattestation.StoreUnavailableException;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.net.TrustedProxies;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.platform.pf.settings.InitParams;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
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
 * method most likely has the wrong endpoint. (PingFederate 13.1.3 answers every OPTIONS 403 itself, so there an
 * OPTIONS never reaches this servlet; seen on the rig, 2026-09-27.)
 *
 * <p>Init-params, each read by the endpoint for its own namespace through the {@value #SETTINGS} settings catalogue:
 * {@code challengeCacheMaxEntries} and {@code challengeTtlSeconds} (the size and lifetime of its challenges; with Redis
 * only the lifetime applies), and {@code challengeRateLimitPerWindow}, {@code challengeRateLimitWindowSeconds} and
 * {@code challengeRateLimitMaxCallers} (its per-caller cap, counted by client address: the remote address, or behind a
 * proxy {@code OIDF_TRUSTED_PROXIES} lists, the right-most forwarding hop it does not list - platform's
 * {@link TrustedProxies}). They are read strictly (plan item ST-5): a value that is
 * not a whole number in the entry's range leaves the endpoint's part {@code FAILED_CONFIG}, naming the setting, and
 * the endpoint answers 503.
 *
 * <p>Each endpoint is a part of the component that consumes its challenges (plan item S-9): the authorization server's
 * of {@code ATTESTATION_AUTH}, the attester's of {@code ATTESTATION_ISSUER}, registered at deploy. Its start asks
 * {@link AttestationSupport#requireSharedState} first, so under the production profile, with no Redis URL and the
 * {@code in-memory-state} risk not accepted, the part is {@code REFUSED} and so is its component. Every challenge
 * issued or refused is an event of the {@value #EVENTS} catalogue - {@value #ISSUED} or {@value #REFUSED}, with the
 * surface and the reason, never the challenge - and so counted in {@code oidf_events_total}.
 */
public abstract class ChallengeEndpointServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(ChallengeEndpointServlet.class);

    /** The settings catalogue the endpoints' init-params are read through. */
    public static final String SETTINGS = "attestation-challenge";
    /** The event catalogue the endpoints' events are in. */
    public static final String EVENTS = "challenge";
    /** A challenge issued and recorded. */
    public static final String ISSUED = "attestation.challenge.issued";
    /** No challenge issued: {@code rate_limited}, {@code store_unavailable} or {@code method_not_allowed}. */
    public static final String REFUSED = "attestation.challenge.refused";

    private final StoreNamespace namespace;
    private final String method;
    /** This endpoint's part, from init; null when a test's constructor made it and init never ran. */
    private transient volatile ComponentParts.Part part;

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
        ComponentParts.Part begun = Startup.begin(AttestationSupport.componentOf(this.namespace), this.partName());
        this.part = begun;
        begun.start(() -> this.start(Settings.of(SETTINGS).with(InitParams.sources(config))));
    }

    /**
     * The start function: the in-memory rule, then the settings, strictly, then the store and the cap. What it throws is
     * the part's state ({@code REFUSED} for the profile, {@code FAILED_CONFIG} for a setting, naming it), and nothing is
     * configured until every setting has been read.
     */
    void start(Settings settings) {
        AttestationSupport.requireSharedState(this.namespace);
        int challengeMax = settings.integer("challengeCacheMaxEntries");
        long challengeTtl = settings.duration("challengeTtlSeconds").getSeconds();
        int rateMax = settings.integer("challengeRateLimitPerWindow");
        long rateWindow = settings.duration("challengeRateLimitWindowSeconds").getSeconds();
        int rateCallers = settings.integer("challengeRateLimitMaxCallers");
        // The per-caller cap counts client addresses, which OIDF_TRUSTED_PROXIES decides (H-ATT-3, F-0116): a value it
        // cannot read leaves the part FAILED_CONFIG, naming it, rather than counting every caller as its proxy.
        TrustedProxies.check();
        this.configure(settings);
        AttestationSupport.configureChallengeService(this.namespace, challengeMax, challengeTtl);
        this.rateLimiter = new ChallengeRateLimiter(rateMax, rateWindow, rateCallers);
    }

    /** The part's name: the servlet's class's simple name, or this class's for a class that has none. */
    String partName() {
        String name = this.getClass().getSimpleName();
        return name.isEmpty() ? ChallengeEndpointServlet.class.getSimpleName() : name;
    }

    /** A subclass's own settings, read in the start function after the endpoint's; nothing by default. */
    protected void configure(Settings settings) {
    }

    /** Test seam: drive the limiter directly rather than through servlet init parameters. */
    void setRateLimiterForTest(ChallengeRateLimiter limiter) {
        this.rateLimiter = limiter != null ? limiter : new ChallengeRateLimiter();
    }

    /** The endpoint's one method issues a challenge; any other is refused before the cap or the store is touched. */
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (ComponentGate.oauthEndpoint(this.part, resp)) {
            return;
        }
        if (this.method.equals(req.getMethod())) {
            this.issue(req, resp);
        } else {
            this.refuseMethod(req, resp);
        }
    }

    private void issue(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        long now = System.currentTimeMillis();
        String caller = TrustedProxies.current().clientAddress(req.getRemoteAddr(), name -> headerValues(req, name));
        if (!this.rateLimiter.allow(caller, now)) {
            long retryAfter = this.rateLimiter.retryAfterSeconds(caller, now);
            resp.setHeader("Retry-After", String.valueOf(retryAfter));
            write(resp, 429, Map.of(
                    "error", "slow_down",
                    "error_description", "too many challenge requests; retry in " + retryAfter + "s"));
            log.warn((Object) ("challenge endpoint " + this.namespace.prefix() + " rate cap hit by " + caller));
            this.refused("rate_limited");
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
            this.refused("store_unavailable");
            return;
        }
        resp.setHeader("Pragma", "no-cache");
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("attestation_challenge", challenge);
        body.put("expires_in", service.ttlSeconds());
        write(resp, 200, body);
        Events.event(EVENTS, ISSUED).success().field("surface", this.surface()).emit();
    }

    /** The surface an event names: {@code AS} or {@code CAS}, the namespace's own name. */
    String surface() {
        return this.namespace.name();
    }

    private void refused(String reason) {
        Events.event(EVENTS, REFUSED).failure(reason).field("surface", this.surface()).emit();
    }

    private void refuseMethod(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setHeader("Allow", this.method);
        write(resp, 405, Map.of(
                "error", "invalid_request",
                "error_description", "this challenge endpoint takes " + this.method + ", not " + req.getMethod()));
        this.refused("method_not_allowed");
    }

    /** Every value of a request header, for {@link TrustedProxies}; {@code null} when the container gives none. */
    static List<String> headerValues(HttpServletRequest req, String name) {
        Enumeration<String> values = req.getHeaders(name);
        return values == null ? null : Collections.list(values);
    }

    private static void write(HttpServletResponse resp, int status, Map<String, Object> body) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(body));
        }
    }
}
