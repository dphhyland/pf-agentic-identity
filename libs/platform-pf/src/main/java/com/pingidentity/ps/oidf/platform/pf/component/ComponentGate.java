/*
 * The first statement of every request method a component serves: what the surface does while its component is not serving.
 */
package com.pingidentity.ps.oidf.platform.pf.component;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.json.Json;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;

/**
 * S-9's fail-closed floor (Phase 3 plan, decision 2). Once {@code init} never throws, a component that failed to
 * start still has its servlets and filters mapped; this is what keeps each of them from serving half-configured.
 * It is the first statement of every request method of a component's surfaces:
 *
 * <pre>{@code
 * protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
 *     if (ComponentGate.servlet(this.part, resp)) {
 *         return;
 *     }
 *     ...
 * }
 *
 * public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
 *     if (ComponentGate.filter(this.part, req, resp, chain, ComponentGate::attestationTraffic)) {
 *         return;
 *     }
 *     ...
 * }
 * }</pre>
 *
 * <ul>
 *   <li>{@code READY} and {@code DEGRADED}: the gate does nothing; the surface serves.</li>
 *   <li>{@code STARTING}, {@code FAILED_CONFIG}, {@code FAILED_DEPENDENCY} and {@code REFUSED}: a servlet answers
 *       503 with {@code {"error":"temporarily_unavailable","error_description":...}}, the body both OpenID Federation
 *       1.0 §8.9 and RFC 6749 §5.2 give that code, and never runs. A filter over PingFederate's own endpoints answers
 *       the same 503 for the traffic its component acts on - the filter's own trigger, read from the request alone
 *       ({@link #federationClientTraffic}, {@link #attestationTraffic}, {@link #everyRequest}) - and passes the rest on
 *       unchanged, as the filter itself passes it when it is healthy, so PingFederate's own SSO and OAuth keep
 *       serving (the programme's decision 4).</li>
 *   <li>{@code DISABLED}: a filter passes every request on, as a filter that is switched off always has. A servlet
 *       answers 404 {@code not_found}, as a war without it would: its start function never ran, so it has nothing to
 *       serve, and before S-9 its answer was whatever the container gave for an {@code init} that threw.</li>
 *   <li>No part ({@code init} never ran - a test's constructor): the gate does nothing.</li>
 * </ul>
 *
 * <p>S9B (Phase 3, wave 4) replaces this floor with each surface's own rule.
 */
public final class ComponentGate {

    /** The OAuth and OpenID Federation error code for a server that cannot answer now. */
    public static final String UNAVAILABLE = "temporarily_unavailable";
    /** The OpenID Federation error code for an endpoint that is not there. */
    public static final String NOT_FOUND = "not_found";

    static final String ATTESTATION_HEADER = "OAuth-Client-Attestation";
    static final String ATTESTATION_POP_HEADER = "OAuth-Client-Attestation-PoP";

    private ComponentGate() {
    }

    /** What the gate does for a component in a state. */
    enum Action { SERVE, UNAVAILABLE, DISABLED }

    static Action action(ComponentParts.Part part) {
        if (part == null) {
            return Action.SERVE;
        }
        if (part.status().state() == ComponentState.DISABLED) {
            // This part is off (its own setting, or its switch), whatever its component's other parts are doing.
            return Action.DISABLED;
        }
        ComponentState state = part.componentState();
        switch (state) {
            case READY:
            case DEGRADED:
                return Action.SERVE;
            case DISABLED:
                return Action.DISABLED;
            default:
                return Action.UNAVAILABLE;
        }
    }

    /**
     * A servlet's first statement.
     *
     * @return {@code true} when the gate answered and the servlet must return; {@code false} to serve
     */
    public static boolean servlet(ComponentParts.Part part, HttpServletResponse response) throws IOException {
        switch (action(part)) {
            case UNAVAILABLE:
                write(response, 503, UNAVAILABLE, part.component() + " is not available");
                return true;
            case DISABLED:
                write(response, 404, NOT_FOUND, "no such endpoint");
                return true;
            default:
                return false;
        }
    }

    /**
     * A filter's first statement.
     *
     * @param owns whether the request is traffic the filter's component acts on
     * @return {@code true} when the gate answered the request or passed it down the chain, and the filter must
     *         return; {@code false} to run the filter
     */
    public static boolean filter(ComponentParts.Part part, ServletRequest request, ServletResponse response, FilterChain chain,
            Predicate<HttpServletRequest> owns) throws IOException, ServletException {
        Action action = action(part);
        if (action == Action.SERVE) {
            return false;
        }
        boolean http = request instanceof HttpServletRequest && response instanceof HttpServletResponse;
        if (action == Action.UNAVAILABLE && http && owns.test((HttpServletRequest) request)) {
            write((HttpServletResponse) response, 503, UNAVAILABLE, part.component() + " is not available");
            return true;
        }
        chain.doFilter(request, response);
        return true;
    }

    /** Every request: for a filter whose trigger needs the failed component's own configuration (FAPI's client list). */
    public static boolean everyRequest(HttpServletRequest request) {
        return true;
    }

    /**
     * A request that carries {@code OAuth-Client-Attestation} or its PoP: the only traffic
     * {@code attest_jwt_client_auth} acts on. A request without them is passed on untouched by a healthy filter too,
     * and PingFederate enforces the client's own authentication.
     */
    public static boolean attestationTraffic(HttpServletRequest request) {
        return present(request.getHeader(ATTESTATION_HEADER)) || present(request.getHeader(ATTESTATION_POP_HEADER));
    }

    /**
     * A request that may name a federation client: a {@code client_assertion} with a {@code trust_chain} header, or an
     * assertion {@code sub} or a {@code client_id} that is an https URL with a host - either, so that no filter's
     * choice between the two lets one through. Every
     * federation client this module registers is known by its Entity Identifier, which OpenID Federation 1.0 §1.2
     * defines as a URL using the https scheme with a host component (automatic registration uses it as the client id,
     * §12.1, and explicit registration here registers the statement's {@code sub}). Any other client id is
     * PingFederate's own client, which automatic registration leaves alone. An assertion that cannot be read is
     * judged by {@code client_id}, as the filters judge it.
     */
    public static boolean federationClientTraffic(HttpServletRequest request) {
        String assertion = request.getParameter("client_assertion");
        if (present(assertion)) {
            Map<String, Object> header = jwtPart(assertion, 0);
            if (header != null && header.containsKey("trust_chain")) {
                return true;
            }
            Map<String, Object> claims = jwtPart(assertion, 1);
            Object sub = claims == null ? null : claims.get("sub");
            if (sub instanceof String && entityIdentifier((String) sub)) {
                return true;
            }
        }
        String clientId = request.getParameter("client_id");
        return present(clientId) && entityIdentifier(clientId);
    }

    /** Whether {@code id} could be an Entity Identifier: an absolute https URL with a host. */
    static boolean entityIdentifier(String id) {
        try {
            URI uri = new URI(id.trim());
            return uri.getScheme() != null && "https".equals(uri.getScheme().toLowerCase(Locale.ROOT)) && uri.getHost() != null;
        } catch (Exception e) {
            return false;
        }
    }

    /** One of a compact JWS's first two parts as a JSON object, or null when it is not one. Nothing is verified. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> jwtPart(String jwt, int index) {
        String[] parts = jwt.trim().split("\\.", -1);
        if (parts.length != 3) {
            return null;
        }
        try {
            Object json = Json.parse(new String(Base64.getUrlDecoder().decode(parts[index]), StandardCharsets.UTF_8));
            return json instanceof Map ? (Map<String, Object>) json : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static boolean present(String value) {
        return value != null && !value.isBlank();
    }

    /** The error body, as JSON, never cached. */
    static void write(HttpServletResponse response, int status, String error, String description) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        byte[] bytes = Json.write(body).getBytes(StandardCharsets.UTF_8);
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
    }
}
