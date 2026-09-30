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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Plan item S-9's per-surface rules (S9b; the Phase 3 plan's decision 2 replaced S9a's fail-closed floor with these).
 * Once {@code init} never throws, a component that failed to start still has its servlets and filters mapped; this is
 * what each of them does then. It is the first statement of every request method of a component's surfaces, one
 * method per kind of surface:
 *
 * <pre>{@code
 * protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
 *     if (ComponentGate.federationEndpoint(this.part, resp)) {
 *         return;
 *     }
 *     ...
 * }
 * }</pre>
 *
 * <p>Each reads the surface's own part: what a servlet or filter serves is what its own start function configured,
 * so a part that finished its start is not half-configured whatever a sibling part did (seen on the rig on 2026-09-30:
 * explicit registration failing while the Entity Configuration serves, F-0192). The component counts only when a part
 * of it is {@code REFUSED}: a violation of the deployment profile refuses the whole component (the programme's
 * decision 4). A part is <em>serving</em> when it is {@code READY} or {@code DEGRADED} and no part of its component is
 * refused; <em>disabled</em> when it is {@code DISABLED}; and <em>failed</em> in every other state - {@code STARTING},
 * {@code FAILED_CONFIG}, {@code FAILED_DEPENDENCY}, {@code REFUSED}, or a sibling {@code REFUSED}. No part at all
 * ({@code init} never ran - a test's constructor) is serving.
 *
 * <table>
 *   <caption>What each kind of surface does</caption>
 *   <tr><th>Surface</th><th>Disabled</th><th>Failed</th></tr>
 *   <tr><td>{@link #federationEndpoint} - OpenID Federation's endpoints, explicit registration, hosted entities,
 *       the operator API</td><td>404 {@code not_found}</td><td>503 {@code temporarily_unavailable}, OpenID Federation
 *       1.0 §8.9's body</td></tr>
 *   <tr><td>{@link #oauthEndpoint} - SSF, the attester, the challenge endpoints</td><td>404, no body</td>
 *       <td>503 {@code temporarily_unavailable}, RFC 6749's error body</td></tr>
 *   <tr><td>{@link #autoRegistration} - the two automatic registration filters</td><td>401 {@code invalid_client}
 *       for a request naming a federation client ({@link FederationClients}); everything else passes on</td>
 *       <td>503 for a request naming a federation client; everything else passes on</td></tr>
 *   <tr><td>{@link #attestation} - {@code attest_jwt_client_auth}</td><td>401 {@code invalid_client} for a request
 *       with attestation headers, and the filter's own refusal for a client that authenticates only with an
 *       attestation; everything else passes on</td><td>503 for attestation traffic, the same refusal for such a
 *       client; everything else passes on</td></tr>
 *   <tr><td>{@link #filter} with {@link #everyRequest} - FAPI's filter, which needs its client list to tell whose
 *       traffic is whose</td><td>passes every request on</td><td>503 for every request</td></tr>
 *   <tr><td>{@link #emits} - the logout filter</td><td colspan="2">passes every request on; only the emission stops</td></tr>
 * </table>
 *
 * <p>The OGNL criteria, which run on PingFederate's engine classloader and see nothing of the webapp's parts, answer
 * through {@link CriterionGate}.
 */
public final class ComponentGate {

    /** The OAuth and OpenID Federation error code for a server that cannot answer now. */
    public static final String UNAVAILABLE = "temporarily_unavailable";
    /** The OpenID Federation error code for what is not there. */
    public static final String NOT_FOUND = "not_found";
    /** RFC 6749 §5.2's code for a client whose authentication failed, or used a method this server does not support. */
    public static final String INVALID_CLIENT = "invalid_client";

    static final String ATTESTATION_HEADER = "OAuth-Client-Attestation";
    static final String ATTESTATION_POP_HEADER = "OAuth-Client-Attestation-PoP";

    private ComponentGate() {
    }

    /** What the gate does for a part in a state. */
    enum Action { SERVE, UNAVAILABLE, DISABLED }

    static Action action(ComponentParts.Part part) {
        if (part == null) {
            return Action.SERVE;
        }
        // One read of the part's published view, without the parts' monitor (F-0272).
        ComponentParts.GateView view = part.gateView();
        if (view.state() == ComponentState.DISABLED) {
            // This part is off (its own setting, or its switch), whatever its component's other parts are doing.
            return Action.DISABLED;
        }
        if (view.componentRefused()) {
            // A violation of the deployment profile refuses the whole component (the programme's decision 4).
            return Action.UNAVAILABLE;
        }
        // Otherwise the part's own start decides: what this surface serves is what its own start function configured.
        return view.state() == ComponentState.READY || view.state() == ComponentState.DEGRADED ? Action.SERVE : Action.UNAVAILABLE;
    }

    /**
     * A federation endpoint's first statement: 404 {@code not_found} when disabled - as a server without the endpoint
     * would answer, in OpenID Federation 1.0 §8.9's error format - and 503 {@code temporarily_unavailable} when failed,
     * the code §8.9 gives a server "currently unable to handle the request".
     *
     * @return {@code true} when the gate answered and the servlet must return; {@code false} to serve
     */
    public static boolean federationEndpoint(ComponentParts.Part part, HttpServletResponse response) throws IOException {
        switch (action(part)) {
            case UNAVAILABLE:
                unavailable(part, response);
                return true;
            case DISABLED:
                write(response, 404, NOT_FOUND, "no such endpoint");
                return true;
            default:
                return false;
        }
    }

    /**
     * An OAuth-style endpoint's first statement (SSF, the attester, the challenge endpoints): 404 with no body when
     * disabled - OAuth has no error code for an endpoint that is not there - and 503 {@code temporarily_unavailable},
     * RFC 6749's error body, when failed.
     *
     * @return {@code true} when the gate answered and the servlet must return; {@code false} to serve
     */
    public static boolean oauthEndpoint(ComponentParts.Part part, HttpServletResponse response) throws IOException {
        switch (action(part)) {
            case UNAVAILABLE:
                unavailable(part, response);
                return true;
            case DISABLED:
                response.setStatus(404);
                response.setHeader("Cache-Control", "no-store");
                response.setContentLength(0);
                return true;
            default:
                return false;
        }
    }

    /**
     * A filter's first statement, for a filter whose component's traffic is {@code owns}: failed, that traffic answers
     * 503 and the rest passes on; disabled, everything passes on. FAPI's filter uses it with {@link #everyRequest}.
     *
     * @return {@code true} when the gate answered the request or passed it down the chain, and the filter must
     *         return; {@code false} to run the filter
     */
    public static boolean filter(ComponentParts.Part part, ServletRequest request, ServletResponse response, FilterChain chain,
            Predicate<HttpServletRequest> owns) throws IOException, ServletException {
        Action action = action(part);
        if (action == Action.SERVE) {
            return false;
        }
        if (action == Action.UNAVAILABLE && request instanceof HttpServletRequest http && response instanceof HttpServletResponse
                && owns.test(http)) {
            unavailable(part, (HttpServletResponse) response);
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
     * Whether a stored client was registered by OpenID Federation - the answer the automatic registration filters'
     * gate asks PingFederate's client store for.
     */
    @FunctionalInterface
    public interface FederationClients {
        /**
         * @return {@code true} when {@code clientId} is a client this repository registered through the federation,
         *         {@code false} when it is a client registered any other way, and {@code null} when there is no such
         *         client
         * @throws Exception when the store cannot answer; the gate then treats the request as a federation client's
         */
        Boolean registeredByFederation(String clientId) throws Exception;
    }

    /** What a request names, as the automatic registration gate reads it. */
    enum Named { ORDINARY, FEDERATION, UNKNOWN }

    /**
     * An automatic registration filter's first statement. A request that names a federation client
     * ({@link #namesFederationClient}) answers 401 {@code invalid_client} while automatic registration is disabled -
     * nothing keeps a federation client's registration current or enforces its expiry then, so it may not
     * authenticate - and 503 while it is failed; every other request goes on to PingFederate, which authenticates its
     * own clients as it always has. A request whose client the store cannot look up answers 503 in both.
     *
     * @return {@code true} when the gate answered the request or passed it down the chain, and the filter must
     *         return; {@code false} to run the filter
     */
    public static boolean autoRegistration(ComponentParts.Part part, ServletRequest request, ServletResponse response, FilterChain chain,
            FederationClients clients) throws IOException, ServletException {
        Action action = action(part);
        if (action == Action.SERVE) {
            return false;
        }
        if (request instanceof HttpServletRequest http && response instanceof HttpServletResponse httpResponse) {
            Named named = namesFederationClient(http, clients);
            if (named == Named.UNKNOWN || named == Named.FEDERATION && action == Action.UNAVAILABLE) {
                unavailable(part, httpResponse);
                return true;
            }
            if (named == Named.FEDERATION) {
                write(httpResponse, 401, INVALID_CLIENT, "automatic registration (OpenID Federation) is not enabled on this server,"
                        + " so a federation client cannot authenticate here");
                return true;
            }
        }
        chain.doFilter(request, response);
        return true;
    }

    /**
     * Whether a request names a federation client, from three signals:
     *
     * <ul>
     *   <li>its {@code client_assertion} carries a {@code trust_chain} header - the request asks to be registered from
     *       that chain (OpenID Federation 1.0 §12.1.2) - or cannot be read (a header or claims that are not a JSON
     *       object in base64url or standard base64, or a {@code sub} that is not a string: failing closed rather than
     *       guessing, because a healthy filter reads assertions through jose4j);</li>
     *   <li>a client it names - the {@code client_assertion}'s {@code sub}, the {@code client_id} parameter, or the
     *       {@code OAuth-Client-Attestation}'s {@code sub} - is an Entity Identifier (an https URL with a host, OpenID
     *       Federation 1.0 §1.2; every client registered through the federation is known by one) and PingFederate
     *       either has no such client (only a registration could admit it) or has one this repository registered
     *       through the federation ({@link FederationClients});</li>
     *   <li>the store cannot say which ({@link Named#UNKNOWN}).</li>
     * </ul>
     *
     * <p>None of them can deny an ordinary client: each is read from the request itself, so a caller can only change
     * how its own request is treated, and the one that names a stored client asks PingFederate's store, where an
     * ordinary client carries no federation status and registration never overwrites a client it did not register.
     * An ordinary client whose id happens to be an https URL is looked up and passes on.
     */
    static Named namesFederationClient(HttpServletRequest request, FederationClients clients) {
        List<String> ids = new ArrayList<>();
        String assertion = request.getParameter("client_assertion");
        if (present(assertion)) {
            Map<String, Object> header = jwtPart(assertion, 0);
            Map<String, Object> claims = jwtPart(assertion, 1);
            if (header == null || claims == null || header.containsKey("trust_chain")) {
                return Named.FEDERATION;
            }
            Object sub = claims.get("sub");
            if (sub != null && !(sub instanceof String)) {
                return Named.FEDERATION;
            }
            ids.add((String) sub);
        }
        ids.add(request.getParameter("client_id"));
        ids.add(attestedClient(request));
        Named out = Named.ORDINARY;
        for (String id : ids) {
            if (present(id) && entityIdentifier(id)) {
                Named one = lookUp(id.trim(), clients);
                if (one == Named.UNKNOWN) {
                    return one;
                }
                if (one == Named.FEDERATION) {
                    out = one;
                }
            }
        }
        return out;
    }

    private static Named lookUp(String clientId, FederationClients clients) {
        try {
            Boolean federation = clients.registeredByFederation(clientId);
            return federation == null || federation ? Named.FEDERATION : Named.ORDINARY;
        } catch (Exception | LinkageError e) {
            // PingFederate's client manager could not answer (or is not there): nobody can say whose client it is.
            return Named.UNKNOWN;
        }
    }

    /** The {@code sub} of a request's one {@code OAuth-Client-Attestation} header; null when there is none, or more than one. */
    static String attestedClient(HttpServletRequest request) {
        Enumeration<String> headers = request.getHeaders(ATTESTATION_HEADER);
        if (headers == null || !headers.hasMoreElements()) {
            return null;
        }
        String attestation = headers.nextElement();
        if (headers.hasMoreElements() || !present(attestation)) {
            return null;
        }
        Map<String, Object> claims = jwtPart(attestation, 1);
        return claims != null && claims.get("sub") instanceof String sub ? sub : null;
    }

    /** How the attestation gate asks the filter about a request without an attestation. */
    public interface AttestationRules {
        /** Whether the filter authenticates clients at the request's endpoint (the token and PAR endpoints and their kin). */
        boolean authenticates(HttpServletRequest request);

        /**
         * The filter's own refusal of a request without an attestation that names a client which authenticates only
         * with one ({@code attestation_required}, S4c's resolver); answers whether it refused.
         */
        boolean refusedWithoutAttestation(HttpServletRequest request, HttpServletResponse response) throws IOException;
    }

    /**
     * The attestation filter's first statement. Only at an endpoint where the filter authenticates clients: a request
     * with attestation headers answers 401 {@code invalid_client} while the component is disabled (the client is told
     * that this server does not do {@code attest_jwt_client_auth} - RFC 6749 §5.2's "unsupported authentication
     * method") and 503 while it is failed; a request without them is refused by {@code rules} when it names a client
     * that authenticates only with an attestation. Every other request goes on to PingFederate.
     *
     * @return {@code true} when the gate answered the request or passed it down the chain, and the filter must
     *         return; {@code false} to run the filter
     */
    public static boolean attestation(ComponentParts.Part part, ServletRequest request, ServletResponse response, FilterChain chain,
            AttestationRules rules) throws IOException, ServletException {
        Action action = action(part);
        if (action == Action.SERVE) {
            return false;
        }
        if (request instanceof HttpServletRequest http && response instanceof HttpServletResponse httpResponse && rules.authenticates(http)) {
            if (attestationTraffic(http)) {
                if (action == Action.UNAVAILABLE) {
                    unavailable(part, httpResponse);
                } else {
                    challenge(http, httpResponse);
                    write(httpResponse, 401, INVALID_CLIENT, "this server does not accept client attestations"
                            + " (attest_jwt_client_auth is not enabled)");
                }
                return true;
            }
            if (rules.refusedWithoutAttestation(http, httpResponse)) {
                return true;
            }
        }
        chain.doFilter(request, response);
        return true;
    }

    /**
     * RFC 6749 §5.2: a 401 {@code invalid_client} to a client that authenticated with the {@code Authorization} header
     * "MUST" carry a {@code WWW-Authenticate} naming that scheme.
     */
    static void challenge(HttpServletRequest request, HttpServletResponse response) {
        String authorization = request.getHeader("Authorization");
        if (present(authorization)) {
            String scheme = authorization.trim().split("\\s+", 2)[0];
            if (scheme.matches("[A-Za-z0-9!#$%&'*+.^_`|~-]{1,32}")) {
                response.setHeader("WWW-Authenticate", scheme);
            }
        }
    }

    /**
     * A request that carries {@code OAuth-Client-Attestation} or its PoP: the only traffic
     * {@code attest_jwt_client_auth} acts on.
     */
    public static boolean attestationTraffic(HttpServletRequest request) {
        return present(request.getHeader(ATTESTATION_HEADER)) || present(request.getHeader(ATTESTATION_POP_HEADER));
    }

    /**
     * A filter that only emits - the logout filter: whether it may emit. It never answers a request and never stops
     * one; a disabled or failed component only stops the emission.
     */
    public static boolean emits(ComponentParts.Part part) {
        return action(part) == Action.SERVE;
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

    /**
     * One of a compact JWS's first two parts as a JSON object, or null when it is not one. Nothing is verified. The
     * part is decoded as jose4j decodes it: base64url or standard base64, padded or not, whitespace ignored.
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> jwtPart(String jwt, int index) {
        String[] parts = jwt.trim().split("\\.", -1);
        if (parts.length != 3) {
            return null;
        }
        String part = parts[index].replaceAll("\\s", "").replace('+', '-').replace('/', '_');
        while (part.endsWith("=")) {
            part = part.substring(0, part.length() - 1);
        }
        try {
            Object json = Json.parse(new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8));
            return json instanceof Map ? (Map<String, Object>) json : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static boolean present(String value) {
        return value != null && !value.isBlank();
    }

    private static void unavailable(ComponentParts.Part part, HttpServletResponse response) throws IOException {
        write(response, 503, UNAVAILABLE, part.component() + " is not available");
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
