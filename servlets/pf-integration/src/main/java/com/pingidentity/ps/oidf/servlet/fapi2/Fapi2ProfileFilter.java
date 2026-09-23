/*
 * Enforces, in front of PingFederate's own endpoints, the FAPI 2.0 rules it has no setting for.
 */
package com.pingidentity.ps.oidf.servlet.fapi2;

import com.pingidentity.ps.oidf.servlet.fapi2.Fapi2RequestPolicy.Violation;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;

/**
 * A FAPI 2.0 authorization server does two things PingFederate 13.0 cannot be configured to do: accept
 * only its own issuer, as a string, as the audience of a client assertion (Security Profile §5.3.2.1),
 * and accept only PS256, ES256 and EdDSA on a JWT it processes (§5.4.1) - which a client's DPoP proof
 * is. Everything else the profile asks for is PingFederate configuration. These two are here.
 *
 * <p><b>Per client, and off unless asked for.</b> {@code OIDF_FAPI2_CLIENTS} (or the
 * {@code oidf.fapi2.clients} system property, or a {@code clients} init-param) lists the client ids
 * that are FAPI 2.0 clients; {@code *} means every client. Unset, this filter passes everything through
 * and says so once, at startup. It is a list because a real server has both kinds: OpenID Connect
 * Core §9 says the audience "SHOULD be the URL of the Authorization Server's Token Endpoint", so a
 * rule applied to everyone refuses clients that are doing exactly what they were told. (That is not
 * hypothetical. The first version of this had one switch for the whole server, and the OpenID
 * conformance suite's own Shared Signals client - not a FAPI client - failed 18 of 19 modules on it.)
 *
 * <p><b>Whose request it is</b> is read from the request, unverified: the assertion's {@code sub}; with
 * no assertion, the {@code client_id} parameter; at UserInfo, the {@code client_id} claim of a JWT
 * access token. That is sound for the same reason as everything else here. A request that names some
 * other client to get out from under the rules has then to be authenticated BY PingFederate AS that
 * client - with that client's key, or a token PingFederate issued to it - and if it can do that, it
 * is that client, and the rules were never its to break. A request whose client cannot be told at all
 * (a reference token, HTTP Basic) is examined only under {@code *}.
 *
 * <p><b>It can only refuse.</b> A request that is let through is exactly the request that arrived, and
 * PingFederate authenticates it as it would have. So the worst a defect here can do is refuse a request
 * that should have been served - see {@link Fapi2RequestPolicy} for why it refuses what it cannot read.
 *
 * <p>Mapped by {@code build/pingfederate/assemble-pf-runtime-war.sh}, ahead of the two token-endpoint
 * filters: an assertion this server is going to refuse should not first get to trigger an automatic
 * registration, and {@code ClientAttestationAuthFilter} replaces the client's assertion with one of its
 * own, which is not the one these rules are about.
 */
public final class Fapi2ProfileFilter implements Filter {

    private static final Log LOGGER = LogFactory.getLog(Fapi2ProfileFilter.class);
    static final String CLIENTS_ENV = "OIDF_FAPI2_CLIENTS";
    static final String CLIENTS_PROPERTY = "oidf.fapi2.clients";
    private static final String EVERY_CLIENT = "*";

    private final Function<HttpServletRequest, String> issuerResolver;
    private final Function<String, String> environment;
    private volatile Set<String> clients = Set.of();

    public Fapi2ProfileFilter() {
        this(Fapi2ProfileFilter::defaultIssuer, System::getenv);
    }

    /**
     * Test seam, as on the other filters over PingFederate's endpoints: {@code OAuthIssuerUtils} cannot
     * initialise outside a booted server, and a test should not depend on the machine's environment.
     */
    Fapi2ProfileFilter(Function<HttpServletRequest, String> issuerResolver, Function<String, String> environment) {
        this.issuerResolver = issuerResolver;
        this.environment = environment;
    }

    private static String defaultIssuer(HttpServletRequest request) {
        return OAuthIssuerUtils.getInstance().getIssuerValue(request);
    }

    @Override
    public void init(FilterConfig config) {
        String setting = config == null ? null : config.getInitParameter("clients");
        if (setting == null || setting.isBlank()) {
            setting = System.getProperty(CLIENTS_PROPERTY);
        }
        if (setting == null || setting.isBlank()) {
            setting = this.environment.apply(CLIENTS_ENV);
        }
        Set<String> listed = new LinkedHashSet<>();
        for (String id : (setting == null ? "" : setting).split(",")) {
            if (!id.isBlank()) {
                listed.add(id.trim());
            }
        }
        this.clients = Set.copyOf(listed);
        LOGGER.info((Object) (this.clients.isEmpty()
                ? "FAPI 2.0 enforcement off (" + CLIENTS_ENV + " names no client): requests pass through unchanged"
                : "FAPI 2.0 enforcement ON for " + (this.clients.contains(EVERY_CLIENT) ? "every client" : this.clients)
                        + ": client assertions must name the issuer as a string aud, and DPoP proofs must be"
                        + " signed with " + Fapi2RequestPolicy.ALLOWED_ALGORITHMS));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!this.clients.isEmpty() && request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest http = (HttpServletRequest) request;
            Violation violation = violationIn(http);
            if (violation != null) {
                LOGGER.info((Object) ("FAPI 2.0: refused " + http.getMethod() + " " + http.getServletPath() + " - "
                        + violation.error + ": " + violation.description));
                refuse(http, (HttpServletResponse) response, violation);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private Violation violationIn(HttpServletRequest request) {
        // A form parameter, so this reads the body the way PingFederate is about to - which the
        // container allows, and which TokenEndpointAutoRegistrationFilter already relies on.
        String[] assertions = request.getParameterValues("client_assertion");
        // One, or none - and this comes before asking whose request it is, because which of two
        // assertions answers that is the question. Nothing here verifies a signature, so an assertion
        // that merely LOOKS right costs nothing to make: sent alongside a genuine one addressed to the
        // token endpoint, it would be the one examined if this read the first value and whatever
        // authenticates the client read another. RFC 6749 §3.2 forbids repeating a parameter anyway.
        if (assertions != null && assertions.length > 1) {
            return new Violation("invalid_request", "client_assertion must not be repeated");
        }
        String assertion = assertions == null || assertions.length == 0 ? null : assertions[0];

        String client;
        if (assertion == null) {
            String named = request.getParameter("client_id");
            client = named != null && !named.isBlank() ? named
                    : Fapi2RequestPolicy.clientOfAccessToken(request.getHeader("Authorization"));
        } else {
            client = Fapi2RequestPolicy.subjectOf(assertion);
            if (client == null) {
                // Nobody to attribute it to, so no list to look it up in - and an assertion is never
                // waved past unexamined because its owner could not be worked out. PingFederate would
                // refuse it as well: it names nobody to authenticate.
                return new Violation("invalid_client", "client assertion is not a JWT this server can read, or has no sub");
            }
        }
        if (!appliesTo(client)) {
            return null;
        }

        // Every DPoP header, not the first: PingFederate refuses a request that carries two, but it has
        // to be reached to do that, and one of the two would otherwise get here unexamined.
        for (String proof : Collections.list(headers(request, "DPoP"))) {
            Violation violation = Fapi2RequestPolicy.checkDpopProof(proof);
            if (violation != null) {
                return violation;
            }
        }
        return assertion == null ? null
                : Fapi2RequestPolicy.checkClientAssertion(assertion, this.issuerResolver.apply(request));
    }

    /** Whether {@code client} - {@code null} when the request does not say - is a FAPI 2.0 client here. */
    private boolean appliesTo(String client) {
        return this.clients.contains(EVERY_CLIENT) || (client != null && this.clients.contains(client));
    }

    private static java.util.Enumeration<String> headers(HttpServletRequest request, String name) {
        java.util.Enumeration<String> values = request.getHeaders(name);
        return values == null ? Collections.emptyEnumeration() : values;
    }

    /**
     * RFC 9449 gives a refused proof two shapes: {@code 400} and a JSON error from the authorization
     * server's endpoints (§5), and at a resource a {@code 401} whose {@code WWW-Authenticate} names the
     * scheme and the algorithms that would have worked (§7.1). UserInfo is the one resource mapped.
     */
    private static void refuse(HttpServletRequest request, HttpServletResponse response, Violation violation)
            throws IOException {
        boolean proofAtResource = "invalid_dpop_proof".equals(violation.error) && isResource(request);
        if (proofAtResource) {
            response.setHeader("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\", algs=\""
                    + String.join(" ", new java.util.TreeSet<>(Fapi2RequestPolicy.ALLOWED_ALGORITHMS)) + "\"");
        }
        response.setStatus(proofAtResource || "invalid_client".equals(violation.error) ? 401 : 400);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", violation.error);
        body.put("error_description", violation.description);
        response.getWriter().write(JsonUtil.toJson(body));
    }

    /** By request URI: what {@code getServletPath()} holds depends on how PingFederate maps its servlets. */
    private static boolean isResource(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri != null && uri.contains("/idp/userinfo");
    }

    @Override
    public void destroy() {
    }
}
