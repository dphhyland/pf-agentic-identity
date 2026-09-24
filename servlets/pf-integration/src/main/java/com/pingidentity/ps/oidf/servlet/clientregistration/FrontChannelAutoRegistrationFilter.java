package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import com.pingidentity.ps.oidf.pf.PfTracking;
import com.pingidentity.ps.oidf.servlet.oauth.FederationErrorPage;
import com.pingidentity.ps.oidf.servlet.oauth.OAuthErrorWriter;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
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
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;

/**
 * OpenID Federation 1.0 §12.1.1 automatic registration at the authorization and PAR endpoints: an RP that has never
 * registered here sends its authentication request with its Entity Identifier as {@code client_id}, and the request
 * itself - a signed request object (§12.1.1.1), or at PAR a {@code private_key_jwt} client assertion (§12.1.1.2) -
 * shows it holds the RP's keys. This filter, in front of PingFederate, resolves the RP's chain, registers it from its
 * {@code openid_relying_party} metadata once that proof verifies, and lets the very same request go on.
 *
 * <p>Cheapest checks first, so what cannot become a registration costs nothing: a {@code client_id} that is not an
 * Entity Identifier, a PAR {@code request_uri}, a client PingFederate already holds with a current registration - all
 * pass through untouched. A {@code request_uri} is never dereferenced (§12.1.1: it "would make it easier for
 * attackers to mount denial of service attacks"); a client not registered here sends its request object by value
 * or pushes it. The request object's claims are held to §12.1.1.1 before anything is fetched, and its signature is
 * verified against the RP's keys before anything is written.
 *
 * <p>A refusal at PAR is §8.9 JSON. At the authorization endpoint it is a page and never a redirect: §12.1.3 says an
 * OP that fails to establish trust "MUST treat the redirection URI as invalid". Refusal is the default;
 * {@code OIDF_AUTO_REGISTRATION_FAIL_CLOSED=false} passes the request on to PingFederate instead, which will not
 * know the client.
 *
 * <p>Deployment: mapped over {@code /as/authorization.oauth2} and {@code /as/par.oauth2} by
 * {@code build/pingfederate/assemble-pf-runtime-war.sh}, after the FAPI 2.0 and error-description filters.
 */
public final class FrontChannelAutoRegistrationFilter implements Filter {
    private static final Log LOGGER = LogFactory.getLog(FrontChannelAutoRegistrationFilter.class);
    static final String PAR_PATH = "/as/par.oauth2";
    /** RFC 9126 §2.2: the {@code request_uri} a PAR endpoint issues. */
    static final String PAR_REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";
    /** Longer than any Entity Identifier worth resolving, short enough that nothing is spent on one that is not. */
    static final int MAX_CLIENT_ID_LENGTH = 2048;
    private static final String REPLAY_NAMESPACE = "oidf-registration:";

    private final Function<HttpServletRequest, String> issuerResolver;
    private volatile RegistrationService service;
    private volatile AutoRegistrationSettings settings;
    private volatile boolean failClosed = true;
    private volatile FederationErrorPage errorPage = FederationErrorPage.builtIn();
    private volatile RequestObject.ReplayGuard replay;

    public FrontChannelAutoRegistrationFilter() {
        this.issuerResolver = request -> OAuthIssuerUtils.getInstance().getIssuerValue(request);
    }

    /** Test seam: everything injected, nothing read from PingFederate. */
    FrontChannelAutoRegistrationFilter(RegistrationService service, Function<HttpServletRequest, String> issuerResolver,
                                       AutoRegistrationSettings settings, boolean failClosed, RequestObject.ReplayGuard replay,
                                       FederationErrorPage errorPage) {
        this.service = service;
        this.issuerResolver = Objects.requireNonNull(issuerResolver, "issuerResolver");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.failClosed = failClosed;
        this.replay = Objects.requireNonNull(replay, "replay");
        this.errorPage = Objects.requireNonNull(errorPage, "errorPage");
    }

    @Override
    public void init(FilterConfig config) throws ServletException {
        if (this.service != null) {
            return;
        }
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        AutoRegistrationSettings configured = runtime.autoRegistration();
        if (!configured.frontChannel()) {
            LOGGER.info((Object)(FederationRuntimeConfig.AUTO_REGISTRATION_FRONT_CHANNEL_ENV + "=false: no automatic registration at the"
                    + " authorization or PAR endpoints"));
            return;
        }
        if (runtime.isTrustControllerConfigured() && runtime.trustAnchorJwks() == null) {
            // As at the token endpoint: refuse, but keep the web app - and this entity's own /.well-known - serving.
            LOGGER.error((Object)("FrontChannelAutoRegistrationFilter: " + FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV
                    + " is unset - automatic registration at the authorization and PAR endpoints (OpenID Federation 1.0 §12.1.1)"
                    + " is off until the trust anchor's keys are pinned"));
            return;
        }
        try {
            this.errorPage = FederationErrorPage.from(configured.errorPage());
        } catch (IOException e) {
            throw new ServletException(FederationRuntimeConfig.FEDERATION_ERROR_PAGE_ENV + " names " + configured.errorPage()
                    + ", which cannot be read", e);
        }
        try {
            this.service = new RegistrationService(RegistrationConfiguration.forFilter(runtime, config));
        } catch (RuntimeException e) {
            throw new ServletException("OpenID Federation automatic registration: " + e.getMessage(), e);
        }
        this.settings = configured;
        this.failClosed = runtime.registration().failClosed();
        this.replay = (clientId, jti, ttl) -> AttestationSupport.replayCache().firstSeen(REPLAY_NAMESPACE + clientId, jti, ttl);
        LOGGER.info((Object)("FrontChannelAutoRegistrationFilter initialised (trust controller " + runtime.trustControllerHost() + ")"));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest http) || !(response instanceof HttpServletResponse httpResponse) || this.service == null) {
            chain.doFilter(request, response);
            return;
        }
        String uri = http.getRequestURI();
        boolean par = uri != null && uri.endsWith(PAR_PATH);
        String requestUri = http.getParameter("request_uri");
        if (par && !"POST".equalsIgnoreCase(http.getMethod()) || !par && requestUri != null && requestUri.startsWith(PAR_REQUEST_URI_PREFIX)) {
            // PAR takes POST only - PingFederate says so. A pushed request_uri was registered for when it was pushed.
            chain.doFilter(request, response);
            return;
        }
        String assertion = par ? http.getParameter("client_assertion") : null;
        String clientId = clientIdOf(http, assertion);
        if (clientId == null) {
            chain.doFilter(request, response);
            return;
        }
        String requestObject = http.getParameter("request");
        RequestObject proof = null;
        RegistrationRejectedException unreadable = null;
        try {
            proof = requestObject != null && !requestObject.isBlank() ? RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, requestObject)
                    : assertion != null && !assertion.isBlank() ? RequestObject.read(RequestObject.Kind.CLIENT_ASSERTION, assertion) : null;
        } catch (RegistrationRejectedException e) {
            unreadable = e;
        }
        String issuer = this.issuerResolver.apply(http);
        RegistrationService.Channel channel = this.service.frontChannel(par ? "par" : "authorization", clientId, issuer, proof, unreadable,
                this.replay, this.settings);
        try {
            this.service.admit(clientId, proof == null ? List.of() : proof.trustChain(), issuer, channel);
        } catch (RegistrationRejectedException e) {
            this.refuse(http, httpResponse, chain, par, e.status(), e.error(), e.getMessage(), e.isRetryable() ? retryAfter(e) : null);
            return;
        } catch (Exception e) {
            LOGGER.error((Object)("Federation registration at the " + (par ? "PAR" : "authorization") + " endpoint failed"), e);
            this.refuse(http, httpResponse, chain, par, 500, "server_error", "the federation registration could not be completed", null);
            return;
        }
        chain.doFilter(request, response);
    }

    /**
     * The client a request names, when it could be a federation RP: its {@code client_id}, or at PAR its client
     * assertion's {@code sub} - an https Entity Identifier of sane length. Null for anything else, which this filter
     * leaves to PingFederate.
     */
    static String clientIdOf(HttpServletRequest request, String assertion) {
        String clientId = request.getParameter("client_id");
        if ((clientId == null || clientId.isBlank()) && assertion != null && !assertion.isBlank()) {
            try {
                clientId = JwtCodec.parseUnverifiedClaims(assertion).getSubject();
            } catch (Exception e) {
                clientId = null;
            }
        }
        return clientId != null && clientId.length() <= MAX_CLIENT_ID_LENGTH && EntityId.isValid(clientId) ? clientId : null;
    }

    private static String retryAfter(RegistrationRejectedException e) {
        return e.kind() == RegistrationRejectedException.Kind.BUSY ? "2" : Long.toString(RegistrationService.TRANSPORT_FAILURE_BACKOFF_SECONDS);
    }

    private void refuse(HttpServletRequest request, HttpServletResponse response, FilterChain chain, boolean par, int status, String error,
                        String description, String retryAfter) throws IOException, ServletException {
        LOGGER.info((Object)("Automatic registration refused at the " + (par ? "PAR" : "authorization") + " endpoint (" + error + ")"));
        if (!this.failClosed) {
            chain.doFilter(request, response);
            return;
        }
        if (retryAfter != null) {
            response.setHeader("Retry-After", retryAfter);
        }
        if (par) {
            OAuthErrorWriter.write(response, status, error, description);
        } else if (this.settings.pageOnAuthorizationError()) {
            this.errorPage.write(response, status, error, description, PfTracking.trackingIdOr("oidf"));
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {
    }
}
