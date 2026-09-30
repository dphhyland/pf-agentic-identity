package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.pf.PfRequestScope;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.platform.pf.internals.PfInternals;
import com.pingidentity.ps.oidf.servlet.oauth.OAuthErrorWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
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

/**
 * OpenID Federation §12.1 Automatic Registration, and §12.3 registration lifetime, at the OAuth token endpoint.
 *
 * <p>A federation client that has never called {@code /federation/register} can still obtain a token: it
 * presents its Trust Chain inline in the {@code trust_chain} header of its {@code client_assertion}, and the
 * Authorization Server validates the chain and derives the client's metadata on the fly. Because PingFederate
 * must have a persisted client record to authenticate a token request, this filter runs <b>before</b> PF's
 * token-endpoint client authentication: it just-in-time materialises the client from its resolved federation
 * metadata (marking it {@code auto_registered}) so the very same request then authenticates normally.
 *
 * <p>Every federation registration also has an end (§12.3). A request naming a federation client whose
 * registration is due is where it is renewed or, past its expiry, refused - see
 * {@link RegistrationService#admit}. Refusal is the default: a registration that fails, or an expired one that
 * cannot be renewed, is answered here with an RFC 6749 error and the reason, instead of being passed on for
 * PingFederate to refuse without one - or to accept, for a client registered before.
 * {@code OIDF_AUTO_REGISTRATION_FAIL_CLOSED=false} restores the old pass-through.
 *
 * <p>Deployment: map this filter over the PF token endpoint in the runtime web application, e.g.
 * <pre>{@code
 *   <filter>
 *     <filter-name>OidfAutoRegistration</filter-name>
 *     <filter-class>com.pingidentity.ps.oidf.servlet.clientregistration.TokenEndpointAutoRegistrationFilter</filter-class>
 *     <init-param><param-name>trustControllerHost</param-name><param-value>https://trust-controller.example</param-value></init-param>
 *     <init-param><param-name>acceptedSigningAlgorithms</param-name><param-value>ES256,RS256</param-value></init-param>
 *   </filter>
 *   <filter-mapping>
 *     <filter-name>OidfAutoRegistration</filter-name>
 *     <url-pattern>/as/token.oauth2</url-pattern>
 *   </filter-mapping>
 * }</pre>
 */
public final class TokenEndpointAutoRegistrationFilter implements Filter {
    /** The header an attested request names its client in (OAuth 2.0 Attestation-Based Client Authentication). */
    static final String ATTESTATION_HEADER = "OAuth-Client-Attestation";

    private static final Log LOGGER = LogFactory.getLog(TokenEndpointAutoRegistrationFilter.class);
    private volatile RegistrationService service;
    private final Function<HttpServletRequest, String> issuerResolver;
    private volatile boolean failClosed = true;
    /** This filter's part of AUTO_REGISTRATION, from init; null when a test's constructor made it and init never ran. */
    private volatile ComponentParts.Part part;

    public TokenEndpointAutoRegistrationFilter() {
        this.issuerResolver = TokenEndpointAutoRegistrationFilter::defaultIssuer;
    }

    /** Test seam: inject a pre-built (typically mocked) registration service. */
    TokenEndpointAutoRegistrationFilter(RegistrationService service) {
        this(service, TokenEndpointAutoRegistrationFilter::defaultIssuer);
    }

    /** Test seam: inject the registration service and the OP-issuer resolver (avoids the PF runtime singleton). */
    TokenEndpointAutoRegistrationFilter(RegistrationService service, Function<HttpServletRequest, String> issuerResolver) {
        this(service, issuerResolver, true);
    }

    /** Test seam: as above, choosing whether a failed registration refuses the request. */
    TokenEndpointAutoRegistrationFilter(RegistrationService service, Function<HttpServletRequest, String> issuerResolver, boolean failClosed) {
        this.service = service;
        this.issuerResolver = issuerResolver;
        this.failClosed = failClosed;
    }

    /** Whether a registration that fails refuses the request ({@code OIDF_AUTO_REGISTRATION_FAIL_CLOSED}). */
    boolean isFailClosed() {
        return this.failClosed;
    }

    private static String defaultIssuer(HttpServletRequest request) {
        return PfInternals.issuer(request);
    }

    @Override
    public void init(FilterConfig config) throws ServletException {
        boolean injected = this.service != null;
        ComponentParts.Part part = Startup.begin(Startup.AUTO_REGISTRATION, "TokenEndpointAutoRegistrationFilter");
        this.part = part;
        part.start(() -> this.init(config, part, injected));
    }

    /**
     * The start function: what {@code init} did before S-9, run by {@link ComponentParts.Part#start} at deploy and again
     * by each supervisor retry after a dependency failure. What it throws is the part's state, never the container's.
     */
    private void init(FilterConfig config, ComponentParts.Part part, boolean injected) throws ServletException {
        PfAuditEventSink.install();
        if (injected) {
            return;
        }
        // The trust controller is deployment-wide (FederationRuntimeConfig), not per-filter. This used
        // to read the env itself and then pass the bare host as BOTH host and base URL, which - via
        // the statics the constructor wrote - silently replaced any context-path base URL the
        // registration servlet had established. Only the per-component sizing knobs come from
        // init-params now.
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        if (runtime.isTrustControllerConfigured() && !runtime.hasTrustAnchors()) {
            // Refuse, but do not take the web app down. The modules are merged into pf-runtime.war, so a
            // failed init here would also stop this entity's own /.well-known/openid-federation - and a
            // PF that is its own trust anchor has to serve that before anyone can capture the keys to
            // pin. The component is FAILED_CONFIG until the keys are set: the gate answers a request that
            // names a federation client 503, and passes every other token request to PingFederate.
            LOGGER.error((Object)("TokenEndpointAutoRegistrationFilter: " + FederationRuntimeConfig.HOST_ENV + " names "
                    + runtime.trustControllerHost() + " but " + FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV
                    + " is unset - automatic registration (OpenID Federation 1.0 §12.1) is refused for every request until the"
                    + " trust anchor's keys are pinned (§4: they are distributed out of band, not fetched)"));
            part.failedConfig(FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV + " is unset: automatic registration at the token"
                    + " endpoint is refused for every request until the trust anchor's keys are pinned");
            return;
        }
        // Building the service builds the validator, and the validator needs the anchor's out-of-band
        // keys (FederationRuntimeConfig.trustAnchor). No trust controller at all, or a JWKS that is set
        // but is not a usable public key set, is a deployment error that no request can fix: refuse to
        // start, naming what to set - FAILED_CONFIG, with the war still serving. (The "no trust controller" case already failed init before the
        // anchor keys existed - the old validator constructor threw on a blank anchor - but as an
        // unchecked exception, which a container does not reliably surface from init.) So is an init-param
        // that does not parse: it used to mean the default, quietly.
        try {
            this.service = new RegistrationService(RegistrationConfiguration.forFilter(runtime, config));
        }
        catch (RuntimeException e) {
            throw new ServletException("OpenID Federation automatic registration: " + e.getMessage(), e);
        }
        this.failClosed = runtime.registration().failClosed();
        if (!this.failClosed) {
            LOGGER.warn((Object)(FederationRuntimeConfig.AUTO_REGISTRATION_FAIL_CLOSED_ENV + "=false: a token request whose federation"
                    + " registration fails, or whose registration has expired, is passed on to PingFederate rather than refused"));
        }
        new RegistrationExpirySweeper(new com.pingidentity.ps.oidf.pf.PfMgmtClientStore(), this.service.lifetime())
                .startOnce(runtime.registration().sweepIntervalSeconds());
        LOGGER.info((Object)("TokenEndpointAutoRegistrationFilter initialised (trust controller "
                + runtime.trustControllerHost() + ")"));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (ComponentGate.filter(this.part, request, response, chain, ComponentGate::federationClientTraffic)) {
            return;
        }
        // No service means init refused automatic registration (no pinned anchor keys); pass through.
        if (!(request instanceof HttpServletRequest http) || !(response instanceof HttpServletResponse httpResponse) || this.service == null) {
            chain.doFilter(request, response);
            return;
        }
        // What this request raises reaches PingFederate's audit log with the caller's address.
        PfRequestScope.Context outer = PfRequestScope.enter(http);
        try {
            String clientAssertion = http.getParameter("client_assertion");
            String clientId = clientIdOf(http, clientAssertion);
            if (clientId == null) {
                chain.doFilter(request, response);
                return;
            }
            try {
                this.service.admit(clientId, extractTrustChain(clientAssertion), this.issuerResolver.apply(http));
            }
            catch (RegistrationRejectedException e) {
                if (!this.failClosed) {
                    LOGGER.info((Object)("Automatic registration skipped (" + e.error() + "): " + e.getMessage()));
                    chain.doFilter(request, response);
                    return;
                }
                // RFC 6749 §5.2: a client whose federation registration cannot stand has failed client
                // authentication; one whose federation cannot be reached right now, or that arrived while this
                // server was busy registering, may try again.
                boolean retryable = e.isRetryable();
                if (retryable) {
                    httpResponse.setHeader("Retry-After", e.kind() == RegistrationRejectedException.Kind.BUSY ? "2"
                            : Long.toString(RegistrationService.TRANSPORT_FAILURE_BACKOFF_SECONDS));
                }
                OAuthErrorWriter.write(httpResponse, retryable ? 503 : 401, retryable ? "temporarily_unavailable" : "invalid_client",
                        e.getMessage());
                return;
            }
            catch (Exception e) {
                if (!this.failClosed) {
                    LOGGER.info((Object)("Automatic registration skipped: " + e.getClass().getSimpleName()));
                    chain.doFilter(request, response);
                    return;
                }
                LOGGER.error((Object)"Federation registration at the token endpoint failed", e);
                OAuthErrorWriter.write(httpResponse, 500, "server_error", "the federation registration could not be completed");
                return;
            }
            chain.doFilter(request, response);
        }
        finally {
            PfRequestScope.exit(outer);
        }
    }

    /**
     * The client the request names, in this order: the {@code sub} of its {@code client_assertion}, its {@code client_id}
     * parameter, and the {@code sub} of its {@code OAuth-Client-Attestation} header. Null when it names none - such a
     * request is left to PingFederate.
     *
     * <p>None of them is verified yet: PingFederate verifies the assertion next, and ClientAttestationAuth, mapped after
     * this filter, verifies the attestation and refuses the request unless the verified {@code sub} is the one it read
     * first (and, when there is one, the {@code client_id} parameter). Here the name only chooses which registration is
     * looked up - renewed when due, its expiry enforced when past it. A lie can only name another client, which the
     * {@code client_id} parameter could always do; and the request it came with is then refused, or fails
     * authentication, as that client. The attestation's {@code sub} is read so that an attested request, which need send
     * no {@code client_id}, is not let past its client's expired registration. More than one attestation header names
     * nothing: ClientAttestationAuth refuses that request.
     */
    static String clientIdOf(HttpServletRequest request, String clientAssertion) {
        String fromAssertion = unverifiedSubject(clientAssertion);
        if (fromAssertion != null) {
            return fromAssertion;
        }
        String clientId = request.getParameter("client_id");
        if (clientId != null && !clientId.isBlank()) {
            return clientId;
        }
        Enumeration<String> attestations = request.getHeaders(ATTESTATION_HEADER);
        if (attestations == null || !attestations.hasMoreElements()) {
            return null;
        }
        String attestation = attestations.nextElement();
        return attestations.hasMoreElements() ? null : unverifiedSubject(attestation);
    }

    /** A JWT's {@code sub}, not verified; null when it has none or is not a JWT. */
    private static String unverifiedSubject(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            return null;
        }
        try {
            String sub = JwtCodec.parseUnverifiedClaims(jwt).getSubject();
            return sub == null || sub.isBlank() ? null : sub;
        }
        catch (Exception e) {
            // Not a JWT PingFederate (or ClientAttestationAuth) will accept either.
            return null;
        }
    }

    private static List<String> extractTrustChain(String clientAssertion) {
        if (clientAssertion == null || clientAssertion.isBlank()) {
            return Collections.emptyList();
        }
        Map<String, Object> headers;
        try {
            headers = JwtCodec.getJwtHeaders(clientAssertion);
        }
        catch (Exception e) {
            return Collections.emptyList();
        }
        Object rawTrustChain = headers.get("trust_chain");
        if (!(rawTrustChain instanceof List)) {
            return Collections.emptyList();
        }
        List rawList = (List)rawTrustChain;
        ArrayList<String> trustChainList = new ArrayList<String>(rawList.size());
        for (Object item : rawList) {
            if (item instanceof String) {
                trustChainList.add((String)item);
            }
        }
        return trustChainList;
    }

    @Override
    public void destroy() {
    }


}
