/*
 * attest_jwt_client_auth adapter: makes the OAuth-Client-Attestation headers the client's only
 * credential at PingFederate's token endpoint.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.jose.CompactJws;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationException;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationResult;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;

/**
 * Implements {@code attest_jwt_client_auth} (draft-ietf-oauth-attestation-based-client-auth) in front of
 * PingFederate's token endpoint, which has no native support and no SDK extension point for it. Map this
 * filter over {@code /as/token.oauth2} in {@code pf-runtime.war}'s web.xml (the assemble script does it,
 * the same mechanism that registers {@code SsfLogoutSignal}).
 *
 * <p>When a request carries an {@code OAuth-Client-Attestation} header, the filter verifies the
 * attestation and its PoP with the same {@link ClientAttestationVerifier} the OGNL issuance criterion
 * uses, resolves the client from the attestation's {@code sub}, and forwards a wrapped request that
 * authenticates to PF with its native {@code private_key_jwt}: a {@code client_assertion}
 * ({@code iss} = {@code sub} = the resolved client id) signed by a deployment-held <em>bridge key</em>
 * whose public half is registered in each attestation client's JWKS. The workload therefore sends only
 * the draft's wire format — two headers, no {@code client_secret}, no {@code client_id} — and PF's own
 * authenticator makes the accept/reject decision on the bridge assertion.
 *
 * <p><b>Fail closed:</b> an invalid attestation is rejected here with the draft's error codes and never
 * reaches PF. A request with <em>no</em> attestation header passes through untouched — PF then enforces
 * whatever authentication that client is configured for, so the filter can never widen access; it only
 * translates a verified attestation into a credential PF understands. Requests are verified again by the
 * OGNL issuance criterion on the engine classloader; the two run on separate replay caches (one per
 * classloader), so each sees a given PoP {@code jti} exactly once per request and genuine replays fail
 * in both.
 *
 * <p>Signing keys come from {@link BridgeSigners}, one PER CLIENT. What is checked at {@code init} is
 * required: a deployment that registers clients for attestation authentication but has no bridge key
 * is one where this filter passes everything through and those clients are authenticated by nothing.
 * That used to degrade silently to pass-through; it now refuses to deploy, and
 * {@code OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false} is the explicit opt-out for an environment that
 * deliberately runs without attestation-based client authentication.
 */
public final class ClientAttestationAuthFilter implements Filter {
    private static final Log LOGGER = LogFactory.getLog(ClientAttestationAuthFilter.class);
    private static final String ATTESTATION_HEADER = "OAuth-Client-Attestation";
    private static final String POP_HEADER = "OAuth-Client-Attestation-PoP";
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final long ASSERTION_TTL_SECONDS = 60L;

    private volatile boolean bridgeConfigured;
    private final Function<HttpServletRequest, String> issuerResolver;

    public ClientAttestationAuthFilter() {
        this.issuerResolver = ClientAttestationAuthFilter::defaultIssuer;
    }

    /**
     * Test seam: inject the OP-issuer resolver so tests can exercise {@link #doFilter} without
     * PingFederate's {@code OAuthIssuerUtils} singleton, whose static initializer reaches into PF's
     * HiveMind registry and cannot run outside a booted server (mirrors the same seam on
     * {@link TokenEndpointAutoRegistrationFilter}).
     */
    ClientAttestationAuthFilter(Function<HttpServletRequest, String> issuerResolver) {
        this.issuerResolver = issuerResolver;
    }

    private static String defaultIssuer(HttpServletRequest request) {
        return OAuthIssuerUtils.getInstance().getIssuerValue(request);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Signing keys are per client and resolved per request, so what is checked here is whether bridge
        // signing is configured AT ALL. A deployment that registers clients for attestation auth with no
        // signing configured is one where this filter passes everything through and those clients are
        // authenticated by nothing - the failure that must not be silent. Per-client absence is a
        // different thing and is a 401 for that client, not a boot failure for everyone.
        try {
            this.bridgeConfigured = BridgeSigners.isConfigured();
        }
        catch (IllegalStateException e) {
            // A broken or superseded configuration is a deployment error, and the container contract for
            // that is ServletException - an IllegalStateException out of init is not reliably surfaced.
            throw new ServletException("attest_jwt_client_auth: " + e.getMessage(), e);
        }
        if (!this.bridgeConfigured) {
            if (BridgeSigners.isRequired()) {
                throw new ServletException("attest_jwt_client_auth: no bridge signing configured. Set "
                        + BridgeSigners.BACKING_ENV + " and " + BridgeSigners.KEYS_ENV + ", or set "
                        + FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV
                        + "=false to deploy without attestation-based client authentication.");
            }
            LOGGER.warn((Object) ("attest_jwt_client_auth: no bridge signing and "
                    + FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV + "=false - attestation headers will "
                    + "pass through and PF will enforce each client's configured authentication."));
        } else {
            LOGGER.info((Object) "attest_jwt_client_auth: per-client bridge signing configured");
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String attestation;
        String pop;
        String dpop;
        try {
            attestation = ClientAttestationAuthFilter.singleHeader(httpRequest, ATTESTATION_HEADER);
            pop = ClientAttestationAuthFilter.singleHeader(httpRequest, POP_HEADER);
            dpop = ClientAttestationAuthFilter.singleHeader(httpRequest, "DPoP");
        } catch (IllegalArgumentException e) {
            ClientAttestationAuthFilter.reject(httpResponse, 400, "invalid_request", e.getMessage());
            return;
        }
        if (attestation == null || attestation.isBlank()) {
            chain.doFilter(request, response);
            return;
        }

        if (!this.bridgeConfigured) {
            LOGGER.warn((Object) ("Request carries " + ATTESTATION_HEADER + " but no bridge signing is "
                    + "configured (" + BridgeSigners.BACKING_ENV + "/" + BridgeSigners.KEYS_ENV
                    + "); passing through — PF will enforce the client's configured authentication method."));
            chain.doFilter(request, response);
            return;
        }

        try {
            String requestUri = httpRequest.getRequestURL() == null ? null : httpRequest.getRequestURL().toString();
            String opIssuer = this.issuerResolver.apply(httpRequest);
            ClientAttestationVerifier verifier = new ClientAttestationVerifier(
                    ClientAttestationUtils.attesterResolver(opIssuer),
                    ClientAttestationUtils.defaultConfig(opIssuer, requestUri),
                    AttestationSupport.replayCache(),
                    AttestationSupport.challengeService());
            String authorizationDetails = httpRequest.getParameter("authorization_details");
            if (authorizationDetails == null || authorizationDetails.isBlank()) {
                authorizationDetails = httpRequest.getParameter("oidf_requested_access");
            }
            ClientAttestationResult result = verifier.verify(attestation, pop, dpop, httpRequest.getMethod(),
                    requestUri, httpRequest.getParameter("client_id"), authorizationDetails);

            String clientId = result.clientId();
            // Publish what we just verified, so the issuance criterion does not verify the same request a
            // second time. verify() consumes the challenge and burns the PoP jti; doing it twice destroys
            // the first result. BridgeAuthRequest wraps this request and HttpServletRequestWrapper
            // delegates attributes, so the criterion sees it on the engine classloader.
            httpRequest.setAttribute(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE,
                    ClientAttestationUtils.attestationContext(result));

            // The signing key belongs to THIS client, resolved now rather than held for all of them.
            // A client with no key configured cannot authenticate; that is a 401 for it alone.
            JwsSigner signer = BridgeSigners.forClient(clientId).orElse(null);
            if (signer == null) {
                LOGGER.warn((Object) ("attest_jwt_client_auth: attestation verified for client_id=" + clientId
                        + " but no bridge signing key is configured for it - refusing rather than passing "
                        + "an unauthenticated request through. Add it to " + BridgeSigners.KEYS_ENV + "."));
                ClientAttestationAuthFilter.reject(httpResponse, 401, "invalid_client",
                        "no bridge signing key is configured for this client");
                return;
            }
            String bridgeAssertion = this.mintBridgeAssertion(signer, clientId, opIssuer, requestUri);
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info((Object) ("attest_jwt_client_auth: verified attestation for client_id=" + clientId
                        + " mode=" + result.mode() + " attester=" + result.attesterIssuer()
                        + "; authenticating to PF via bridge private_key_jwt"));
            }
            chain.doFilter(new BridgeAuthRequest(httpRequest, clientId, bridgeAssertion), response);
        } catch (ClientAttestationException e) {
            LOGGER.info((Object) ("attest_jwt_client_auth: rejected [" + e.error() + "]: " + e.getMessage()));
            int status = ClientAttestationException.USE_ATTESTATION_CHALLENGE.equals(e.error()) ? 400 : 401;
            ClientAttestationAuthFilter.reject(httpResponse, status, e.error(), e.getMessage());
        } catch (Throwable t) {
            // Fail closed: with attestation headers present, an internal error must never fall through to
            // PF with the original (credential-less) request.
            LOGGER.error((Object) "attest_jwt_client_auth: verification failed with an internal error", t);
            ClientAttestationAuthFilter.reject(httpResponse, 500, "server_error",
                    "client attestation could not be verified");
        }
    }

    /**
     * A {@code private_key_jwt} client assertion for {@code clientId}, signed with that client's own key.
     *
     * <p>Built through {@link JwsSigner} rather than jose4j directly, so the private half can stay in a
     * vault: {@code OpenBaoTransitSigner} returns signature bytes without ever exposing the key, and
     * {@code CompactJws} assembles them. That is the same seam the attestation minter uses on the
     * issuing side.
     */
    private String mintBridgeAssertion(JwsSigner signer, String clientId, String opIssuer,
                                       String requestUri) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(clientId);
        claims.setSubject(clientId);
        claims.setAudience(opIssuer, requestUri);
        claims.setJwtId(UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(ASSERTION_TTL_SECONDS / 60.0f);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", signer.algorithm());
        header.put("typ", "JWT");
        if (signer.keyId() != null) {
            header.put("kid", signer.keyId());
        }
        return CompactJws.sign(header, claims.toJson(), signer);
    }


    private static void reject(HttpServletResponse response, int status, String error, String description)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        if (description != null && !description.isBlank()) {
            body.put("error_description", description);
        }
        response.getWriter().write(org.jose4j.json.JsonUtil.toJson(body));
    }

    private static String singleHeader(HttpServletRequest request, String name) {
        Enumeration<String> values = request.getHeaders(name);
        if (values == null || !values.hasMoreElements()) {
            return null;
        }
        String first = values.nextElement();
        if (values.hasMoreElements()) {
            throw new IllegalArgumentException("Multiple '" + name + "' headers present; exactly one is required");
        }
        return first;
    }

    @Override
    public void destroy() {
    }

    /**
     * The forwarded request: the verified client's {@code client_id} plus the bridge
     * {@code client_assertion} replace whatever credential parameters the workload sent
     * ({@code client_secret} is dropped so a stale secret can neither help nor conflict).
     */
    private static final class BridgeAuthRequest extends HttpServletRequestWrapper {
        private final Map<String, String[]> parameters;

        BridgeAuthRequest(HttpServletRequest request, String clientId, String assertion) {
            super(request);
            Map<String, String[]> merged = new LinkedHashMap<>(request.getParameterMap());
            merged.remove("client_secret");
            merged.put("client_id", new String[]{clientId});
            merged.put("client_assertion_type", new String[]{ASSERTION_TYPE});
            merged.put("client_assertion", new String[]{assertion});
            this.parameters = Collections.unmodifiableMap(merged);
        }

        @Override
        public String getParameter(String name) {
            String[] values = this.parameters.get(name);
            return values == null || values.length == 0 ? null : values[0];
        }

        @Override
        public String[] getParameterValues(String name) {
            String[] values = this.parameters.get(name);
            return values == null ? null : values.clone();
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return this.parameters;
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.enumeration(this.parameters.keySet());
        }

        /**
         * PF must not read HTTP Basic credentials that no longer match the injected parameters; the
         * attestation flow never uses Basic auth, so it is suppressed entirely on the bridged request.
         */
        @Override
        public String getHeader(String name) {
            return "Authorization".equalsIgnoreCase(name) ? null : super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            return "Authorization".equalsIgnoreCase(name)
                    ? Collections.emptyEnumeration() : super.getHeaders(name);
        }
    }
}
