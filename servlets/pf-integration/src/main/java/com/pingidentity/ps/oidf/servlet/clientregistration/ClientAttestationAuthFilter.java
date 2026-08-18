/*
 * attest_jwt_client_auth adapter: makes the OAuth-Client-Attestation headers the client's only
 * credential at PingFederate's token endpoint.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.BridgeKey;
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
 * <p>The bridge key comes from {@link BridgeKey}. It is now resolved at {@code init} and, by default,
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

    private volatile PublicJsonWebKey bridgeKey;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Resolve at init, not per request: a missing or malformed bridge key is a deployment error,
        // and the failure mode it used to produce - pass-through - is indistinguishable from "no
        // attestation clients configured" until a workload is silently let through unauthenticated.
        try {
            this.bridgeKey = BridgeKey.load().orElse(null);
        }
        catch (IllegalStateException e) {
            throw new ServletException("attest_jwt_client_auth: " + e.getMessage(), e);
        }
        if (this.bridgeKey == null) {
            if (BridgeKey.isRequired()) {
                throw new ServletException("attest_jwt_client_auth: no bridge key configured. Set "
                        + FederationRuntimeConfig.BRIDGE_KEY_ENV + ", or set "
                        + FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV
                        + "=false to deploy without attestation-based client authentication.");
            }
            LOGGER.warn((Object) ("attest_jwt_client_auth: no bridge key and "
                    + FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV + "=false - attestation headers will "
                    + "pass through and PF will enforce each client's configured authentication."));
        } else {
            LOGGER.info((Object) ("attest_jwt_client_auth bridge key loaded (kid=" + this.bridgeKey.getKeyId() + ")"));
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

        PublicJsonWebKey signer = this.bridgeKey;
        if (signer == null) {
            LOGGER.warn((Object) ("Request carries " + ATTESTATION_HEADER + " but no bridge key is configured "
                    + "(OIDF_BRIDGE_PRIVATE_JWK); passing through — PF will enforce the client's configured "
                    + "authentication method."));
            chain.doFilter(request, response);
            return;
        }

        try {
            String requestUri = httpRequest.getRequestURL() == null ? null : httpRequest.getRequestURL().toString();
            String opIssuer = OAuthIssuerUtils.getInstance().getIssuerValue(httpRequest);
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

    private String mintBridgeAssertion(PublicJsonWebKey signer, String clientId, String opIssuer,
                                       String requestUri) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(clientId);
        claims.setSubject(clientId);
        claims.setAudience(opIssuer, requestUri);
        claims.setJwtId(UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(ASSERTION_TTL_SECONDS / 60.0f);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signer.getPrivateKey());
        jws.setKeyIdHeaderValue(signer.getKeyId());
        jws.setAlgorithmHeaderValue("ES256");
        return jws.getCompactSerialization();
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
