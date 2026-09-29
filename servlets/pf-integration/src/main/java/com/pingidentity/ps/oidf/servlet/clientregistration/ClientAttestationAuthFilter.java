/*
 * attest_jwt_client_auth adapter: makes the OAuth-Client-Attestation headers the client's only
 * credential at PingFederate's token endpoint.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.jose.CompactJws;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.authority.EntityStatus;
import com.pingidentity.ps.oidf.authority.HostedEntity;
import com.pingidentity.ps.oidf.authority.HostedEntityRegistry;
import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationException;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.platform.pf.internals.PfInternals;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationResult;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Locale;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

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
 * ({@code iss} = {@code sub} = the resolved client id) signed with that client's own <em>bridge key</em>
 * ({@link BridgeSigners}, one per client), whose public half is already in the client's registered JWKS.
 * The workload therefore sends only
 * the draft's wire format — two headers, no {@code client_secret}, no {@code client_id} — and PF's own
 * authenticator makes the accept/reject decision on the bridge assertion.
 *
 * <p><b>Fail closed:</b> an invalid attestation is rejected here with the draft's error codes and never
 * reaches PF. A request with <em>no</em> attestation header passes through untouched — PF then enforces
 * whatever authentication that client is configured for, so the filter can never widen access; it only
 * translates a verified attestation into a credential PF understands. The attestation is verified ONCE
 * per request: this filter publishes the verified context as a server-side request attribute, and the
 * OGNL issuance criterion on the engine classloader reuses it rather than calling {@code verify()} again
 * ({@code verify()} consumes the PoP {@code jti} and any challenge, so a second call would report a
 * replay as soon as both classloaders share a Redis store). When the attribute is absent — a deployment
 * that runs without this filter — the criterion verifies for itself.
 *
 * <p>Which attesters may vouch for a client is also per client: the same {@code OIDF_BRIDGE_SIGNING_KEYS}
 * entry names them as {@code "attesters"}. Federation trust says an attester is genuine; the binding
 * says it is <em>this client's</em>. A trusted attester naming a client it is not bound to is refused,
 * and so - by default - is a client bound to nobody ({@code OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING}).
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
    /**
     * draft-ietf-oauth-rfc7523bis explicit typing. PingFederate 13.1 with Rfc7523bisCompliantAudienceVerification
     * on refuses a client assertion typed anything else, as it refused "JWT".
     */
    static final String BRIDGE_ASSERTION_TYP = "client-authentication+jwt";

    /** Where this authority hosts agents as federation entities (HostedEntityServlet). */
    static final String AGENTS_PATH = "/federation/agents/";
    static final String REQUIRE_HOSTED_AGENT_ENV = "OIDF_ATTESTATION_REQUIRE_HOSTED_AGENT";
    static final String REQUIRE_HOSTED_AGENT_PROP = "oidf.attestation.require_hosted_agent";

    private volatile boolean bridgeConfigured;
    /** This filter's part of ATTESTATION_AUTH, from init; null when a test's constructor made it and init never ran. */
    private volatile ComponentParts.Part part;
    private volatile boolean requireHostedAgent;
    /** The RAR model set the token gate asks, loaded at {@code init} when attestation authentication is live. */
    private volatile RarModels rarModels;
    private final Function<HttpServletRequest, String> issuerResolver;
    private final Supplier<String> tokenEndpointBaseUrl;

    public ClientAttestationAuthFilter() {
        this(ClientAttestationAuthFilter::defaultIssuer, ClientAttestationUtils::configuredTokenEndpointBaseUrl);
    }

    /**
     * Test seam: inject the OP-issuer resolver so tests can exercise {@link #doFilter} without
     * PingFederate's {@code OAuthIssuerUtils} singleton, whose static initializer reaches into PF's
     * HiveMind registry and cannot run outside a booted server (mirrors the same seam on
     * {@link TokenEndpointAutoRegistrationFilter}). No token endpoint base URL is set.
     */
    ClientAttestationAuthFilter(Function<HttpServletRequest, String> issuerResolver) {
        this(issuerResolver, () -> null);
    }

    /** Test seam: as above, with PingFederate's token endpoint base URL setting as well. */
    ClientAttestationAuthFilter(Function<HttpServletRequest, String> issuerResolver, Supplier<String> tokenEndpointBaseUrl) {
        this.issuerResolver = issuerResolver;
        this.tokenEndpointBaseUrl = tokenEndpointBaseUrl;
    }

    private static String defaultIssuer(HttpServletRequest request) {
        return PfInternals.issuer(request);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        ComponentParts.Part part = Startup.begin(Startup.ATTESTATION_AUTH, "ClientAttestationAuthFilter");
        this.part = part;
        part.start(() -> this.init(filterConfig, part));
    }

    /**
     * The start function: what {@code init} did before S-9, run by {@link ComponentParts.Part#start} at deploy and again
     * by each supervisor retry after a dependency failure. What it throws is the part's state, never the container's.
     */
    private void init(FilterConfig filterConfig, ComponentParts.Part part) throws ServletException {
        // Everything is resolved into locals and published at the end, so a retry after a failure starts clean
        // and a request never meets half of one attempt. OIDF_ATTESTATION_AUTH_ENABLED=false - or its superseded
        // name OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false - disables the part before any of this runs.
        boolean requireHostedAgent = requireHostedAgentSetting(System.getProperty(REQUIRE_HOSTED_AGENT_PROP),
                System.getenv(REQUIRE_HOSTED_AGENT_ENV));
        boolean bridgeConfigured;
        RarModels rarModels = null;
        // Signing keys are per client and resolved per request, so what is checked here is whether bridge
        // signing is configured AT ALL. A deployment that registers clients for attestation auth with no
        // signing configured is one where this filter passes everything through and those clients are
        // authenticated by nothing - the failure that must not be silent. Per-client absence is a
        // different thing and is a 401 for that client, not a boot failure for everyone.
        try {
            bridgeConfigured = BridgeSigners.isConfigured();
        }
        catch (IllegalStateException e) {
            // A broken or superseded configuration is a deployment error, and the container contract for
            // that is ServletException - an IllegalStateException out of init is not reliably surfaced.
            throw new ServletException("attest_jwt_client_auth: " + e.getMessage(), e);
        }
        if (!bridgeConfigured) {
            // Switched on, or inferred: either way a deployment that runs this filter without a bridge key is one
            // whose attestation clients are authenticated by nothing, so the part is refused, not disabled.
            part.failedConfig("attest_jwt_client_auth: no bridge signing configured. Set " + BridgeSigners.BACKING_ENV + " and "
                    + BridgeSigners.KEYS_ENV + ", or set " + ComponentSwitches.ATTESTATION_AUTH
                    + "=false to deploy without attestation-based client authentication");
            return;
        } else {
            // Attestation authentication is live, so an attester that is not statically trusted resolves
            // through a trust chain to the deployment's anchor, whose keys are pinned out of band (OpenID
            // Federation 1.0 §4). A pinned JWKS that is not a usable public key set can never work: refuse
            // to start. An absent one is refused per attester instead - failing init would also stop this
            // web app's own /.well-known/openid-federation, which a self-anchored PF has to serve before
            // its keys can be captured - so say so once, loudly, here.
            FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
            if (runtime.isTrustControllerConfigured()) {
                if (!runtime.hasTrustAnchors()) {
                    LOGGER.error((Object) ("attest_jwt_client_auth: " + FederationRuntimeConfig.HOST_ENV + " names "
                            + runtime.trustControllerHost() + " but " + FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV
                            + " is unset - every attester resolved through the federation is refused until the trust"
                            + " anchor's keys are pinned; statically trusted attesters (oidf.mock.attesters) are unaffected"));
                    part.degraded(FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV + " is unset: every attester resolved through"
                            + " the federation is refused; statically trusted attesters are unaffected");
                } else {
                    try {
                        runtime.trustAnchors();
                    }
                    catch (RuntimeException e) {
                        throw new ServletException("attest_jwt_client_auth: " + e.getMessage(), e);
                    }
                }
            }
            // The containment model the token gate asks, once per classloader: a models document that cannot be
            // read would leave the gate enforcing something other than what the deployment wrote, so the filter
            // is FAILED_CONFIG - the same contract as a broken bridge configuration above - and, as plan item S-9
            // has it, the web app still starts and the gate refuses only attestation traffic.
            try {
                rarModels = AttestationRarModels.get();
            }
            catch (RarModelException e) {
                throw new ServletException("attest_jwt_client_auth: the RAR containment models could not be loaded: "
                        + e.getMessage() + ". Fix " + RarModels.ENV_MODELS_FILE + " or " + RarModels.ENV_MODELS + ".", e);
            }
            LOGGER.info((Object) "attest_jwt_client_auth: per-client bridge signing configured");
        }
        this.requireHostedAgent = requireHostedAgent;
        this.rarModels = rarModels;
        this.bridgeConfigured = bridgeConfigured;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (ComponentGate.filter(this.part, request, response, chain, ComponentGate::attestationTraffic)) {
            return;
        }
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
            String opIssuer = this.issuerResolver.apply(httpRequest);
            // What this server calls the endpoint, from its configuration: the issuer (the PoP audience) and the
            // URL PingFederate advertises for the endpoint under it (the DPoP htu). Never getRequestURL(), which
            // the container rebuilds from the Host header the client wrote.
            String endpointUrl = ClientAttestationUtils.endpointUrl(opIssuer, this.tokenEndpointBaseUrl.get(),
                    ClientAttestationUtils.endpointPath(httpRequest));
            ClientAttestationVerifier verifier = ClientAttestationVerifier.withRarModels(
                    ClientAttestationUtils.attesterResolver(opIssuer),
                    ClientAttestationUtils.defaultConfig(opIssuer, endpointUrl),
                    AttestationSupport.replayCache(),
                    AttestationSupport.challengeService(),
                    this.rarModels);
            String authorizationDetails = httpRequest.getParameter("authorization_details");
            if (authorizationDetails == null || authorizationDetails.isBlank()) {
                authorizationDetails = httpRequest.getParameter("oidf_requested_access");
            }
            ClientAttestationResult result = verifier.verify(attestation, pop, dpop, httpRequest.getMethod(),
                    endpointUrl, httpRequest.getParameter("client_id"), authorizationDetails);

            String clientId = result.clientId();
            // Trust in the attester is federation-wide - any issuer whose chain reaches the anchor
            // resolves keys - and says nothing about WHICH clients that attester may vouch for. Without
            // this, any trusted attester (any federation member with a resolvable leaf) could mint an
            // attestation naming some other client and be bridged to PF as that client. The binding
            // is per client, in the same entry as its bridge key, and is checked BEFORE anything about
            // this verification is published or bridged.
            String unbound = ClientAttestationAuthFilter.attesterNotBoundTo(clientId, result.attesterIssuer());
            if (unbound != null) {
                LOGGER.warn((Object) ("attest_jwt_client_auth: " + unbound));
                ClientAttestationAuthFilter.reject(httpResponse, 401, "invalid_client", unbound);
                return;
            }
            // Revoking an agent at the bank must stop it HERE, at the bank's own authorization server, and not
            // only at partners that resolve its trust chain: an attestation stays valid for its whole lifetime,
            // so an agent this authority hosts as a federation entity is checked against that entity's
            // standing on every PAR and token request (refresh included).
            String standing = ClientAttestationAuthFilter.agentStandingProblem(result.agentId(),
                    AuthoritySupport.authorityEntityIdIfConfigured(), AuthoritySupport.registryIfConfigured(),
                    this.requireHostedAgent, Instant.now());
            if (standing != null) {
                LOGGER.warn((Object) ("attest_jwt_client_auth: " + standing));
                ClientAttestationAuthFilter.reject(httpResponse, 401, "invalid_client", standing);
                return;
            }
            // Publish what we just verified, so the issuance criterion does not verify the same request a
            // second time. verify() consumes the challenge and burns the PoP jti; doing it twice destroys
            // the first result. BridgeAuthRequest wraps this request and HttpServletRequestWrapper
            // delegates attributes, so the criterion sees it on the engine classloader.
            Map<String, Object> context = ClientAttestationUtils.attestationContext(result);
            httpRequest.setAttribute(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE, context);
            // ...and under the RAR key as well, because the two are not the same deployment decision.
            // The issuance criterion publishes both (ClientAttestationUtils:167-168); this filter used to
            // publish only the first. A deployment that runs the filter WITHOUT putting the criterion on
            // the access-token mapping - which OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false explicitly
            // supports - therefore left AttestationSubject.fromAttribute(null) -> empty(), and the RAR
            // processor fell back to the client as its own subject with the attested entitlement silently
            // gone. Same already-verified Map, second key: it costs nothing and removes a way for the
            // ceiling to disappear based on how a mapping happens to be configured.
            httpRequest.setAttribute(ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE, context);

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
            String bridgeAssertion = this.mintBridgeAssertion(signer, clientId, opIssuer);
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info((Object) ("attest_jwt_client_auth: verified attestation for client_id=" + clientId
                        + " mode=" + result.mode() + " attester=" + result.attesterIssuer()
                        + "; authenticating to PF via bridge private_key_jwt"));
            }
            chain.doFilter(new BridgeAuthRequest(httpRequest, clientId, bridgeAssertion, result.agentId()), response);
        } catch (ClientAttestationException e) {
            LOGGER.info((Object) ("attest_jwt_client_auth: rejected [" + e.error() + "]: " + e.getMessage()
                    + ClientAttestationUtils.refusalDetail(e)));
            ClientAttestationAuthFilter.reject(httpResponse, ClientAttestationAuthFilter.statusFor(e), e.error(), e.getMessage());
        } catch (Throwable t) {
            // Fail closed: with attestation headers present, an internal error must never fall through to
            // PF with the original (credential-less) request.
            LOGGER.error((Object) "attest_jwt_client_auth: verification failed with an internal error", t);
            ClientAttestationAuthFilter.reject(httpResponse, 500, "server_error",
                    "client attestation could not be verified");
        }
    }

    /** Each authorization_details entry's agent marker - the name the RAR processor reads (AGENT_DETAIL_KEY). */
    static final String AGENT_MARKER = "_agent_id";

    /**
     * {@code authorization_details} with every entry carrying the agent instance this filter verified, and
     * nothing a client wrote under the marker's name. PingFederate stores a PAR request's parameters and
     * consults its RAR processor later, from the authorisation endpoint, where the attestation is gone; the
     * entries themselves are the only thing that survives. An unverified request carries no marker at all.
     * A value that is not a JSON array is returned untouched: PingFederate refuses it anyway.
     */
    @SuppressWarnings("unchecked")
    static String markAgent(String authorizationDetails, String agentId) {
        Object parsed;
        try {
            parsed = org.jose4j.json.JsonUtil.parseJson("{\"v\":" + authorizationDetails + "}").get("v");
        } catch (org.jose4j.lang.JoseException e) {
            return authorizationDetails;
        }
        if (!(parsed instanceof List)) {
            return authorizationDetails;
        }
        List<Object> marked = new java.util.ArrayList<>();
        for (Object entry : (List<Object>) parsed) {
            if (entry instanceof Map) {
                Map<String, Object> copy = new LinkedHashMap<>((Map<String, Object>) entry);
                copy.remove(AGENT_MARKER);
                if (agentId != null && !agentId.isBlank()) {
                    copy.put(AGENT_MARKER, agentId);
                }
                marked.add(copy);
            } else {
                marked.add(entry);
            }
        }
        return org.jose4j.json.internal.json_simple.JSONValue.toJSONString(marked);
    }

    /**
     * Why an attested agent may not authenticate here, or {@code null} when it may.
     *
     * <p>Only agents this authority hosts are judged: an attestation without {@code agent_id}, a deployment
     * with no hosted-entity authority, or a registry nobody has configured yet (the authority servlet
     * initialises on first use, and reading the registry first would install the in-memory fallback) all
     * pass. A hosted agent must be ACTIVE and inside its {@code notAfter}. One that is not hosted at all passes
     * unless {@code requireHosted} ({@value #REQUIRE_HOSTED_AGENT_ENV}=true) says every attested agent must
     * be a member. A registry that cannot answer throws, and the filter fails closed.
     */
    /** The system property wins when set; otherwise the environment variable; otherwise false. */
    static boolean requireHostedAgentSetting(String property, String environment) {
        return Boolean.parseBoolean(property != null && !property.isBlank() ? property : environment);
    }

    /** For tests: whether every attested agent must be a hosted member of this authority. */
    boolean requiresHostedAgent() {
        return this.requireHostedAgent;
    }

    static String agentStandingProblem(String agentId, Optional<String> authorityEntityId,
            Optional<HostedEntityRegistry> registry, boolean requireHosted, Instant now) throws AuthorityRegistryException {
        if (agentId == null || agentId.isBlank() || authorityEntityId.isEmpty() || registry.isEmpty()) {
            return null;
        }
        String entityId = authorityEntityId.get() + AGENTS_PATH + agentId;
        Optional<HostedEntity> hosted = registry.get().find(entityId);
        if (hosted.isEmpty()) {
            return requireHosted ? "agent " + entityId + " is not a member of this authority's federation" : null;
        }
        HostedEntity entity = hosted.get();
        if (entity.status() != EntityStatus.ACTIVE) {
            return "agent " + entityId + " is " + entity.status().name().toLowerCase(Locale.ROOT) + " at this authority";
        }
        if (!entity.resolvable(now)) {
            return "agent " + entityId + "'s federation membership has expired";
        }
        return null;
    }

    /**
     * A {@code private_key_jwt} client assertion for {@code clientId}, signed with that client's own key.
     *
     * <p>Built through {@link JwsSigner} rather than jose4j directly, so the private half can stay in a
     * vault: {@code OpenBaoTransitSigner} returns signature bytes without ever exposing the key, and
     * {@code CompactJws} assembles them. That is the same seam the attestation minter uses on the
     * issuing side.
     *
     * <p>Explicitly typed {@code client-authentication+jwt}, with ONE audience: {@code opIssuer}, the issuer
     * PingFederate resolves for this request, as a string. draft-ietf-oauth-rfc7523bis-11 §4 wants the issuer
     * "as its sole value" and allows a one-member array; FAPI 2.0 wants the string (§5.3.3.1: "The issuer
     * identifier value shall be sent as a string not as an item in an array"). The string meets both.
     *
     * <p>This used to be {@code typ: JWT} with {@code aud: [issuer, request URL]}, which 13.0.3 accepted and
     * 13.1.3 refuses with "Invalid typ header parameter value 'JWT'" and "Audience (aud) claim must contain
     * only one value" once {@code Rfc7523bisCompliantAudienceVerification} is on - the setting a fresh 13.1.3
     * install ships with - so every bridged request failed after the attestation had verified. With the
     * setting off, as on an archive upgraded from 13.0, the issuer is still accepted: both of 13.1.3's
     * audience providers accept the value {@code OAuthIssuerUtils.getIssuerValue} gives for the request (read
     * with javap from 13.1.3's {@code pf-protocolengine}, 2026-09-26).
     */
    private String mintBridgeAssertion(JwsSigner signer, String clientId, String opIssuer) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(clientId);
        claims.setSubject(clientId);
        claims.setAudience(opIssuer);
        claims.setJwtId(UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(ASSERTION_TTL_SECONDS / 60.0f);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", signer.algorithm());
        header.put("typ", BRIDGE_ASSERTION_TYP);
        if (signer.keyId() != null) {
            header.put("kid", signer.keyId());
        }
        return CompactJws.sign(header, claims.toJson(), signer);
    }


    /**
     * Why {@code attester} may not vouch for {@code clientId}, or {@code null} when it may.
     *
     * <p>A client whose entry binds it to attesters is refused for any other attester, always. A client
     * whose entry names none is refused too, by default, naming the setting - the same shape as a
     * missing bridge key: a 401 for this client, not a boot failure for everyone. The opt-out
     * ({@link FederationRuntimeConfig#REQUIRE_ATTESTER_BINDING_ENV}=false) relaxes only the unbound
     * case, for a deployment with one attester that knows it.
     */
    private static String attesterNotBoundTo(String clientId, String attester) {
        java.util.Set<String> bound = BridgeSigners.attestersFor(clientId);
        if (!bound.isEmpty()) {
            return bound.contains(attester) ? null
                    : "attestation for client_id=" + clientId + " was issued by " + attester
                            + ", which is not an attester this client is bound to";
        }
        if (FederationRuntimeConfig.get().requireAttesterBinding()) {
            return "attestation for client_id=" + clientId + " verified, but its entry in "
                    + BridgeSigners.KEYS_ENV + " names no \"attesters\" - any trusted attester could vouch for it. "
                    + "Add \"attesters\": [<issuer>] to the client's entry, or set "
                    + FederationRuntimeConfig.REQUIRE_ATTESTER_BINDING_ENV + "=false to let unbound clients accept any trusted attester.";
        }
        return null;
    }

    /**
     * The HTTP status a verification failure answers with: 400 for a challenge the client must fetch and for
     * {@code authorization_details} the token gate refuses, 503 when the challenge or replay store could not
     * answer ({@code temporarily_unavailable}, RFC 6749 §4.1.2.1's code for the condition, used at this endpoint
     * by plan item S3a: an outage of ours, never reported as a replay), 401 for everything else the client got
     * wrong.
     *
     * <p>The 400 for {@code invalid_authorization_details} is RFC 6749 §5.2's rule for the token endpoint: "The
     * authorization server responds with an HTTP 400 (Bad Request) status code (unless specified otherwise)".
     * RFC 9396 §6 gives the refusal no status of its own and likens it to {@code invalid_scope}, which §5.2
     * answers with 400. 0.3.0 answered both refusals with 401: {@code access_denied} for a request outside the
     * attestation's details, {@code invalid_authorization_details} for a malformed one.
     */
    static int statusFor(ClientAttestationException e) {
        if (ClientAttestationException.USE_ATTESTATION_CHALLENGE.equals(e.error())
                || ClientAttestationException.INVALID_AUTHORIZATION_DETAILS.equals(e.error())) {
            return 400;
        }
        if (ClientAttestationException.TEMPORARILY_UNAVAILABLE.equals(e.error())) {
            return 503;
        }
        return 401;
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

        BridgeAuthRequest(HttpServletRequest request, String clientId, String assertion, String agentId) {
            super(request);
            Map<String, String[]> merged = new LinkedHashMap<>(request.getParameterMap());
            merged.remove("client_secret");
            String details = request.getParameter("authorization_details");
            if (details != null && !details.isBlank()) {
                merged.put("authorization_details", new String[]{markAgent(details, agentId)});
            }
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
