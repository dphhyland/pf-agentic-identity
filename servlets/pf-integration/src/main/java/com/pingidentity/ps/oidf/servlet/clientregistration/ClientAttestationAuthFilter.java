/*
 * attest_jwt_client_auth adapter: makes the OAuth-Client-Attestation headers the client's only
 * credential at PingFederate's token, PAR, CIBA, device authorization, introspection and revocation endpoints.
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
import com.pingidentity.ps.oidf.rar.model.Omission;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationResult;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationEvents;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationPolicyException;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationPolicyResolver;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.AttestationPolicyScan;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationPolicy;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils;
import com.pingidentity.ps.oidf.servlet.clientregistration.utils.SubjectTokenVerifier;
import com.pingidentity.ps.oidf.servlet.oauth.FederationErrorPage;
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
 * PingFederate's endpoints that authenticate a client, which have no native support and no SDK extension point for
 * it: the token endpoint, PAR, CIBA's backchannel endpoint, the device authorization endpoint, introspection and
 * revocation ({@link AttestedEndpoint}; {@code build/pingfederate/filters.xml} maps it, the war assembler checks the
 * mapping and its order). It is also mapped over the authorization endpoint, where it verifies nothing and only
 * refuses details an attestation-required client did not push ({@link PushedDetailsRule}).
 *
 * <p><b>The details PingFederate stores are the ones granted.</b> PingFederate issues what was stored at PAR and CIBA
 * whatever a token request then says (U-0019, the rig, 2026-09-30), and the device grant is taken to do the same, so a
 * request's {@code authorization_details} are held to the attestation's where they arrive: the filter grants
 * {@code authorize(requested, ceiling, INHERIT)} and forwards the granted details, marked with the verified agent, in
 * place of the client's ({@link GrantedDetails}). A request that asks for none forwards none. A signed request object
 * cannot be rewritten, so its details must be within the attestation's as they stand. Plan item S4d, F-0032.
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
 * translates a verified attestation into a credential PF understands - unless the client it names has
 * {@code attestation_required=true}, which is refused here (401 {@code invalid_client}).
 *
 * <p><b>Each client's policy:</b> the attestation is verified under the server's policy tightened by the client's
 * {@code attestation_*} extended properties ({@link AttestationPolicyResolver}, the same resolver the OGNL criterion
 * asks, plan item S4c). The client is found from the attestation's {@code sub} before it is verified -
 * draft-ietf-oauth-attestation-based-client-auth-10 §4: "sub: REQUIRED.  The sub (subject) claim MUST specify
 * client_id value of the OAuth Client." - and the verified {@code sub} must be that client. A client whose properties
 * are refused is 401 {@code invalid_client}; a client manager that cannot answer is 503. The attestation is verified ONCE
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
    private final ClientStore clientStore;
    private final AttestationPolicyResolver policies;
    private final SubjectTokenVerifier subjectTokens;
    private final PushedDetailsRule pushedDetails;
    /** The page a refusal at the authorization endpoint is answered with, read on first use. */
    private volatile FederationErrorPage errorPage;

    public ClientAttestationAuthFilter() {
        this(ClientAttestationAuthFilter::defaultIssuer, ClientAttestationUtils::configuredTokenEndpointBaseUrl,
                new PfMgmtClientStore(), AttestationPolicyResolver.shared(), SubjectTokenVerifier.pingFederate());
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

    /**
     * Test seam: as above, with PingFederate's token endpoint base URL setting as well. Its clients are a store that
     * has none, so every client has the server's policy, and no subject token verifies.
     */
    ClientAttestationAuthFilter(Function<HttpServletRequest, String> issuerResolver, Supplier<String> tokenEndpointBaseUrl) {
        this(issuerResolver, tokenEndpointBaseUrl, NO_CLIENTS,
                AttestationPolicyResolver.over(AttestationPolicyResolver.from(NO_CLIENTS), java.time.Clock.systemUTC(), () -> false),
                new SubjectTokenVerifier(() -> null));
    }

    /** Test seam: every collaborator supplied. */
    ClientAttestationAuthFilter(Function<HttpServletRequest, String> issuerResolver, Supplier<String> tokenEndpointBaseUrl,
            ClientStore clientStore, AttestationPolicyResolver policies, SubjectTokenVerifier subjectTokens) {
        this.issuerResolver = issuerResolver;
        this.tokenEndpointBaseUrl = tokenEndpointBaseUrl;
        this.clientStore = clientStore;
        this.policies = policies;
        this.subjectTokens = subjectTokens;
        this.pushedDetails = new PushedDetailsRule(policies, this::errorPage);
    }

    /** A client store with no clients, for the test seams. */
    static final ClientStore NO_CLIENTS = new ClientStore() {
        @Override
        public void add(org.sourceid.oauth20.domain.Client client) {
        }

        @Override
        public void update(org.sourceid.oauth20.domain.Client client) {
        }

        @Override
        public org.sourceid.oauth20.domain.Client get(String clientId) {
            return null;
        }

        @Override
        public java.util.Collection<org.sourceid.oauth20.domain.Client> getAll() {
            return List.of();
        }

        @Override
        public void disable(org.sourceid.oauth20.domain.Client client) {
        }
    };

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
        // Every client's attestation_* properties, read once now and every ten minutes on this copy's executor:
        // a client they would refuse is named in the health detail before its first request is (plan item S4c).
        // Started here, the webapp's start function, so the engine's copy never runs it; it never blocks or throws.
        AttestationPolicyScan.start(this.clientStore, this.policies);
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
        String path = ClientAttestationUtils.endpointPath(httpRequest);
        AttestedEndpoint endpoint = AttestedEndpoint.of(path);
        if (!endpoint.authenticates()) {
            // The authorization endpoint: nothing to verify, only details that should have been pushed to refuse.
            if (!this.bridgeConfigured || !this.pushedDetails.refused(httpRequest, httpResponse)) {
                chain.doFilter(request, response);
            }
            return;
        }

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
            // No attestation: PingFederate authenticates the client as it is configured to - unless the client says it
            // authenticates only with one (attestation_required), which is refused here rather than passed on.
            if (!this.bridgeConfigured || !this.refusedWithoutAttestation(httpRequest, httpResponse)) {
                chain.doFilter(request, response);
            }
            return;
        }

        if (!this.bridgeConfigured) {
            LOGGER.warn((Object) ("Request carries " + ATTESTATION_HEADER + " but no bridge signing is "
                    + "configured (" + BridgeSigners.BACKING_ENV + "/" + BridgeSigners.KEYS_ENV
                    + "); passing through — PF will enforce the client's configured authentication method."));
            chain.doFilter(request, response);
            return;
        }

        // The client the attestation names, read before it is verified so that it is verified under that client's
        // policy (ABCA-10 §4: sub is the client_id), and held to the verified sub afterwards.
        String claimedClient = ClientAttestationAuthFilter.unverifiedSubject(attestation);
        // RFC 6749 §3.2: "Request and response parameters MUST NOT be included more than once." The filter forwards one
        // value in place of the client's, so which of several PingFederate would have read is never left to it.
        String repeated = ClientAttestationAuthFilter.repeatedParameter(httpRequest);
        if (repeated != null) {
            this.refuse(httpResponse, claimedClient, 400, "invalid_request", repeated + " must not be sent more than once");
            return;
        }
        try {
            String opIssuer = this.issuerResolver.apply(httpRequest);
            // What this server calls the endpoint, from its configuration: the issuer (the PoP audience) and the
            // URL PingFederate advertises for the endpoint under it (the DPoP htu). Never getRequestURL(), which
            // the container rebuilds from the Host header the client wrote.
            String tokenBase = this.tokenEndpointBaseUrl.get();
            String endpointUrl = ClientAttestationUtils.endpointUrl(opIssuer, tokenBase, path);
            ClientAttestationConfig policy;
            try {
                policy = ClientAttestationUtils.effectivePolicy(this.policies, claimedClient, opIssuer, tokenBase, path);
            } catch (AttestationPolicyException e) {
                this.refusePolicy(httpResponse, e);
                return;
            } catch (AttestationPolicyResolver.Unavailable e) {
                this.refuseUnavailable(httpResponse, claimedClient, e);
                return;
            }
            ClientAttestationVerifier verifier = ClientAttestationVerifier.withRarModels(
                    ClientAttestationUtils.attesterResolver(opIssuer),
                    policy,
                    AttestationSupport.replayCache(),
                    AttestationSupport.challengeService(),
                    this.rarModels);
            // What is asked for, and how an omitted constrained field is read. authorization_details is forwarded as
            // the details granted (INHERIT: the attestation's value fills the field); oidf_requested_access is
            // forwarded as sent, so it is held to the attestation as it stands (STRICT). Introspection and revocation
            // carry no details, and whatever was sent there under the name is not forwarded.
            String sentDetails = endpoint.carriesDetails() ? httpRequest.getParameter(GrantedDetails.PARAMETER) : null;
            boolean rewrite = sentDetails != null && !sentDetails.isBlank();
            String checkedDetails = rewrite ? sentDetails
                    : endpoint.carriesDetails() ? httpRequest.getParameter(REQUESTED_ACCESS) : null;
            ClientAttestationResult result = verifier.verify(attestation, pop, dpop, httpRequest.getMethod(),
                    endpointUrl, httpRequest.getParameter("client_id"), checkedDetails,
                    rewrite ? Omission.INHERIT : Omission.STRICT);

            String clientId = result.clientId();
            String changed = ClientAttestationAuthFilter.subjectChanged(claimedClient, clientId);
            if (changed != null) {
                this.refuse(httpResponse, claimedClient, 401, "invalid_client", changed);
                return;
            }
            // Trust in the attester is federation-wide - any issuer whose chain reaches the anchor
            // resolves keys - and says nothing about WHICH clients that attester may vouch for. Without
            // this, any trusted attester (any federation member with a resolvable leaf) could mint an
            // attestation naming some other client and be bridged to PF as that client. The binding
            // is per client, in the same entry as its bridge key, and is checked BEFORE anything about
            // this verification is published or bridged.
            String unbound = ClientAttestationAuthFilter.attesterNotBoundTo(clientId, result.attesterIssuer());
            if (unbound != null) {
                LOGGER.warn((Object) ("attest_jwt_client_auth: " + unbound));
                this.refuse(httpResponse, clientId, 401, "invalid_client", unbound);
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
                this.refuse(httpResponse, clientId, 401, "invalid_client", standing);
                return;
            }
            // What cannot be rewritten is held to the attestation as it stands: a signed request object at PAR and CIBA.
            // RFC 9126 §2.1 forbids request_uri at PAR ("The \"request_uri\" authorization request parameter is one
            // exception, and it MUST NOT be provided"); refused here so a request object by reference is never one whose
            // details this filter did not see.
            if (endpoint.takesRequestObjects()) {
                if (endpoint == AttestedEndpoint.PAR && ClientAttestationAuthFilter.present(httpRequest.getParameter("request_uri"))) {
                    this.refuse(httpResponse, clientId, 400, "invalid_request", "request_uri must not be provided at the PAR endpoint");
                    return;
                }
                String requestObject = httpRequest.getParameter("request");
                if (ClientAttestationAuthFilter.present(requestObject)) {
                    GrantedDetails.requestObjectWithin(this.rarModels, requestObject, attestation);
                }
            }
            // Publish what we just verified, so the issuance criterion does not verify the same request a
            // second time. verify() consumes the challenge and burns the PoP jti; doing it twice destroys
            // the first result. BridgeAuthRequest wraps this request and HttpServletRequestWrapper
            // delegates attributes, so the criterion sees it on the engine classloader. The context carries the
            // policy's fingerprint, which the criterion checks against the policy it resolves, and the subject of a
            // token exchange's subject token when it verifies as PingFederate's (F-0074).
            Map<String, Object> context = ClientAttestationUtils.attestationContext(result, policy, httpRequest, opIssuer,
                    this.subjectTokens);
            httpRequest.setAttribute(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE, context);
            // ...and under the RAR key as well, because the two are not the same deployment decision.
            // The issuance criterion publishes both; this filter used to
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
                this.refuse(httpResponse, clientId, 401, "invalid_client",
                        "no bridge signing key is configured for this client");
                return;
            }
            String bridgeAssertion = this.mintBridgeAssertion(signer, clientId, opIssuer);
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info((Object) ("attest_jwt_client_auth: verified attestation for client_id=" + clientId
                        + " mode=" + result.mode() + " attester=" + result.attesterIssuer()
                        + "; authenticating to PF via bridge private_key_jwt"));
            }
            AttestationEvents.verified(AttestationEvents.FILTER, clientId, result.attesterIssuer());
            String forwarded = rewrite ? GrantedDetails.forwarded(result.grantedAuthorizationDetails(),
                    GrantedDetails.requested(sentDetails), result.agentId()) : null;
            chain.doFilter(new BridgeAuthRequest(httpRequest, clientId, bridgeAssertion, forwarded), response);
        } catch (ClientAttestationException e) {
            LOGGER.info((Object) ("attest_jwt_client_auth: rejected [" + e.error() + "]: " + e.getMessage()
                    + ClientAttestationUtils.refusalDetail(e)));
            this.refuse(httpResponse, claimedClient, ClientAttestationAuthFilter.statusFor(e), e.error(), e.getMessage());
        } catch (Throwable t) {
            // Fail closed: with attestation headers present, an internal error must never fall through to
            // PF with the original (credential-less) request.
            LOGGER.error((Object) "attest_jwt_client_auth: verification failed with an internal error", t);
            this.refuse(httpResponse, claimedClient, 500, "server_error", "client attestation could not be verified");
        }
    }

    /**
     * Refuses a request that carries no attestation for a client that authenticates only with one
     * ({@code attestation_required}), or whose {@code attestation_required} is refused, or when the client manager
     * cannot answer. The client is each one the request names ({@link #namedClients}), none of them verified: PingFederate decides which of them the request
     * authenticates as, and each is refused here if it may not authenticate without an attestation.
     *
     * @return whether the request was refused
     */
    boolean refusedWithoutAttestation(HttpServletRequest request, HttpServletResponse response) throws IOException {
        for (String clientId : ClientAttestationAuthFilter.namedClients(request)) {
            ClientAttestationPolicy client;
            try {
                client = this.policies.policy(clientId);
                // Only attestation_required decides a request without an attestation; the other properties apply to
                // one with an attestation, and are refused there.
                if (client.invalid() != null && ClientAttestationPolicy.REQUIRED.equals(client.invalid().property())) {
                    throw client.invalid();
                }
            } catch (AttestationPolicyException e) {
                this.refusePolicy(response, e);
                return true;
            } catch (AttestationPolicyResolver.Unavailable e) {
                this.refuseUnavailable(response, clientId, e);
                return true;
            }
            if (client.attestationRequired()) {
                LOGGER.info((Object) ("attest_jwt_client_auth: client_id=" + com.pingidentity.ps.oidf.platform.events.LogSafe.value(clientId)
                        + " has " + ClientAttestationPolicy.REQUIRED
                        + "=true and sent no " + ATTESTATION_HEADER + "; refused"));
                this.refuse(response, clientId, 401, "invalid_client", "this client authenticates with a client attestation");
                return true;
            }
        }
        return false;
    }

    /**
     * The clients a request without an attestation names, unverified and in order, without repeats: its
     * {@code client_id}, the user of HTTP Basic both as sent and form-decoded (RFC 6749 §2.3.1), and its
     * {@code client_assertion}'s {@code sub} and {@code iss}. Whichever of them PingFederate authenticates the
     * request as is among them; each extra name can only refuse, never admit. What cannot be read names nobody.
     */
    static java.util.Set<String> namedClients(HttpServletRequest request) {
        java.util.Set<String> ids = new java.util.LinkedHashSet<>();
        ClientAttestationAuthFilter.addNamed(ids, request.getParameter("client_id"));
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            try {
                String decoded = new String(java.util.Base64.getDecoder().decode(authorization.substring(6).trim()),
                        java.nio.charset.StandardCharsets.UTF_8);
                int colon = decoded.indexOf(':');
                String user = colon < 0 ? decoded : decoded.substring(0, colon);
                ClientAttestationAuthFilter.addNamed(ids, user);
                ClientAttestationAuthFilter.addNamed(ids, java.net.URLDecoder.decode(user, java.nio.charset.StandardCharsets.UTF_8));
            } catch (IllegalArgumentException e) {
                // Not Basic credentials, or a user that does not form-decode; what was read so far stays named.
            }
        }
        String assertion = request.getParameter("client_assertion");
        ClientAttestationAuthFilter.addNamed(ids, ClientAttestationAuthFilter.unverifiedClaim(assertion, "sub"));
        ClientAttestationAuthFilter.addNamed(ids, ClientAttestationAuthFilter.unverifiedClaim(assertion, "iss"));
        return ids;
    }

    private static void addNamed(java.util.Set<String> ids, String id) {
        if (id != null && !id.isBlank()) {
            ids.add(id);
        }
    }

    /** A JWT's {@code sub}, not verified, or null when it has none or cannot be read. */
    static String unverifiedSubject(String jwt) {
        return ClientAttestationAuthFilter.unverifiedClaim(jwt, "sub");
    }

    /** A JWT's string claim {@code name}, not verified, or null when it has none or cannot be read. */
    static String unverifiedClaim(String jwt, String name) {
        if (jwt == null || jwt.isBlank()) {
            return null;
        }
        try {
            Object value = com.pingidentity.ps.oidf.jose.JwtCodec.parseUnverifiedClaims(jwt).getClaimValue(name);
            return value instanceof String ? (String) value : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Why the verified attestation may not stand for the client the filter resolved its policy for, or null when it
     * may: the verified {@code sub} must be the one read before verifying.
     */
    static String subjectChanged(String claimed, String verified) {
        return verified != null && verified.equals(claimed) ? null
                : "the verified attestation's sub is not the client its policy was resolved for";
    }

    /** 401 {@code invalid_client} for a client whose attestation properties are refused, with the two events. */
    private void refusePolicy(HttpServletResponse response, AttestationPolicyException e) throws IOException {
        LOGGER.warn((Object) ("attest_jwt_client_auth: " + e.getMessage() + "; refused"));
        AttestationEvents.policyInvalid(AttestationEvents.FILTER, e);
        this.refuse(response, e.clientId(), 401, "invalid_client", AttestationPolicyException.CLIENT_DESCRIPTION);
    }

    /** 503 {@code temporarily_unavailable}: the client's policy could not be read, which is never "no policy". */
    private void refuseUnavailable(HttpServletResponse response, String clientId, AttestationPolicyResolver.Unavailable e)
            throws IOException {
        LOGGER.warn((Object) ("attest_jwt_client_auth: " + e.getMessage()), e.getCause());
        this.refuse(response, clientId, 503, ClientAttestationException.TEMPORARILY_UNAVAILABLE,
                "the client's attestation policy could not be read");
    }

    /** Answers {@code error} and records {@code attestation.client.refused} for {@code clientId}. */
    private void refuse(HttpServletResponse response, String clientId, int status, String error, String description)
            throws IOException {
        AttestationEvents.refused(AttestationEvents.FILTER, clientId, error);
        ClientAttestationAuthFilter.reject(response, status, error, description);
    }

    /** Each authorization_details entry's agent marker - the name the RAR processor reads (AGENT_DETAIL_KEY). */
    static final String AGENT_MARKER = "_agent_id";

    /** The harness's older name for the requested details: checked as sent, forwarded as sent. */
    static final String REQUESTED_ACCESS = "oidf_requested_access";

    /** The first of the details parameters the request carries more than once, or null. */
    static String repeatedParameter(HttpServletRequest request) {
        for (String name : List.of(GrantedDetails.PARAMETER, REQUESTED_ACCESS, "request", "request_uri")) {
            String[] values = request.getParameterValues(name);
            if (values != null && values.length > 1) {
                return name;
            }
        }
        return null;
    }

    private static boolean present(String value) {
        return value != null && !value.isBlank();
    }

    /**
     * The page a refusal at the authorization endpoint is answered with: the operator's
     * ({@link FederationRuntimeConfig#FEDERATION_ERROR_PAGE_ENV}), the one the front-channel registration filter shows,
     * or the built-in page when none is set or it cannot be read (said once, at ERROR).
     */
    FederationErrorPage errorPage() {
        FederationErrorPage page = this.errorPage;
        if (page == null) {
            String named = null;
            try {
                named = FederationRuntimeConfig.get().autoRegistration().errorPage();
                page = FederationErrorPage.from(named);
            } catch (IOException | RuntimeException e) {
                LOGGER.error((Object) ("attest_jwt_client_auth: the error page " + named + " cannot be read; the built-in page"
                        + " answers refusals at the authorization endpoint"), e);
                page = FederationErrorPage.builtIn();
            }
            this.errorPage = page;
        }
        return page;
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
     * The HTTP status a verification failure answers with: 400 for a challenge the client must fetch, for
     * {@code authorization_details} the token gate refuses and for a request object that cannot be held to the
     * attestation ({@code invalid_request_object}, RFC 9101 §6.3's code), 503 when the challenge or replay store could not
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
                || ClientAttestationException.INVALID_AUTHORIZATION_DETAILS.equals(e.error())
                || GrantedDetails.INVALID_REQUEST_OBJECT.equals(e.error())) {
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
     * ({@code client_secret} is dropped so a stale secret can neither help nor conflict), and
     * {@code authorization_details} is the granted details or absent - never what the client sent.
     */
    static final class BridgeAuthRequest extends HttpServletRequestWrapper {
        private final Map<String, String[]> parameters;

        BridgeAuthRequest(HttpServletRequest request, String clientId, String assertion, String grantedDetails) {
            super(request);
            Map<String, String[]> merged = new LinkedHashMap<>(request.getParameterMap());
            merged.remove("client_secret");
            merged.remove(GrantedDetails.PARAMETER);
            if (grantedDetails != null) {
                merged.put(GrantedDetails.PARAMETER, new String[]{grantedDetails});
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
