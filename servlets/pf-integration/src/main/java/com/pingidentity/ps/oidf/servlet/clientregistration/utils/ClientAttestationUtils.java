/*
 * PingFederate issuance-criteria hook for attestation-based client authentication.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.clientattestation.AttesterKeyResolver;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationException;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationResult;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.pf.FallbackAttesterKeyResolver;
import com.pingidentity.ps.oidf.pf.FederationAttesterKeyResolver;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.clientattestation.StaticAttesterKeyResolver;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.TrustControllerGateway;
import com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationConfiguration;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * Runtime entry point for attestation-based client authentication, designed to be called from a
 * PingFederate token-endpoint OAuth issuance-criteria OGNL expression, e.g.
 * {@code ClientAttestationUtils.validateClientAttestation(#this)}. It mirrors
 * {@link OIDFederationUtils#validateTrustChain(Object)}: it receives the criteria context map (with
 * {@code context.HttpRequest} and {@code context.ClientId}), verifies the
 * {@code OAuth-Client-Attestation} header together with either {@code OAuth-Client-Attestation-PoP}
 * (PoP-JWT mode) or {@code DPoP} (combined mode), and returns {@code true}/{@code false}.
 *
 * <p>Attester trust is resolved via the OpenID Federation trust chain (reusing {@link TrustChainValidator}).
 * Optional per-client tuning is read from {@code extproperties.*} (see {@link #buildConfig}).
 */
public final class ClientAttestationUtils {
    /**
     * Request attribute carrying an attestation this request has ALREADY verified, as plain types.
     *
     * <p>Written by whichever of the two enforcement points verifies first - the token-endpoint filter on
     * the webapp classloader, or this issuance criterion on the engine classloader - and read by the
     * other. A string key and a plain Map are the only things that cross that split.
     */
    public static final String VERIFIED_ATTESTATION_ATTRIBUTE =
            "com.pingidentity.ps.oidf.attestation.verified";

    private static final Log LOGGER = LogFactory.getLog(ClientAttestationUtils.class);
    private static final Object LOCK = new Object();
    private static volatile TrustControllerGateway gateway;
    private static volatile TrustChainValidator validator;
    private static volatile Boolean configuredIgnoreSslErrors;
    private static volatile String configuredTrustControllerHost;
    private static volatile String configuredTrustControllerBaseUrl;

    private ClientAttestationUtils() {
    }

    public static boolean validateClientAttestation(Object inObj) {
        // Deployment-wide settings, resolved once and identical for every reader. These used to be
        // statics on RegistrationConfiguration, mirrored from its constructor, so this call site
        // needed its own env fallback for the case where nothing had constructed one yet -- see
        // FederationRuntimeConfig.
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        return ClientAttestationUtils.validateClientAttestation(inObj, runtime.ignoreSslErrors(), runtime.trustControllerHost(),
                runtime.trustControllerBaseUrl());
    }

    /**
     * Thin fail-closed shell around {@link #validateClientAttestationInner}: a linkage error in the
     * body's class graph surfaces at the inner method's call site, so this shell can log it — inside a
     * single method it would escape to OGNL as an opaque "Method failed" with no trace.
     *
     * @param trustControllerHost the trust controller's bare federation identity (used for
     *     {@code knownTrustAnchor} matching)
     */
    public static boolean validateClientAttestation(Object inObj, Boolean ignoreSslErrors, String trustControllerHost) {
        return ClientAttestationUtils.validateClientAttestation(inObj, ignoreSslErrors, trustControllerHost, trustControllerHost);
    }

    /**
     * @param trustControllerBaseUrl the HTTP base actually used to reach the trust controller's
     *     federation endpoints — distinct from {@code trustControllerHost} when that identity string
     *     isn't itself a reachable URL (e.g. PF acting as its own anchor; see
     *     {@code HttpTrustControllerGateway}'s {@code selfIssuer} javadoc).
     */
    public static boolean validateClientAttestation(Object inObj, Boolean ignoreSslErrors, String trustControllerHost, String trustControllerBaseUrl) {
        try {
            return ClientAttestationUtils.validateClientAttestationInner(inObj, ignoreSslErrors, trustControllerHost, trustControllerBaseUrl);
        } catch (Throwable t) {
            LOGGER.error((Object) "Attestation-based client authentication failed with a non-Exception throwable", t);
            return false;
        }
    }

    private static boolean validateClientAttestationInner(Object inObj, Boolean ignoreSslErrors, String trustControllerHost, String trustControllerBaseUrl) {
        try {
            if (!(inObj instanceof Map)) {
                LOGGER.error((Object) ("In parameters not instance of Map. " + (inObj == null ? "null" : inObj.getClass().getName())));
                return false;
            }
            Map inParameters = (Map) inObj;
            HttpServletRequest request = (HttpServletRequest) ((AttributeValue) inParameters.get("context.HttpRequest")).getObjectValue();
            String requestedClientId = ClientAttestationUtils.attributeValue(inParameters, "context.ClientId");
            // If the token-endpoint filter already verified this request, reuse its result rather than
            // verifying again. Both paths call ClientAttestationVerifier.verify(), and verify() CONSUMES
            // the challenge and burns the PoP jti - so two verifications of one request destroy each
            // other. Latent today only because challenges default off and the two classloaders get
            // separate in-memory stores; point them at one Redis and the second verify reports "Replay
            // detected" and nobody gets a token. Verifying once removes the conflict, and is what makes
            // challenges usable at all.
            //
            // The attribute is server-side and plain-typed - a client cannot set it, and a Map of strings
            // is what crosses the servlet/engine classloader split. Absent means the filter did not
            // verify (a deliberately filter-less deployment), so fall through and verify here.
            Object alreadyVerified = request.getAttribute(VERIFIED_ATTESTATION_ATTRIBUTE);
            if (alreadyVerified instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> verified = (Map<String, Object>) alreadyVerified;
                request.setAttribute("com.pingidentity.ps.oidf.rar.attestation_context", verified);
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info((Object) ("Attestation-based client authentication satisfied by the "
                            + "token-endpoint filter's verification for client_id=" + verified.get("client_id")));
                }
                return true;
            }

            String opIssuer = OAuthIssuerUtils.getInstance().getIssuerValue(request);

            String attestation = ClientAttestationUtils.singleHeader(request, "OAuth-Client-Attestation");
            String pop = ClientAttestationUtils.singleHeader(request, "OAuth-Client-Attestation-PoP");
            String dpop = ClientAttestationUtils.singleHeader(request, "DPoP");
            String requestUri = request.getRequestURL() == null ? null : request.getRequestURL().toString();

            AttesterKeyResolver resolver = ClientAttestationUtils.resolveAttesterTrust(
                    ignoreSslErrors, trustControllerHost, trustControllerBaseUrl, opIssuer,
                    ClientAttestationUtils.trustChainEntryMaxAge(inParameters));
            ClientAttestationConfig config = ClientAttestationUtils.buildConfig(inParameters, opIssuer, requestUri);
            ClientAttestationVerifier verifier = new ClientAttestationVerifier(resolver, config, AttestationSupport.replayCache(), AttestationSupport.challengeService());

            // Prefer the standard RFC 9396 parameter, but PingFederate's AS pre-validates
            // 'authorization_details' against the client's configured RAR types and rejects
            // unregistered types before this issuance criterion runs. Fall back to a dedicated
            // parameter so the attestation-bound entitlement check works without full PF RAR config.
            String authorizationDetails = request.getParameter("authorization_details");
            if (authorizationDetails == null || authorizationDetails.isBlank()) {
                authorizationDetails = request.getParameter("oidf_requested_access");
            }
            ClientAttestationResult result = verifier.verify(attestation, pop, dpop, request.getMethod(), requestUri, requestedClientId, authorizationDetails);
            if (!result.grantedAuthorizationDetails().isEmpty()) {
                // Stash the granted RFC 9396 authorization_details so an access-token-manager attribute
                // mapping can surface it into the issued token (OGNL reads the HttpRequest attribute).
                request.setAttribute("oidf.authorization_details", authorizationDetails);
            }
            // Publish the verified attestation context for the RAR -> PingAuthorize AuthorizationDetailProcessor
            // (pf-rar-paz-plugin: AttestationSubject.REQUEST_ATTRIBUTE). Decoupled by a shared string key and a
            // plain Map, so neither module depends on the other.
            Map<String, Object> context = ClientAttestationUtils.attestationContext(result);
            request.setAttribute("com.pingidentity.ps.oidf.rar.attestation_context", context);
            request.setAttribute(VERIFIED_ATTESTATION_ATTRIBUTE, context);
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info((Object) ("Attestation-based client authentication succeeded for client_id=" + result.clientId()
                        + " mode=" + result.mode() + " attester=" + result.attesterIssuer()
                        + " granted_authorization_details=" + result.grantedAuthorizationDetails().size()));
            }
            return true;
        } catch (ClientAttestationException e) {
            LOGGER.info((Object) ("Attestation-based client authentication failed [" + e.error() + "]: " + e.getMessage()));
            return false;
        } catch (Exception e) {
            LOGGER.info((Object) "Attestation-based client authentication failed", (Throwable) e);
            return false;
        } catch (Throwable t) {
            // An Error escaping here surfaces as an opaque OGNL "Method failed" with no trace; this
            // boundary must stay fail-closed AND diagnosable (e.g. a linkage error in the module jar).
            LOGGER.error((Object) "Attestation-based client authentication failed with a non-Exception throwable",
                    t);
            return false;
        }
    }

    /**
     * Builds the attestation context handed to the RAR {@code AuthorizationDetailProcessor}
     * (pf-rar-paz-plugin): the authenticated subject/{@code client_id}, the attested RFC 9396 entitlement
     * ceiling, and the confirmed instance-key thumbprint. Consumed via a request attribute so the RAR
     * decision can be bounded by what the attester actually vouched.
     */
    public static Map<String, Object> attestationContext(ClientAttestationResult result) {
        Map<String, Object> ctx = new java.util.LinkedHashMap<>();
        ctx.put("sub", result.clientId());
        ctx.put("client_id", result.clientId());
        // The running instance's identity (Phase 2.6), kept as its own key rather than folded into "sub"
        // or "client_id" — those two name the registered client/agent TYPE and must stay unaffected by
        // whether an agent_id happens to be present at all.
        if (result.agentId() != null && !result.agentId().isBlank()) {
            ctx.put("agent_id", result.agentId());
        }
        // The attester's own issuer. agent_id and client_id are unique only WITHIN an issuing
        // authority, so the acting party's full identity is the pair - which is why delegationActChain
        // emits both. Published here because the OGNL contract names "iss", and reading it from the
        // header instead would mean trusting an unverified issuer to say who vouched for the client.
        if (result.attesterIssuer() != null && !result.attesterIssuer().isBlank()) {
            ctx.put("iss", result.attesterIssuer());
        }
        ctx.put("entitlement", result.entitledAuthorizationDetails());
        // The workload behind the client — SPIFFE ID, attestor and any introspected selectors. Surfaced
        // flat as well so an access-token attribute mapping (OGNL) can name the workload in the token.
        Map<String, Object> workload = result.workload();
        if (workload != null && !workload.isEmpty()) {
            ctx.put("workload", workload);
            Object spiffeId = workload.get("spiffe_id");
            if (spiffeId != null) {
                ctx.put("spiffe_id", spiffeId);
            }
            Object attestedBy = workload.get("attested_by");
            if (attestedBy != null) {
                ctx.put("attested_by", attestedBy);
            }
        }
        try {
            ctx.put("cnf_thumbprint", Jwks.thumbprint(result.cnfJwk()));
        } catch (Exception e) {
            LOGGER.info((Object) "could not compute cnf thumbprint for attestation context", (Throwable) e);
        }
        return ctx;
    }

    /**
     * Shared entry point for the token-endpoint auth filter: the same attester trust resolution this
     * class uses from OGNL (mock-attester file in dev, OpenID Federation trust chain otherwise), with
     * the same instance caching. Kept here so the filter and the issuance criterion cannot drift.
     */
    public static AttesterKeyResolver attesterResolver(String opIssuer) {
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        return ClientAttestationUtils.resolveAttesterTrust(runtime.ignoreSslErrors(),
                runtime.trustControllerHost(), runtime.trustControllerBaseUrl(), opIssuer, -1L);
    }

    /**
     * Resolves attester trust for one request: if {@code oidf.mock.attesters} is configured, static
     * entries resolve exactly as before and anything NOT in that file falls through to real OpenID
     * Federation trust-chain validation (see {@link FallbackAttesterKeyResolver}) — lets a static
     * legacy-demo trust list and newly-onboarded federation-backed attesters coexist on one PF
     * instance. With no static file configured, this is pure federation, as before.
     */
    private static AttesterKeyResolver resolveAttesterTrust(boolean ignoreSslErrors, String trustControllerHost,
            String trustControllerBaseUrl, String opIssuer, long trustChainEntryMaxAge) {
        StaticAttesterKeyResolver staticResolver = ClientAttestationUtils.mockAttesterResolver();
        TrustChainValidator chainValidator = ClientAttestationUtils.getValidator(ignoreSslErrors, trustControllerHost, trustControllerBaseUrl);
        FederationAttesterKeyResolver federationResolver = new FederationAttesterKeyResolver(chainValidator, opIssuer, trustChainEntryMaxAge);
        return staticResolver == null ? federationResolver : new FallbackAttesterKeyResolver(staticResolver, federationResolver);
    }

    /**
     * Default verification policy for the token-endpoint auth filter: PoP audience = OP issuer or the
     * request URL, method POST. The filter has no issuance-criteria context, so the per-client
     * {@code extproperties.*} tuning read by {@link #buildConfig} does not apply here; the OGNL issuance
     * criterion still enforces it on the same request.
     */
    public static ClientAttestationConfig defaultConfig(String opIssuer, String requestUri) {
        return ClientAttestationConfig.builder()
                .addAcceptedAudience(opIssuer)
                .addAcceptedAudience(requestUri)
                .expectedHtm("POST")
                .build();
    }

    private static volatile StaticAttesterKeyResolver mockResolver;
    private static volatile boolean mockResolverLoaded;

    /**
     * DEV/DEMO hook: if the {@code oidf.mock.attesters} system property points to a readable
     * mock-attester JWKS file, returns a {@link StaticAttesterKeyResolver} that trusts those keys
     * directly (no federation trust chain). Returns {@code null} in normal operation.
     */
    private static StaticAttesterKeyResolver mockAttesterResolver() {
        if (mockResolverLoaded) {
            return mockResolver;
        }
        synchronized (LOCK) {
            if (!mockResolverLoaded) {
                String path = System.getProperty("oidf.mock.attesters");
                if (path != null && !path.isBlank() && java.nio.file.Files.isReadable(java.nio.file.Path.of(path))) {
                    try {
                        mockResolver = StaticAttesterKeyResolver.fromFile(java.nio.file.Path.of(path));
                        LOGGER.warn((Object) ("DEV MODE: trusting static mock attester keys from '" + path
                                + "' — OpenID Federation trust-chain validation is DISABLED."));
                    } catch (Exception e) {
                        LOGGER.error((Object) ("Failed to load oidf.mock.attesters file '" + path + "'"), (Throwable) e);
                    }
                }
                mockResolverLoaded = true;
            }
        }
        return mockResolver;
    }

    /**
     * Test-only: clears the memoised {@code oidf.mock.attesters} resolution. {@link #mockAttesterResolver}
     * caches for the life of the JVM, which is right for a running deployment but means a test that sets
     * the property after another test has already forced the cache (with the property unset, or set to a
     * different file) would otherwise see a stale answer regardless of test order. Accessed via
     * reflection, the same convention as {@code BridgeSigners.resetForTest}.
     */
    private static void resetMockAttesterResolverForTest() {
        synchronized (LOCK) {
            mockResolver = null;
            mockResolverLoaded = false;
        }
    }

    private static TrustChainValidator getValidator(boolean ignoreSslErrors, String trustControllerHost, String trustControllerBaseUrl) {
        String effectiveBaseUrl = trustControllerBaseUrl == null || trustControllerBaseUrl.isBlank() ? trustControllerHost : trustControllerBaseUrl;
        TrustChainValidator local = validator;
        if (local != null) {
            ClientAttestationUtils.validateConfiguration(ignoreSslErrors, trustControllerHost, effectiveBaseUrl);
            return local;
        }
        synchronized (LOCK) {
            if (validator == null) {
                // trustControllerHost is the bare identity used for knownTrustAnchor matching;
                // effectiveBaseUrl is the (possibly different) HTTP base actually needed to reach it —
                // see HttpTrustControllerGateway's selfIssuer javadoc for why these can diverge.
                gateway = new HttpTrustControllerGateway(new JdkHttpGetClient(ignoreSslErrors, OutboundUrlPolicy.fromEnvironment()
                        .trusting(effectiveBaseUrl, trustControllerHost)), effectiveBaseUrl, trustControllerHost);
                configuredIgnoreSslErrors = ignoreSslErrors;
                configuredTrustControllerHost = trustControllerHost;
                configuredTrustControllerBaseUrl = effectiveBaseUrl;
                validator = new TrustChainValidator(gateway, trustControllerHost);
            } else {
                ClientAttestationUtils.validateConfiguration(ignoreSslErrors, trustControllerHost, effectiveBaseUrl);
            }
            return validator;
        }
    }

    private static void validateConfiguration(boolean ignoreSslErrors, String trustControllerHost, String trustControllerBaseUrl) {
        if (!java.util.Objects.equals(configuredIgnoreSslErrors, ignoreSslErrors)
                || !java.util.Objects.equals(configuredTrustControllerHost, trustControllerHost)
                || !java.util.Objects.equals(configuredTrustControllerBaseUrl, trustControllerBaseUrl)) {
            throw new IllegalStateException("TrustControllerGateway already initialized with different configuration");
        }
    }

    /**
     * Builds the verification policy, defaulting the PoP audience to the OP issuer and the request URL,
     * and reading optional {@code extproperties.*} overrides: {@code attestation_pop_max_age},
     * {@code attestation_dpop_max_age}, {@code attestation_clock_skew},
     * {@code attestation_challenge_required}, {@code attestation_expected_htu},
     * {@code attestation_accepted_algs}, {@code attestation_pop_algs}, {@code attestation_dpop_algs}.
     */
    private static ClientAttestationConfig buildConfig(Map inParameters, String opIssuer, String requestUri) {
        ClientAttestationConfig.Builder b = ClientAttestationConfig.builder()
                .addAcceptedAudience(opIssuer)
                .addAcceptedAudience(requestUri)
                .expectedHtm("POST");

        Long popMaxAge = ClientAttestationUtils.longProp(inParameters, "extproperties.attestation_pop_max_age");
        if (popMaxAge != null) {
            b.popMaxAgeSeconds(popMaxAge);
        }
        Long dpopMaxAge = ClientAttestationUtils.longProp(inParameters, "extproperties.attestation_dpop_max_age");
        if (dpopMaxAge != null) {
            b.dpopMaxAgeSeconds(dpopMaxAge);
        }
        Long clockSkew = ClientAttestationUtils.longProp(inParameters, "extproperties.attestation_clock_skew");
        if (clockSkew != null) {
            b.allowedClockSkewSeconds(clockSkew.intValue());
        }
        Boolean challengeRequired = ClientAttestationUtils.boolProp(inParameters, "extproperties.attestation_challenge_required");
        if (challengeRequired != null) {
            b.challengeRequired(challengeRequired);
        }
        String expectedHtu = ClientAttestationUtils.stringProp(inParameters, "extproperties.attestation_expected_htu");
        if (expectedHtu != null) {
            b.expectedHtu(expectedHtu);
        }
        Set<String> attAlgs = ClientAttestationUtils.setProp(inParameters, "extproperties.attestation_accepted_algs");
        if (attAlgs != null) {
            b.attestationAlgorithms(attAlgs);
        }
        Set<String> popAlgs = ClientAttestationUtils.setProp(inParameters, "extproperties.attestation_pop_algs");
        if (popAlgs != null) {
            b.popAlgorithms(popAlgs);
        }
        Set<String> dpopAlgs = ClientAttestationUtils.setProp(inParameters, "extproperties.attestation_dpop_algs");
        if (dpopAlgs != null) {
            b.dpopAlgorithms(dpopAlgs);
        }
        // Required-claims policy (AS side): top-level claims this AS requires the attestation to carry.
        // Per-client via extproperties.attestation_required_claims, else a global default from the
        // oidf.attestation.required.claims system property (comma-separated; e.g. "workload").
        Set<String> requiredClaims = ClientAttestationUtils.setProp(inParameters, "extproperties.attestation_required_claims");
        if (requiredClaims == null) {
            requiredClaims = ClientAttestationUtils.systemPropertySet("oidf.attestation.required.claims");
        }
        if (requiredClaims != null) {
            b.requiredDisclosedClaims(requiredClaims);
        }
        return b.build();
    }

    private static Set<String> systemPropertySet(String property) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            return null;
        }
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String token : value.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result.isEmpty() ? null : result;
    }

    private static long trustChainEntryMaxAge(Map inParameters) {
        Long value = ClientAttestationUtils.longProp(inParameters, "extproperties.trust_chain_request_max_age");
        return value != null ? value : -1L;
    }

    /**
     * OGNL helper for access-token attribute mapping: reads one claim out of the <em>verified</em>
     * Client Attestation so an issued JWT access token can name the attested workload —
     * {@code spiffe_id}, {@code attested_by}, {@code client_id}, {@code agent_id} (the attester-minted
     * per-instance identifier, Phase 2.6), {@code iss} (the attester's own issuer), or
     * {@code trust_domain}.
     *
     * <p>The value comes from the context the token-endpoint filter published after verifying
     * ({@link #VERIFIED_ATTESTATION_ATTRIBUTE}) — never from decoding the presented header. Those are
     * not the same thing: the header is attacker-supplied bytes until something checks the attester's
     * signature over them.
     *
     * <p>This used to base64-decode the header directly, justified by the sibling
     * {@code validateClientAttestation} issuance criterion rejecting a bad attestation before any token
     * issued. That reasoning is sound only where the criterion is actually on the mapping, and only for
     * mappings PF gates that way — it is a property of a deployment's configuration, not of this code.
     * Reading the verified context makes it a property of the code: unverified input has no path into a
     * token, whatever the configuration.
     *
     * <p><b>No fallback, deliberately.</b> Absent context ⇒ empty string ⇒ omitted attribute. Verifying
     * here instead would re-consume the challenge and burn the PoP {@code jti} — the exact
     * double-verification removed in {@link #validateClientAttestation}. A deployment running without
     * the filter therefore issues tokens without these claims rather than with unverified ones, which is
     * the safe direction of that trade; the log line below says so, because silently empty claims are
     * otherwise an unpleasant thing to diagnose.
     */
    public static String attestationClaim(Object inObj, String claimName) {
        try {
            if (!(inObj instanceof Map)) {
                return "";
            }
            HttpServletRequest request =
                    (HttpServletRequest) ((AttributeValue) ((Map) inObj).get("context.HttpRequest")).getObjectValue();
            Object verified = request.getAttribute(VERIFIED_ATTESTATION_ATTRIBUTE);
            if (!(verified instanceof Map)) {
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info((Object) ("no verified attestation published on this request, so '" + claimName
                            + "' is omitted from the token. The token-endpoint filter publishes it once it "
                            + "has verified; a deployment running without that filter cannot map "
                            + "attestation claims, and unverified header content is not a substitute."));
                }
                return "";
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> context = (Map<String, Object>) verified;
            // Flat first (sub/client_id/agent_id/iss, and the workload values surfaced flat by
            // attestationContext), then the nested workload map for anything else it carries.
            Object value = context.get(claimName);
            if (value == null) {
                Object workloadRaw = context.get("workload");
                if (workloadRaw instanceof Map) {
                    value = ((Map) workloadRaw).get(claimName);
                }
            }
            return scalarClaim(value);
        } catch (Exception e) {
            LOGGER.info((Object) ("could not read attestation claim '" + claimName + "' for token mapping"), e);
            return "";
        }
    }

    /**
     * A claim value fit for a token attribute: strings, numbers and booleans only. The verified context
     * also carries structured entries — the entitlement list, the workload map itself — whose Java
     * {@code toString} would be meaningless in a token, so those map to nothing rather than to junk.
     */
    private static String scalarClaim(Object value) {
        if (value instanceof String) {
            return (String) value;
        }
        if (value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        return "";
    }

    /**
     * OGNL helper for token-exchange access-token mappings: builds the RFC 8693 delegation chain
     * {@code {"sub": <acting party>, "iss": <attester issuer>, "act": <subject token's chain>}} as a
     * JSON string claim.
     *
     * <p>Needed because PF's expression validator exposes ONLY context attributes
     * ({@code context.HttpRequest}, {@code context.ClientId}) to a mapping's OGNL — token-exchange
     * processor-policy contract attributes are not referable, so the prior chain cannot be nested
     * from a policy attribute. Instead this reads the {@code subject_token} request parameter and
     * decodes its {@code act} claim without verifying the signature. That is safe for the same
     * reason as {@link #attestationClaim}: the subject token's validity is separately enforced by
     * the token-exchange processor before any token is issued, so an unverified read can never
     * produce a token for a subject token PF rejected. The {@code act} claim is emitted (and
     * consumed) as a JSON string; a string-encoded prior chain is re-parsed so it nests as an
     * object rather than double-escaped text.
     *
     * <p>Phase 2.8: the acting party's {@code sub} is the attester-minted {@code agent_id} when the
     * exchanging client's presented attestation carries one — naming the specific instance, not just its
     * registered client/agent type — falling back to {@code client_id} otherwise (the fallback lives
     * here, in Java, rather than as an OGNL ternary at the Terraform call site, which stays a plain
     * {@code delegationActChain(#this)} invocation unchanged by this addition). {@code iss} is the
     * attester's own issuer, included because {@code agent_id}/{@code client_id} are only unique within
     * their issuing authority — the full identity of the acting party is the pair. Both reads go through
     * {@link #attestationClaim} and therefore come from the VERIFIED attestation context, not from
     * decoding the presented header.
     *
     * <p>The {@code act} chain below is the one unverified read left here, and it is a different claim
     * with a different justification: it is the caller's own {@code subject_token}, which the
     * token-exchange processor validates before any token is issued, so a rejected subject token cannot
     * produce a token carrying its chain. That is a property of the grant type rather than of a
     * configurable issuance criterion — which is what made the old reasoning for {@code attestationClaim}
     * weaker than it looked.
     */
    @SuppressWarnings("unchecked")
    public static String delegationActChain(Object inObj) {
        try {
            if (!(inObj instanceof Map)) {
                return "";
            }
            Map<String, Object> map = (Map<String, Object>) inObj;
            Object clientIdRaw = map.get("context.ClientId");
            String clientId = clientIdRaw instanceof AttributeValue
                    ? ((AttributeValue) clientIdRaw).getValue() : null;
            if (clientId == null || clientId.isBlank()) {
                return "";
            }
            java.util.LinkedHashMap<String, Object> chain = new java.util.LinkedHashMap<>();
            String agentId = ClientAttestationUtils.attestationClaim(map, "agent_id");
            chain.put("sub", ClientAttestationUtils.actingPartySub(agentId, clientId));
            String attesterIssuer = ClientAttestationUtils.attestationClaim(map, "iss");
            if (attesterIssuer != null && !attesterIssuer.isBlank()) {
                chain.put("iss", attesterIssuer);
            }
            HttpServletRequest request =
                    (HttpServletRequest) ((AttributeValue) map.get("context.HttpRequest")).getObjectValue();
            String subjectToken = request.getParameter("subject_token");
            String[] parts = subjectToken == null ? new String[0] : subjectToken.split("\\.");
            if (parts.length >= 2) {
                String json = new String(java.util.Base64.getUrlDecoder().decode(parts[1]),
                        java.nio.charset.StandardCharsets.UTF_8);
                Object priorAct = org.jose4j.json.JsonUtil.parseJson(json).get("act");
                if (priorAct instanceof String && !((String) priorAct).isBlank()) {
                    priorAct = org.jose4j.json.JsonUtil.parseJson((String) priorAct);
                }
                if (priorAct instanceof Map) {
                    chain.put("act", priorAct);
                }
            }
            return org.jose4j.json.JsonUtil.toJson(chain);
        } catch (Exception e) {
            LOGGER.info((Object) "could not build delegation act chain for token mapping", e);
            return "";
        }
    }

    /**
     * The RFC 8693 acting party's {@code sub} (Phase 2.8): the attester-minted {@code agent_id} when
     * present and non-blank, naming the specific instance rather than just its registered client/agent
     * type; {@code clientId} otherwise. Extracted as a pure function (no OGNL/servlet types) specifically
     * so this fallback decision is directly unit-testable without mocking PF's request/attribute types —
     * {@link #delegationActChain} itself has no other test coverage precedent in this class.
     */
    static String actingPartySub(String agentId, String clientId) {
        return agentId != null && !agentId.isBlank() ? agentId : clientId;
    }

    private static String singleHeader(HttpServletRequest request, String name) {
        Enumeration<String> values = request.getHeaders(name);
        if (values == null) {
            return null;
        }
        String first = null;
        int count = 0;
        while (values.hasMoreElements()) {
            String v = values.nextElement();
            if (count == 0) {
                first = v;
            }
            ++count;
        }
        if (count == 0) {
            return null;
        }
        if (count > 1) {
            throw new IllegalArgumentException("Multiple '" + name + "' headers present; exactly one is required");
        }
        return first;
    }

    private static String attributeValue(Map inParameters, String key) {
        Object value = inParameters.get(key);
        if (value instanceof AttributeValue) {
            return ((AttributeValue) value).getValue();
        }
        return null;
    }

    private static String stringProp(Map inParameters, String key) {
        if (!inParameters.containsKey(key)) {
            return null;
        }
        // PF's issuance-criteria context maps the extended-property key even when the client has no value:
        // unwrap an AttributeValue, and treat Java null / the literal "null" (from String.valueOf(null)) /
        // blank as "not set" so callers fall back to defaults instead of a bogus "null" token.
        Object raw = inParameters.get(key);
        if (raw instanceof AttributeValue) {
            raw = ((AttributeValue) raw).getValue();
        }
        if (raw == null) {
            return null;
        }
        String value = String.valueOf(raw).trim();
        return value.isEmpty() || "null".equalsIgnoreCase(value) ? null : value;
    }

    private static Long longProp(Map inParameters, String key) {
        String value = ClientAttestationUtils.stringProp(inParameters, key);
        if (value == null) {
            return null;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            LOGGER.warn((Object) (key + " is not an integer (\"" + value + "\"); ignoring"));
            return null;
        }
    }

    private static Boolean boolProp(Map inParameters, String key) {
        String value = ClientAttestationUtils.stringProp(inParameters, key);
        return value == null ? null : Boolean.valueOf(Boolean.parseBoolean(value));
    }

    private static Set<String> setProp(Map inParameters, String key) {
        String value = ClientAttestationUtils.stringProp(inParameters, key);
        if (value == null) {
            return null;
        }
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String token : value.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result.isEmpty() ? null : result;
    }
}
