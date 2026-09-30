/*
 * PingFederate issuance-criteria hook for attestation-based client authentication.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.platform.pf.component.CriterionGate;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.platform.pf.internals.PfInternals;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
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
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.TrustControllerGateway;
import com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationConfiguration;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

    /**
     * Request attribute carrying the same verified context to the RAR → PingAuthorize
     * {@code AuthorizationDetailProcessor}.
     *
     * <p>This value is a contract with {@code plugins/rar-paz-plugin}, which reads it as
     * {@code AttestationSubject.REQUEST_ATTRIBUTE}. The two modules deliberately do not depend on each
     * other — the plugin loads on a per-plugin isolated classloader and shades its own jackson — so the
     * key is a string literal on both sides and cannot be a shared constant. {@code RarContextKeyTest}
     * pins the two literals equal; if you change this, that test tells you what else to change.
     */
    public static final String RAR_ATTESTATION_CONTEXT_ATTRIBUTE =
            "com.pingidentity.ps.oidf.rar.attestation_context";

    /**
     * The attestation context's member carrying {@link AttestationPolicyResolver#fingerprint} of the policy the
     * attestation was verified under. The criterion, reusing the filter's verification, computes it again from the
     * policy it resolves for the client and refuses a context whose member differs or is absent (plan item S4c).
     */
    public static final String POLICY_FINGERPRINT_KEY = "attestation_policy_fingerprint";

    /**
     * The attestation context's member carrying the {@code sub} of a token-exchange {@code subject_token} this
     * PingFederate signed ({@link SubjectTokenVerifier}): the RAR plugin's {@code AttestationSubject.VERIFIED_SUBJECT_TOKEN_KEY},
     * pinned equal by {@code RarContextKeyTest} (F-0074). Absent when the request is not a token exchange or its subject
     * token does not verify.
     */
    public static final String VERIFIED_SUBJECT_TOKEN_KEY = "verified_subject_token_sub";

    /** RFC 8693 §2.1's grant type. */
    static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

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
        // S9b: false, never a throw, while ATTESTATION_AUTH is not serving here (CriterionGate says how the engine knows).
        if (!CriterionGate.serves(Startup.ATTESTATION_AUTH, "validateClientAttestation")) {
            return false;
        }
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
        // S9b: false, never a throw, while ATTESTATION_AUTH is not serving here (CriterionGate says how the engine knows).
        if (!CriterionGate.serves(Startup.ATTESTATION_AUTH, "validateClientAttestation")) {
            return false;
        }
        return ClientAttestationUtils.validateClientAttestation(inObj, ignoreSslErrors, trustControllerHost, trustControllerHost);
    }

    /**
     * @param trustControllerBaseUrl the HTTP base actually used to reach the trust controller's
     *     federation endpoints — distinct from {@code trustControllerHost} when that identity string
     *     isn't itself a reachable URL (e.g. PF acting as its own anchor; see
     *     {@code HttpTrustControllerGateway}'s {@code selfIssuer} javadoc).
     */
    public static boolean validateClientAttestation(Object inObj, Boolean ignoreSslErrors, String trustControllerHost, String trustControllerBaseUrl) {
        // S9b: false, never a throw, while ATTESTATION_AUTH is not serving here (CriterionGate says how the engine knows).
        if (!CriterionGate.serves(Startup.ATTESTATION_AUTH, "validateClientAttestation")) {
            return false;
        }
        return ClientAttestationUtils.validateClientAttestation(inObj, ignoreSslErrors, trustControllerHost, trustControllerBaseUrl,
                ClientAttestationUtils::pingFederateIssuer);
    }

    /**
     * The same criterion with the OP issuer resolved by {@code issuerOf}. {@code OAuthIssuerUtils.getInstance()}
     * reaches into PingFederate's HiveMind registry and cannot run outside a booted server, so this is the seam
     * that lets a test drive the criterion's own containment check - as {@code ClientAttestationAuthFilter}'s
     * package-private constructor does for the filter.
     */
    static boolean validateClientAttestation(Object inObj, Boolean ignoreSslErrors, String trustControllerHost,
            String trustControllerBaseUrl, java.util.function.Function<HttpServletRequest, String> issuerOf) {
        try {
            return ClientAttestationUtils.validateClientAttestationInner(inObj, ignoreSslErrors, trustControllerHost, trustControllerBaseUrl,
                    issuerOf, ClientAttestationUtils::configuredTokenEndpointBaseUrl);
        } catch (Throwable t) {
            LOGGER.error((Object) "Attestation-based client authentication failed with a non-Exception throwable", t);
            return false;
        }
    }

    private static String pingFederateIssuer(HttpServletRequest request) {
        return PfInternals.issuer(request);
    }

    /**
     * Test seam: the criterion with PingFederate's issuer and token endpoint base URL supplied, as
     * {@code ClientAttestationAuthFilter} takes them, because {@code OAuthIssuerUtils}' static initialiser reaches
     * into PingFederate's registry and cannot run outside a booted server.
     */
    static boolean validateClientAttestationInner(Object inObj, Boolean ignoreSslErrors, String trustControllerHost,
            String trustControllerBaseUrl, java.util.function.Function<HttpServletRequest, String> issuerOf,
            java.util.function.Supplier<String> tokenEndpointBaseUrl) {
        return ClientAttestationUtils.validateClientAttestationInner(inObj, ignoreSslErrors, trustControllerHost, trustControllerBaseUrl,
                issuerOf, tokenEndpointBaseUrl, AttestationPolicyResolver.shared(), SubjectTokenVerifier.pingFederate());
    }

    /**
     * Test seam: the criterion with the client policy resolver and the subject token verifier supplied as well, since
     * both reach PingFederate's client manager and signing keys in production.
     */
    static boolean validateClientAttestationInner(Object inObj, Boolean ignoreSslErrors, String trustControllerHost,
            String trustControllerBaseUrl, java.util.function.Function<HttpServletRequest, String> issuerOf,
            java.util.function.Supplier<String> tokenEndpointBaseUrl, AttestationPolicyResolver resolver,
            SubjectTokenVerifier subjectTokens) {
        String requestedClientId = null;
        try {
            if (!(inObj instanceof Map)) {
                LOGGER.error((Object) ("In parameters not instance of Map. " + (inObj == null ? "null" : inObj.getClass().getName())));
                return false;
            }
            Map inParameters = (Map) inObj;
            HttpServletRequest request = (HttpServletRequest) ((AttributeValue) inParameters.get("context.HttpRequest")).getObjectValue();
            requestedClientId = ClientAttestationUtils.attributeValue(inParameters, "context.ClientId");
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
                // The filter verified under the policy it resolved for the client. This copy resolves the client's
                // policy again and refuses a verification made under another one - a filter that ignored the client's
                // properties, as every filter before 0.6.0 did (F-0009), or a context for another client.
                ClientAttestationConfig policy = ClientAttestationUtils.effectivePolicy(resolver, requestedClientId,
                        issuerOf.apply(request), tokenEndpointBaseUrl.get(), ClientAttestationUtils.endpointPath(request));
                String mismatch = ClientAttestationUtils.reusedVerificationProblem(verified, requestedClientId,
                        AttestationPolicyResolver.fingerprint(policy));
                if (mismatch != null) {
                    LOGGER.info((Object) ("Attestation-based client authentication refused: " + mismatch));
                    AttestationEvents.refused(AttestationEvents.CRITERION, requestedClientId, ClientAttestationException.INVALID_CLIENT);
                    return false;
                }
                request.setAttribute(RAR_ATTESTATION_CONTEXT_ATTRIBUTE, verified);
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info((Object) ("Attestation-based client authentication satisfied by the "
                            + "token-endpoint filter's verification for client_id=" + verified.get("client_id")));
                }
                AttestationEvents.verified(AttestationEvents.CRITERION, requestedClientId, ClientAttestationUtils.string(verified.get("iss")));
                return true;
            }

            ClientAttestationResult result = ClientAttestationUtils.verifyAtTheCriterion(inParameters, request, requestedClientId,
                    issuerOf, ignoreSslErrors, trustControllerHost, trustControllerBaseUrl, tokenEndpointBaseUrl, resolver, subjectTokens);
            if (result == null) {
                AttestationEvents.refused(AttestationEvents.CRITERION, requestedClientId, "server_error");
                return false;
            }
            AttestationEvents.verified(AttestationEvents.CRITERION, requestedClientId, result.attesterIssuer());
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info((Object) ("Attestation-based client authentication succeeded for client_id=" + result.clientId()
                        + " mode=" + result.mode() + " attester=" + result.attesterIssuer()
                        + " granted_authorization_details=" + result.grantedAuthorizationDetails().size()));
            }
            return true;
        } catch (ClientAttestationException e) {
            // PingFederate answers a false criterion with the Error Result configured on it (400 invalid_grant),
            // not with this error: the criterion can refuse the token, not choose the refusal's code. The token
            // endpoint filter, where it runs, answers first with the error itself.
            LOGGER.info((Object) ("Attestation-based client authentication failed [" + e.error() + "]: " + e.getMessage()
                    + ClientAttestationUtils.refusalDetail(e)));
            AttestationEvents.refused(AttestationEvents.CRITERION, requestedClientId, e.error());
            return false;
        } catch (AttestationPolicyException e) {
            LOGGER.warn((Object) ("Attestation-based client authentication refused: " + e.getMessage()));
            AttestationEvents.policyInvalid(AttestationEvents.CRITERION, e);
            AttestationEvents.refused(AttestationEvents.CRITERION, requestedClientId, ClientAttestationException.INVALID_CLIENT);
            return false;
        } catch (AttestationPolicyResolver.Unavailable e) {
            LOGGER.warn((Object) ("Attestation-based client authentication refused: " + e.getMessage()));
            AttestationEvents.refused(AttestationEvents.CRITERION, requestedClientId, ClientAttestationException.TEMPORARILY_UNAVAILABLE);
            return false;
        } catch (Exception e) {
            LOGGER.info((Object) "Attestation-based client authentication failed", (Throwable) e);
            AttestationEvents.refused(AttestationEvents.CRITERION, requestedClientId, "server_error");
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
     * The criterion's own verification, for a request the filter did not verify: load the containment models (a
     * document that cannot be read refuses, and the answer is {@code null}), verify the attestation and its proof,
     * check the request's authorization_details strictly within the attestation's (CAS section 7.1, through the same
     * {@link ClientAttestationVerifier} the filter asks), stash what was granted, and publish the context. A refusal
     * throws {@link ClientAttestationException}; the caller logs it and answers false.
     */
    static ClientAttestationResult verifyAtTheCriterion(Map inParameters, HttpServletRequest request, String requestedClientId,
            java.util.function.Function<HttpServletRequest, String> issuerOf, Boolean ignoreSslErrors, String trustControllerHost,
            String trustControllerBaseUrl, java.util.function.Supplier<String> tokenEndpointBaseUrl, AttestationPolicyResolver resolver,
            SubjectTokenVerifier subjectTokens) throws Exception {
        // The containment model the token gate asks. The engine classloader has no start-up hook, so this first
        // call is where it loads, once per classloader; a models document it cannot read refuses every attested
        // token here, and AttestationRarModels logs why once. Plan item S-9 (Phase 3) gives the component a
        // state of its own instead.
        RarModels rarModels;
        try {
            rarModels = AttestationRarModels.get();
        } catch (RarModelException e) {
            LOGGER.info((Object) ("Attestation-based client authentication refused: the RAR containment models "
                    + "could not be loaded (" + e.getMessage() + ")"));
            return null;
        }

        String opIssuer = issuerOf.apply(request);

        String attestation = ClientAttestationUtils.singleHeader(request, "OAuth-Client-Attestation");
        String pop = ClientAttestationUtils.singleHeader(request, "OAuth-Client-Attestation-PoP");
        String dpop = ClientAttestationUtils.singleHeader(request, "DPoP");
        // The endpoint's URL as PingFederate advertises it, not the request URL: that is rebuilt from the
        // Host header, which is the caller's to write (see endpointUrl).
        String tokenBase = tokenEndpointBaseUrl.get();
        String path = ClientAttestationUtils.endpointPath(request);
        String endpointUrl = ClientAttestationUtils.endpointUrl(opIssuer, tokenBase, path);

        // The client's policy, from the same resolver the filter asks: the server's, tightened by the client's
        // attestation_* properties (plan item S4c). context.ClientId is the client PingFederate authenticated.
        ClientAttestationConfig config = ClientAttestationUtils.effectivePolicy(resolver, requestedClientId, opIssuer, tokenBase, path);
        AttesterKeyResolver attesters = ClientAttestationUtils.resolveAttesterTrust(
                ignoreSslErrors, trustControllerHost, trustControllerBaseUrl, opIssuer,
                ClientAttestationUtils.trustChainEntryMaxAge(inParameters));
        ClientAttestationVerifier verifier = ClientAttestationVerifier.withRarModels(attesters, config,
                AttestationSupport.replayCache(), AttestationSupport.challengeService(), rarModels);

        // Prefer the standard RFC 9396 parameter, but PingFederate's AS pre-validates
        // 'authorization_details' against the client's configured RAR types and rejects
        // unregistered types before this issuance criterion runs. Fall back to a dedicated
        // parameter so the attestation-bound entitlement check works without full PF RAR config.
        //
        // Either parameter repeated is refused: this checks the first value, and with no filter in front nothing here
        // decides which value PingFederate goes on to read. RFC 6749 section 3.2: "Request and response parameters
        // MUST NOT be included more than once." The filter path is not affected - the filter forwards only the value
        // it checked - and Fapi2ProfileFilter refuses a repeated client_assertion for the same reason.
        ClientAttestationUtils.requireAtMostOnce(request, "authorization_details");
        ClientAttestationUtils.requireAtMostOnce(request, "oidf_requested_access");
        String authorizationDetails = request.getParameter("authorization_details");
        if (authorizationDetails == null || authorizationDetails.isBlank()) {
            authorizationDetails = request.getParameter("oidf_requested_access");
        }
        ClientAttestationResult result = verifier.verify(attestation, pop, dpop, request.getMethod(), endpointUrl, requestedClientId, authorizationDetails);
        if (!result.grantedAuthorizationDetails().isEmpty()) {
            // Stash the granted RFC 9396 authorization_details so an access-token-manager attribute mapping
            // can surface them into the issued token (OGNL reads the HttpRequest attribute): the request's
            // own details, found strictly within the attestation's, without the _principal_sub and _agent_id
            // markers, so neither marker reaches a token through this attribute.
            request.setAttribute("oidf.authorization_details",
                    new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(result.grantedAuthorizationDetails()));
        }
        // Publish the verified attestation context for the RAR -> PingAuthorize AuthorizationDetailProcessor
        // (pf-rar-paz-plugin: AttestationSubject.REQUEST_ATTRIBUTE). Decoupled by a shared string key and a
        // plain Map, so neither module depends on the other.
        Map<String, Object> context = ClientAttestationUtils.attestationContext(result, config, request, opIssuer, subjectTokens);
        request.setAttribute(RAR_ATTESTATION_CONTEXT_ATTRIBUTE, context);
        request.setAttribute(VERIFIED_ATTESTATION_ATTRIBUTE, context);
        return result;
    }

    /**
     * Why a context the filter published may not satisfy the criterion for {@code clientId}, or null when it may: it
     * must name the client PingFederate authenticated, and carry the fingerprint of the policy this copy resolves for
     * that client.
     */
    static String reusedVerificationProblem(Map<String, Object> verified, String clientId, String fingerprint) {
        if (clientId == null || !clientId.equals(verified.get("client_id"))) {
            return "the token-endpoint filter verified an attestation for another client than " + clientId;
        }
        if (!fingerprint.equals(verified.get(POLICY_FINGERPRINT_KEY))) {
            return "the token-endpoint filter verified client " + clientId + "'s attestation under another policy than"
                    + " its attestation_* properties give (a filter from before 0.6.0, or properties changed in between)";
        }
        return null;
    }

    /**
     * The server's attestation policy for a request to {@code endpointUrl}: {@link #defaultConfig}, with the required
     * claims every client's attestation must carry ({@link #requiredClaimsDefault}). Both routes start from it; a
     * client's properties can only tighten it ({@link ClientAttestationPolicy}). Until 0.6.0 the filter used
     * {@link #defaultConfig} alone, so {@code OIDF_ATTESTATION_REQUIRED_CLAIMS} applied only where the criterion
     * verified.
     */
    public static ClientAttestationConfig globalPolicy(String opIssuer, String endpointUrl) {
        ClientAttestationConfig base = ClientAttestationUtils.defaultConfig(opIssuer, endpointUrl);
        Set<String> required = ClientAttestationUtils.requiredClaimsDefault(Sources.process());
        return required == null ? base : ClientAttestationConfig.builder()
                .expectedAudience(base.expectedAudience())
                .expectedHtu(base.expectedHtu())
                .expectedHtm(base.expectedHtm())
                .requiredDisclosedClaims(required)
                .build();
    }

    /**
     * {@code clientId}'s effective policy for a request to the endpoint at {@code endpointPath}: {@link #globalPolicy}
     * tightened by the client's {@code attestation_*} properties, which {@code resolver} reads. The URLs an
     * {@code attestation_expected_htu} may pin are the token endpoint's as PingFederate advertises it
     * ({@link #endpointUrl}) and the issuer followed by its path; at another endpoint the pin does not apply.
     *
     * @throws AttestationPolicyException when the client's properties do not parse or would loosen the server's policy
     * @throws AttestationPolicyResolver.Unavailable when PingFederate's client manager cannot answer
     */
    public static ClientAttestationConfig effectivePolicy(AttestationPolicyResolver resolver, String clientId, String opIssuer,
            String tokenEndpointBaseUrl, String endpointPath) throws AttestationPolicyException, AttestationPolicyResolver.Unavailable {
        String endpointUrl = ClientAttestationUtils.endpointUrl(opIssuer, tokenEndpointBaseUrl, endpointPath);
        Set<String> aliases = new LinkedHashSet<>();
        if (TOKEN_ENDPOINT_PATH.equals(endpointPath)) {
            aliases.add(endpointUrl);
            aliases.add(ClientAttestationUtils.endpointUrl(opIssuer, null, endpointPath));
            aliases.remove(null);
        }
        return resolver.policy(clientId).apply(ClientAttestationUtils.globalPolicy(opIssuer, endpointUrl), aliases);
    }

    /**
     * The containment model's own reason for a refusal, for a log line: it names the detail and the field, never
     * the value, and the client's error_description carries only the token gate's fixed text. Empty when the
     * refusal did not come from the model.
     */
    public static String refusalDetail(ClientAttestationException e) {
        return e.getCause() instanceof RarModelException ? " (" + e.getCause().getMessage() + ")" : "";
    }

    /**
     * Builds the attestation context handed to the RAR {@code AuthorizationDetailProcessor}
     * (pf-rar-paz-plugin): the authenticated subject/{@code client_id}, the attested RFC 9396 entitlement
     * ceiling, the confirmed instance-key thumbprint, and {@code rar_models_fingerprint} - the
     * {@code RarModels.fingerprint()} of the model set that checked the request's details, lower-case hex SHA-256,
     * which the plugin compares with its own (plan item S1c). Consumed via a request attribute so the RAR
     * decision can be bounded by what the attester actually vouched.
     */
    public static Map<String, Object> attestationContext(ClientAttestationResult result, ClientAttestationConfig policy,
            HttpServletRequest request, String opIssuer, SubjectTokenVerifier subjectTokens) {
        Map<String, Object> ctx = ClientAttestationUtils.attestationContext(result);
        ctx.put(POLICY_FINGERPRINT_KEY, AttestationPolicyResolver.fingerprint(policy));
        String subject = ClientAttestationUtils.verifiedSubjectTokenSubject(request, opIssuer, subjectTokens);
        if (subject != null) {
            ctx.put(VERIFIED_SUBJECT_TOKEN_KEY, subject);
        }
        return ctx;
    }

    /**
     * The {@code sub} of a token exchange's {@code subject_token} when it verifies as a token this PingFederate signed
     * ({@link SubjectTokenVerifier}); null for any other request, for a subject token sent more than once, and for one
     * that does not verify (F-0074). The RAR plugin takes a token exchange's principal from this alone.
     */
    static String verifiedSubjectTokenSubject(HttpServletRequest request, String opIssuer, SubjectTokenVerifier subjectTokens) {
        if (!TOKEN_EXCHANGE_GRANT.equals(request.getParameter("grant_type"))) {
            return null;
        }
        String[] tokens = request.getParameterValues("subject_token");
        if (tokens == null || tokens.length != 1) {
            return null;
        }
        return SubjectTokenVerifier.subject(subjectTokens.verify(tokens[0], opIssuer));
    }

    /**
     * The context without the policy fingerprint or a subject token: the attestation's own members. The filter and the
     * criterion publish {@link #attestationContext(ClientAttestationResult, ClientAttestationConfig, HttpServletRequest,
     * String, SubjectTokenVerifier)}.
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
        // Which model set this classloader checked the request's details with. The RAR plugin shades its own copy
        // of the library and reads the same environment; a different fingerprint means the two would answer the
        // same question differently, and the plugin denies. Absent only for a result no model checked.
        if (result.rarModelsFingerprint() != null) {
            ctx.put("rar_models_fingerprint", result.rarModelsFingerprint());
        }
        // The workload behind the client — SPIFFE ID, attestor and any introspected selectors. Surfaced
        // flat as well so an access-token attribute mapping (OGNL) can name the workload in the token.
        Map<String, Object> workload = result.workload(); // never null: the result holds an empty map for none
        if (!workload.isEmpty()) {
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
        // The filter has no client's extended properties here, so an attester's presented chain is held to the per-client
        // property's default, as the criterion holds it (F-0198): statements older than that are fetched again.
        return ClientAttestationUtils.resolveAttesterTrust(runtime.ignoreSslErrors(),
                runtime.trustControllerHost(), runtime.trustControllerBaseUrl(), opIssuer, OIDFederationUtils.TRUST_CHAIN_REQUEST_MAX_AGE_DEFAULT);
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
        if (staticResolver == null) {
            return ClientAttestationUtils.federationAttesterResolver(ignoreSslErrors, trustControllerHost, trustControllerBaseUrl,
                    opIssuer, trustChainEntryMaxAge);
        }
        // The federation side is built only when a static entry misses. Building it needs the trust
        // anchor's pinned keys (FederationRuntimeConfig.trustAnchor), and a statically trusted attester
        // must not be refused because a key it never uses is not configured yet - that is exactly the
        // state of a self-anchored deployment between first boot and capturing its own keys.
        return new FallbackAttesterKeyResolver(staticResolver, (attesterIssuer, trustChainHeader) ->
                ClientAttestationUtils.federationAttesterResolver(ignoreSslErrors, trustControllerHost, trustControllerBaseUrl,
                        opIssuer, trustChainEntryMaxAge).resolve(attesterIssuer, trustChainHeader));
    }

    private static AttesterKeyResolver federationAttesterResolver(boolean ignoreSslErrors, String trustControllerHost,
            String trustControllerBaseUrl, String opIssuer, long trustChainEntryMaxAge) {
        TrustChainValidator chainValidator = ClientAttestationUtils.getValidator(ignoreSslErrors, trustControllerHost, trustControllerBaseUrl);
        return new FederationAttesterKeyResolver(chainValidator, opIssuer, trustChainEntryMaxAge);
    }

    /**
     * Default verification policy for the token-endpoint auth filter: the PoP audience is the OP issuer and
     * nothing else (draft-ietf-oauth-attestation-based-client-auth-10 §5.1 and §7.2, item 7), a DPoP proof's
     * {@code htu} is {@code endpointUrl} (see {@link #endpointUrl}), method POST. {@link #globalPolicy} adds the
     * required claims, and a client's {@code attestation_*} properties tighten that on both routes
     * ({@link #effectivePolicy}); until 0.6.0 the filter used this alone and the properties applied only where the
     * criterion verified (F-0009).
     *
     * <p>Until 0.4.0 the request URL was accepted as a PoP audience as well, and was the {@code htu}. It is
     * rebuilt from the {@code Host} header, so a PoP or DPoP proof minted for another server - one whose token
     * endpoint shares this one's path, as every PingFederate's does - passed here with a {@code Host} header
     * naming that server.
     */
    public static ClientAttestationConfig defaultConfig(String opIssuer, String endpointUrl) {
        return ClientAttestationConfig.builder()
                .expectedAudience(opIssuer)
                .expectedHtu(endpointUrl)
                .expectedHtm("POST")
                .build();
    }

    /**
     * The URL of the PingFederate endpoint at {@code endpointPath}, as PingFederate advertises it for
     * {@code issuer}: the issuer followed by the path, except the token endpoint, which PingFederate advertises
     * under its token endpoint base URL when one is set ({@code ProviderConfigurationInfoHandler} in 13.1.3's
     * {@code pf-protocolengine}: {@code token_endpoint} is that base URL, or the issuer when it is blank, then
     * {@code /as/token.oauth2}; {@code pushed_authorization_request_endpoint} is the issuer then
     * {@code /as/par.oauth2}; read with javap on 2026-09-27). {@code null} when either the issuer or the path is
     * unknown, and then a DPoP proof is refused rather than compared with nothing.
     *
     * <p>This is the {@code htu} a DPoP proof must name. RFC 9449 §4.3, item 9, compares it with "the HTTP URI
     * value for the HTTP request in which the JWT was received"; a servlet container rebuilds that from the
     * {@code Host} header (or {@code X-Forwarded-*}), which the client writes, so a proof minted for another
     * server would pass with a {@code Host} header naming it. The issuer comes from configuration: PingFederate's
     * {@code OAuthIssuerUtils.getIssuerValue} returns its base URL, or a virtual host name or issuer it has
     * configured when the request names one; a {@code Host} it does not know gets the base URL (13.1.3, javap,
     * 2026-09-27).
     */
    public static String endpointUrl(String issuer, String tokenEndpointBaseUrl, String endpointPath) {
        if (issuer == null || issuer.isBlank() || endpointPath == null || endpointPath.isEmpty()) {
            return null;
        }
        boolean tokenEndpoint = TOKEN_ENDPOINT_PATH.equals(endpointPath);
        String base = tokenEndpoint && tokenEndpointBaseUrl != null && !tokenEndpointBaseUrl.isBlank()
                ? tokenEndpointBaseUrl : issuer;
        return base + endpointPath;
    }

    /** Where PingFederate serves its token endpoint, under the issuer or the token endpoint base URL. */
    static final String TOKEN_ENDPOINT_PATH = "/as/token.oauth2";

    /**
     * The path within PingFederate's runtime web application that {@code request} was routed to, as the container
     * decoded and matched it: servlet path and path info ({@code /as/token.oauth2} under PingFederate's
     * {@code *.oauth2} mapping, whose servlet path is the whole path). The context path is left out: PingFederate's
     * base URL, and so the issuer, already carries it ({@code run.properties} in 13.1.3 says of
     * {@code pf.runtime.context.path}: "If this property is changed, the path must also be added to the base URL for
     * your PingFederate system protocol settings"), and {@code OAuthIssuer.constructCurrentRequestUrl} strips it from
     * the request URI before adding the rest to the issuer (javap, 2026-09-27). A request that carries no servlet
     * path - one the OGNL criterion is handed that was not dispatched through a mapping, say - gives its
     * request-target path, less the context path, instead: the client writes that, but it only chooses a path under
     * the configured issuer, never a host. {@code null} when the request names neither.
     */
    public static String endpointPath(HttpServletRequest request) {
        String path = ClientAttestationUtils.nullToEmpty(request.getServletPath())
                + ClientAttestationUtils.nullToEmpty(request.getPathInfo());
        if (path.isEmpty()) {
            path = ClientAttestationUtils.nullToEmpty(request.getRequestURI());
            String contextPath = ClientAttestationUtils.nullToEmpty(request.getContextPath());
            if (!contextPath.isEmpty() && path.startsWith(contextPath)) {
                path = path.substring(contextPath.length());
            }
        }
        return path.isEmpty() ? null : path;
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static final java.util.concurrent.atomic.AtomicBoolean TOKEN_ENDPOINT_BASE_URL_WARNED =
            new java.util.concurrent.atomic.AtomicBoolean();

    /**
     * PingFederate's token endpoint base URL (Authorization Server Settings), or {@code null} when it is not set
     * or cannot be read. An internal of PingFederate's, not SDK, read the way {@code ProviderConfigurationInfoHandler}
     * reads it for the discovery document. Unreadable is said once and treated as unset, which leaves the token
     * endpoint under the issuer: a proof naming the base URL is then refused, never one naming another server
     * accepted.
     */
    public static String configuredTokenEndpointBaseUrl() {
        try {
            return PfInternals.tokenEndpointBaseUrl();
        } catch (RuntimeException | LinkageError e) {
            if (TOKEN_ENDPOINT_BASE_URL_WARNED.compareAndSet(false, true)) {
                LOGGER.warn((Object) ("PingFederate's token endpoint base URL could not be read, so a DPoP proof at "
                        + "the token endpoint must name the issuer's token endpoint: " + e));
            }
            return null;
        }
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
                java.nio.file.Path path = endpointSettings(Sources.process()).path(MOCK_ATTESTERS);
                if (path != null && java.nio.file.Files.isReadable(path)) {
                    try {
                        mockResolver = StaticAttesterKeyResolver.fromFile(path);
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
                // The anchor's keys are deployment-wide and out of band; the host has to be that
                // anchor. Same rule and same check as OIDFederationUtils.
                TrustAnchorSet anchors = OIDFederationUtils.requireConfiguredAnchors(trustControllerHost);
                gateway = new HttpTrustControllerGateway(new JdkHttpGetClient(ignoreSslErrors, OutboundUrlPolicy.fromEnvironment()
                        .trusting(effectiveBaseUrl, trustControllerHost)), effectiveBaseUrl, trustControllerHost);
                configuredIgnoreSslErrors = ignoreSslErrors;
                configuredTrustControllerHost = trustControllerHost;
                configuredTrustControllerBaseUrl = effectiveBaseUrl;
                validator = new TrustChainValidator(gateway, anchors, java.util.Set.of(), ValidatorOptions.defaults());
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

    /** The catalogue the global attestation-endpoint settings are in ({@code attestation-token-endpoint.json}). */
    public static final String ENDPOINT_SETTINGS = "attestation-token-endpoint";
    static final String REQUIRED_CLAIMS = "oidf.attestation.required.claims";
    static final String MOCK_ATTESTERS = "oidf.mock.attesters";

    /**
     * The required claims every client's attestation must carry, to which a client's {@code attestation_required_claims}
     * adds: the {@code oidf.attestation.required.claims} system property, else {@code OIDF_ATTESTATION_REQUIRED_CLAIMS},
     * space- or comma-separated, read through the entry's sources in their order - or null when neither names one. A
     * list of nothing (a comma alone) is refused (plan item ST-5). The image used to set the property to
     * {@code workload}; from 0.6.0 the deployment sets either (plan item R-I3).
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused for a list of nothing
     */
    public static Set<String> requiredClaimsDefault(Sources sources) {
        Settings settings = endpointSettings(sources);
        return settings.words(REQUIRED_CLAIMS);
    }

    /** The global attestation-endpoint settings, read from {@code sources}. */
    static Settings endpointSettings(Sources sources) {
        return Settings.load(ClientAttestationUtils.class.getClassLoader(), ENDPOINT_SETTINGS).with(sources);
    }

    /**
     * The per-client {@code trust_chain_request_max_age} for an attester's chain: the same property, and the same default,
     * as the OGNL chain criterion's ({@link OIDFederationUtils#trustChainRequestMaxAge}), F-0198.
     */
    private static long trustChainEntryMaxAge(Map inParameters) {
        return OIDFederationUtils.trustChainRequestMaxAge(inParameters);
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
        // S9b: nothing - the omitted attribute, never a throw - while ATTESTATION_AUTH is not serving here.
        if (!CriterionGate.serves(Startup.ATTESTATION_AUTH, "attestationClaim")) {
            return "";
        }
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
     * from a policy attribute. Instead this reads the {@code subject_token} request parameter, and nests its
     * {@code act} only when the token verifies as one this PingFederate signed - its signature against
     * PingFederate's signing keys, its issuer, its {@code exp} ({@link SubjectTokenVerifier}; plan item S4c,
     * F-0074). A subject token that does not verify contributes nothing, and the chain names only the acting
     * party. Until 0.6.0 the {@code act} was decoded without verifying, on the grounds that the token-exchange
     * processor validates the subject token before any token is issued; that is a property of how a deployment
     * configures the processor, not of this code. The {@code act} claim is emitted (and consumed) as a JSON
     * string; a string-encoded prior chain is re-parsed so it nests as an object rather than double-escaped text.
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
     */
    public static String delegationActChain(Object inObj) {
        // S9b: no component gate of its own. The acting party's agent_id and attester come through attestationClaim,
        // which answers nothing while ATTESTATION_AUTH is not serving; the rest - context.ClientId and a subject token
        // this PingFederate signed - needs no component, so a token exchange keeps its act chain with the client as actor.
        return ClientAttestationUtils.delegationActChain(inObj, ClientAttestationUtils::pingFederateIssuer,
                SubjectTokenVerifier.pingFederate());
    }

    /** Test seam: {@link #delegationActChain(Object)} with PingFederate's issuer and signing keys supplied. */
    @SuppressWarnings("unchecked")
    static String delegationActChain(Object inObj, java.util.function.Function<HttpServletRequest, String> issuerOf,
            SubjectTokenVerifier subjectTokens) {
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
            String[] subjectTokenValues = request.getParameterValues("subject_token");
            if (subjectTokenValues != null && subjectTokenValues.length == 1) {
                Map<String, Object> priorAct = SubjectTokenVerifier.act(
                        subjectTokens.verify(subjectTokenValues[0], issuerOf.apply(request)));
                if (priorAct != null) {
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

    private static void requireAtMostOnce(HttpServletRequest request, String name) {
        String[] values = request.getParameterValues(name);
        if (values != null && values.length > 1) {
            throw new IllegalArgumentException("Multiple '" + name + "' parameters present; at most one is allowed");
        }
    }

    /** {@code value} when it is a string, else null. */
    static String string(Object value) {
        return value instanceof String ? (String) value : null;
    }

    private static String attributeValue(Map inParameters, String key) {
        Object value = inParameters.get(key);
        if (value instanceof AttributeValue) {
            return ((AttributeValue) value).getValue();
        }
        return null;
    }

}
