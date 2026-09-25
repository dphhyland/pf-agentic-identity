package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException;
import com.pingidentity.ps.oidf.federation.TrustControllerGateway;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.FederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.pf.FederationPolicySupport;
import com.pingidentity.ps.oidf.jose.JwtVerificationException;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationConfiguration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * OGNL-invoked helper that validates an RP's OpenID Federation trust chain during token-endpoint
 * client authentication. Lazily builds and caches a shared {@link TrustControllerGateway} /
 * {@link TrustChainValidator} (pinned to one host/SSL configuration), extracts the {@code trust_chain}
 * header from the {@code client_assertion}, and returns whether the chain validates.
 */
public final class OIDFederationUtils {
    private static final long DEFAULT_ = 60L;
    private static final Log LOGGER = LogFactory.getLog(OIDFederationUtils.class);
    private static volatile TrustControllerGateway gateway;
    private static volatile TrustChainValidator validator;
    private static volatile Boolean configuredIgnoreSslErrors;
    private static volatile String configuredTrustControllerHost;
    private static volatile String configuredTrustControllerBaseUrl;
    private static final Object LOCK = new Object();
    private static final Function<HttpServletRequest, String> PF_ISSUER = req -> OAuthIssuerUtils.getInstance().getIssuerValue(req);
    /** Test seam: PF's issuer resolver needs a booted PingFederate. */
    private static volatile Function<HttpServletRequest, String> issuerResolver = PF_ISSUER;
    /** Test seam: the transport the gateway fetches through; null means a screened JDK client. */
    private static volatile HttpGetClient httpClientOverride;

    static {
        // The OGNL criteria run on PF's engine classloader, which has its own copy of FederationEvents.
        PfAuditEventSink.install();
    }

    private OIDFederationUtils() {
    }

    private static void initialize(boolean ignoreSslErrors, String trustControllerHost, String trustControllerBaseUrl) {
        getGateway(ignoreSslErrors, trustControllerHost, trustControllerBaseUrl);
    }

    private static TrustControllerGateway getGateway(boolean ignoreSslErrors, String trustControllerHost, String trustControllerBaseUrl) {
        String effectiveBaseUrl = trustControllerBaseUrl == null || trustControllerBaseUrl.isBlank() ? trustControllerHost : trustControllerBaseUrl;
        TrustControllerGateway local = gateway;
        if (local != null) {
            validateConfiguration(ignoreSslErrors, trustControllerHost, effectiveBaseUrl);
            return local;
        }
        synchronized (LOCK) {
            local = gateway;
            if (local == null) {
                // trustControllerHost is the bare identity used for knownTrustAnchor matching;
                // effectiveBaseUrl is the (possibly different) HTTP base actually needed to reach it —
                // see HttpTrustControllerGateway's selfIssuer javadoc for why these can diverge.
                // The anchor's keys are deployment-wide and out of band (FederationRuntimeConfig).
                // The host an OGNL expression passes has to be that anchor; a different one would
                // otherwise be validated against keys that are not its own.
                TrustAnchorSet anchors = requireConfiguredAnchors(trustControllerHost);
                HttpGetClient http = httpClientOverride != null ? httpClientOverride : new JdkHttpGetClient(ignoreSslErrors,
                        OutboundUrlPolicy.fromEnvironment().trusting(effectiveBaseUrl, trustControllerHost));
                gateway = local = new HttpTrustControllerGateway(http, effectiveBaseUrl, trustControllerHost);
                configuredIgnoreSslErrors = ignoreSslErrors;
                configuredTrustControllerHost = trustControllerHost;
                configuredTrustControllerBaseUrl = effectiveBaseUrl;
                validator = new TrustChainValidator(gateway, anchors, java.util.Set.of(), ValidatorOptions.defaults());
            } else {
                validateConfiguration(ignoreSslErrors, trustControllerHost, effectiveBaseUrl);
            }
            return local;
        }
    }

    /**
     * The deployment's pinned anchors, which must include the host this call site was asked to validate
     * against. A chain then validates to any of them - the anchor set is the deployment's trust policy
     * (OpenID Federation 1.0 §10) - but a host that is none of them would be validated against keys that are
     * not its own, so it is refused.
     */
    static TrustAnchorSet requireConfiguredAnchors(String trustControllerHost) {
        TrustAnchorSet anchors = FederationRuntimeConfig.get().trustAnchors();
        if (!anchors.contains(trustControllerHost)) {
            throw new IllegalStateException("trust controller host " + trustControllerHost + " is not a configured trust anchor "
                    + anchors.entityIds() + " (" + FederationRuntimeConfig.HOST_ENV + " / " + FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV
                    + "); refusing to validate against keys that are not its own");
        }
        return anchors;
    }

    private static void validateConfiguration(boolean ignoreSslErrors, String trustControllerHost, String trustControllerBaseUrl) {
        if (!Objects.equals(configuredIgnoreSslErrors, ignoreSslErrors)
                || !Objects.equals(configuredTrustControllerHost, trustControllerHost)
                || !Objects.equals(configuredTrustControllerBaseUrl, trustControllerBaseUrl)) {
            throw new IllegalStateException("TrustControllerGateway already initialized with different configuration");
        }
    }

    public static boolean validateTrustChain(Object inObj) {
        // Deployment-wide settings, resolved once and identical for every reader. These used to be
        // statics on RegistrationConfiguration, mirrored from its constructor, so this call site
        // needed its own env fallback for the case where nothing had constructed one yet -- see
        // FederationRuntimeConfig.
        FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
        return validateTrustChain(inObj, runtime.ignoreSslErrors(), runtime.trustControllerHost(),
                runtime.trustControllerBaseUrl());
    }

    public static boolean validateTrustChain(Object inObj, Boolean ignoreSslErrors, String trustControllerHost) {
        return validateTrustChain(inObj, ignoreSslErrors, trustControllerHost, trustControllerHost);
    }

    /**
     * Thin fail-closed shell around {@link #validateTrustChainInner}: an exception thrown before
     * the inner method's own try/catch (e.g. during lazy gateway initialization) would otherwise
     * surface at the OGNL boundary as an opaque "Method failed" with no logged detail — this shell
     * catches and logs it. Mirrors ClientAttestationUtils.validateClientAttestation's identical shell.
     */
    public static boolean validateTrustChain(Object inObj, Boolean ignoreSslErrors, String trustControllerHost, String trustControllerBaseUrl) {
        try {
            return validateTrustChainInner(inObj, ignoreSslErrors, trustControllerHost, trustControllerBaseUrl);
        } catch (Throwable t) {
            LOGGER.error("Trust chain validation failed with a non-Exception throwable", t);
            return false;
        }
    }

    private static boolean validateTrustChainInner(Object inObj, Boolean ignoreSslErrors, String trustControllerHost, String trustControllerBaseUrl) {
        initialize(ignoreSslErrors, trustControllerHost, trustControllerBaseUrl);
        if (!(inObj instanceof Map)) {
            LOGGER.error("In parameters not instance of Map. " + inObj.getClass().getName());
            return false;
        }
        Map inParameters = (Map)inObj;
        String rpEntityId = ((AttributeValue)inParameters.get("context.ClientId")).getValue();
        HttpServletRequest request = (HttpServletRequest)((AttributeValue)inParameters.get("context.HttpRequest")).getObjectValue();
        String opEntityId = issuerResolver.apply(request);
        List<String> trustChainList = extractTrustChainFromClientAssertion(request);
        long maxLeafNodeTime = longSetting(inParameters, "extproperties.trust_chain_leaf_max_time", -1L);
        long maxTrustAnchorNodeTime = longSetting(inParameters, "extproperties.trust_chain_trustanchor_max_time", -1L);
        long maxTrustChainEntryAgeSeconds = longSetting(inParameters, "extproperties.trust_chain_request_max_age", 60L);
        if (registrationExpired(inParameters, rpEntityId)) {
            return false;
        }
        try {
            validator.validate(trustChainList, rpEntityId, opEntityId, maxLeafNodeTime, maxTrustAnchorNodeTime, maxTrustChainEntryAgeSeconds);
            FederationEvents.event(FederationEvents.CHAIN_VALIDATED).subject(rpEntityId).partner(configuredTrustControllerHost)
                    .field("endpoint", "token").field("presented", trustChainList.size()).emit();
        }
        catch (Exception e) {
            FederationEvents.event(FederationEvents.CHAIN_REFUSED).failure(refusalReason(e)).subject(rpEntityId)
                    .partner(configuredTrustControllerHost).role("OP").field("endpoint", "token").audit()
                    .description(e instanceof TrustChainValidationException || e instanceof JwtVerificationException
                            ? e.getMessage() : "trust chain did not validate").emit();
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("trust chain refused for " + rpEntityId + ": " + e.getClass().getSimpleName());
            }
            return false;
        }
        // The chain stands; whether this token may be issued is the policy decision point's to say, when it is asked.
        return TokenIssuancePolicy.permits(inParameters, rpEntityId, opEntityId, request,
                FederationPolicySupport.decisionPointFor(DecisionPoint.TOKEN_ISSUANCE), FederationPolicySupport.settings());
    }

    /**
     * The token-issuance decision point on its own, for an access token mapping that does not validate the chain: true
     * unless the deployment asks a policy decision point about tokens ({@code token_issuance} in
     * {@code OIDF_PDP_DECISION_POINTS}) and it refuses. {@link #validateTrustChain(Object)} asks it too, once the chain
     * validates - so a mapping needs one or the other, not both. Fails closed on anything unexpected.
     */
    public static boolean federationPolicy(Object inObj) {
        try {
            FederationPolicyDecisionPoint pdp = FederationPolicySupport.decisionPointFor(DecisionPoint.TOKEN_ISSUANCE);
            if (pdp == null) {
                return true;
            }
            Map<?, ?> criteria = (Map<?, ?>) inObj;
            String clientId = ((AttributeValue) criteria.get("context.ClientId")).getValue();
            HttpServletRequest request = (HttpServletRequest) ((AttributeValue) criteria.get("context.HttpRequest")).getObjectValue();
            return TokenIssuancePolicy.permits(criteria, clientId, issuerResolver.apply(request), request, pdp, FederationPolicySupport.settings());
        } catch (Throwable t) {
            LOGGER.error("The token-issuance policy check failed", t);
            return false;
        }
    }

    /**
     * The no-network backstop for OpenID Federation 1.0 §12.3: a client whose recorded registration expiry has
     * passed is refused at issuance, whatever its chain says now - an explicit registration is renewed by its
     * RP registering again, an automatic one by the token-endpoint filter. A client with no recorded expiry
     * (registered before expiries were) is left to the chain check. With
     * {@code OIDF_REGISTRATION_EXPIRY_ENFORCEMENT=log} the expiry is only logged.
     *
     * @return true when the request must be refused
     */
    static boolean registrationExpired(Map inParameters, String clientId) {
        long expiresAt = longSetting(inParameters, EXPIRES_AT_PROPERTY, -1L);
        if (expiresAt < 0 || java.time.Instant.now().getEpochSecond() < expiresAt) {
            return false;
        }
        FederationRuntimeConfig.ExpiryEnforcement enforcement = FederationRuntimeConfig.get().registration().expiryEnforcement();
        FederationEvents.event(FederationEvents.REGISTRATION_EXPIRED_AT_ISSUANCE).failure("expired").subject(clientId).role("OP")
                .field("expires_at", expiresAt).field("enforcement", enforcement.name().toLowerCase(java.util.Locale.ROOT)).audit().emit();
        if (enforcement == FederationRuntimeConfig.ExpiryEnforcement.LOG) {
            LOGGER.warn("Federation client " + clientId + " is past its registration's expiry; issuing because "
                    + FederationRuntimeConfig.REGISTRATION_EXPIRY_ENFORCEMENT_ENV + "=log");
            return false;
        }
        return true;
    }

    /** The criteria-map key of a client's recorded registration expiry. */
    static final String EXPIRES_AT_PROPERTY = "extproperties.federation_registration_expires_at";

    /** A short machine reason for a refusal, for the event's {@code reason}. */
    static String refusalReason(Exception e) {
        if (e instanceof TrustChainValidationException tcve) {
            return tcve.kind().code();
        }
        if (e instanceof JwtVerificationException jve) {
            return jve.code();
        }
        return "invalid";
    }

    /**
     * A numeric per-client setting from the criteria map. PF maps an extended property into the map even
     * when the client has no value for it, so a blank, {@code "null"} or non-numeric value falls back to
     * {@code fallback} with a warning naming the key - it never throws out of the criterion.
     */
    static long longSetting(Map inParameters, String key, long fallback) {
        if (!inParameters.containsKey(key)) {
            return fallback;
        }
        Object raw = inParameters.get(key);
        String value = raw == null ? null : String.valueOf(raw instanceof AttributeValue ? ((AttributeValue) raw).getValue() : raw);
        if (value == null || value.isBlank() || "null".equals(value)) {
            return fallback;
        }
        try {
            return Long.parseLong(value.trim());
        }
        catch (NumberFormatException e) {
            LOGGER.warn(key + " is not a whole number; using " + fallback + " for this request");
            return fallback;
        }
    }

    /** Test seam: resolve the OP issuer without a booted PingFederate. */
    static void useIssuerResolver(Function<HttpServletRequest, String> resolver) {
        issuerResolver = resolver == null ? PF_ISSUER : resolver;
    }

    /** Test seam: fetch through this client instead of a screened JDK client. Takes effect after {@link #resetForTests}. */
    static void useHttpClient(HttpGetClient client) {
        httpClientOverride = client;
    }

    /** Test seam: forget the memoised gateway and validator and every override. */
    static void resetForTests() {
        synchronized (LOCK) {
            gateway = null;
            validator = null;
            configuredIgnoreSslErrors = null;
            configuredTrustControllerHost = null;
            configuredTrustControllerBaseUrl = null;
            issuerResolver = PF_ISSUER;
            httpClientOverride = null;
        }
    }

    private static List<String> extractTrustChainFromClientAssertion(HttpServletRequest request) {
        Map<String, Object> headers;
        String clientAssertion = request.getParameter("client_assertion");
        if (clientAssertion == null || clientAssertion.isBlank()) {
            return Collections.emptyList();
        }
        try {
            headers = JwtCodec.getJwtHeaders(clientAssertion);
        }
        catch (Exception e) {
            // The caller's input, not a fault of ours: one line, no stack, nothing of the assertion itself.
            LOGGER.info("client_assertion is not a parseable JWT (" + refusalReason(e) + "); running validator with empty trust_chain");
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
                continue;
            }
            if (!LOGGER.isDebugEnabled()) continue;
            LOGGER.debug("Skipping non-string entry in client_assertion trust_chain header: " + (item == null ? "null" : item.getClass().getName()));
        }
        return trustChainList;
    }
}

