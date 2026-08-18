package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.TrustControllerGateway;
import com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationConfiguration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
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
                gateway = local = new HttpTrustControllerGateway(new JdkHttpGetClient(ignoreSslErrors, OutboundUrlPolicy.fromEnvironment()
                        .trusting(effectiveBaseUrl, trustControllerHost)), effectiveBaseUrl, trustControllerHost);
                configuredIgnoreSslErrors = ignoreSslErrors;
                configuredTrustControllerHost = trustControllerHost;
                configuredTrustControllerBaseUrl = effectiveBaseUrl;
                validator = new TrustChainValidator(gateway, trustControllerHost);
            } else {
                validateConfiguration(ignoreSslErrors, trustControllerHost, effectiveBaseUrl);
            }
            return local;
        }
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
        String opEntityId = OAuthIssuerUtils.getInstance().getIssuerValue(request);
        List<String> trustChainList = extractTrustChainFromClientAssertion(request);
        int maxLeafNodeTime = -1;
        if (inParameters.containsKey("extproperties.trust_chain_leaf_max_time")) {
            String value = String.valueOf(inParameters.get("extproperties.trust_chain_leaf_max_time"));
            maxLeafNodeTime = Integer.parseInt(value);
        }
        int maxTrustAnchorNodeTime = -1;
        if (inParameters.containsKey("extproperties.trust_chain_trustanchor_max_time")) {
            String value = String.valueOf(inParameters.get("extproperties.trust_chain_trustanchor_max_time"));
            maxTrustAnchorNodeTime = Integer.parseInt(value);
        }
        long maxTrustChainEntryAgeSeconds = 60L;
        if (inParameters.containsKey("extproperties.trust_chain_request_max_age")) {
            String value = String.valueOf(inParameters.get("extproperties.trust_chain_request_max_age"));
            try {
                maxTrustChainEntryAgeSeconds = Long.parseLong(value);
            }
            catch (NumberFormatException e) {
                LOGGER.warn("extproperties.trust_chain_entry_max_age is not a valid integer (\"" + value + "\"); disabling the trust-chain pre-filter for this request", e);
                maxTrustChainEntryAgeSeconds = 60L;
            }
        }
        try {
            validator.validate(trustChainList, rpEntityId, opEntityId, maxLeafNodeTime, maxTrustAnchorNodeTime, maxTrustChainEntryAgeSeconds);
            return true;
        }
        catch (Exception e) {
            LOGGER.info("Trust chain validation failed", e);
            return false;
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
            LOGGER.info("client_assertion is not a parseable JWT; running validator with empty trust_chain", e);
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

