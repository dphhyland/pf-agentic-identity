package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.common.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.common.JdkHttpGetClient;
import com.pingidentity.ps.oidf.common.JwtCodec;
import com.pingidentity.ps.oidf.common.TrustChainValidator;
import com.pingidentity.ps.oidf.common.TrustControllerGateway;
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
    private static final Object LOCK = new Object();

    private OIDFederationUtils() {
    }

    private static void initialize(boolean ignoreSslErrors, String trustControllerHost) {
        getGateway(ignoreSslErrors, trustControllerHost);
    }

    private static TrustControllerGateway getGateway(boolean ignoreSslErrors, String trustControllerHost) {
        TrustControllerGateway local = gateway;
        if (local != null) {
            validateConfiguration(ignoreSslErrors, trustControllerHost);
            return local;
        }
        synchronized (LOCK) {
            local = gateway;
            if (local == null) {
                gateway = local = new HttpTrustControllerGateway(new JdkHttpGetClient(ignoreSslErrors), trustControllerHost);
                configuredIgnoreSslErrors = ignoreSslErrors;
                configuredTrustControllerHost = trustControllerHost;
                validator = new TrustChainValidator(gateway, trustControllerHost);
            } else {
                validateConfiguration(ignoreSslErrors, trustControllerHost);
            }
            return local;
        }
    }

    private static void validateConfiguration(boolean ignoreSslErrors, String trustControllerHost) {
        if (!Objects.equals(configuredIgnoreSslErrors, ignoreSslErrors) || !Objects.equals(configuredTrustControllerHost, trustControllerHost)) {
            throw new IllegalStateException("TrustControllerGateway already initialized with different configuration");
        }
    }

    public static boolean validateTrustChain(Object inObj) {
        return validateTrustChain(inObj, RegistrationConfiguration._IGNORE_SSL_ERRORS, RegistrationConfiguration._TRUST_CONTROLLER_HOST);
    }

    public static boolean validateTrustChain(Object inObj, Boolean ignoreSslErrors, String trustControllerHost) {
        initialize(ignoreSslErrors, trustControllerHost);
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

