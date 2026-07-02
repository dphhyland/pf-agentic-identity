/*
 * PingFederate AuthorizationDetailProcessor that delegates the RFC 9396 decision to a PingAuthorize
 * governance engine, bounded by the client attestation's entitlement.
 */
package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessor;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessorDescriptor;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailValidationResult;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PingFederate SDK {@code AuthorizationDetailProcessor} for RFC 9396 Rich Authorization Requests.
 *
 * <p>Modelled on the reference {@code RARAuthDetailsProcessor}, but this is a Policy Enforcement Point that
 * <em>honours</em> the governance-engine decision rather than only enriching:
 * <ul>
 *   <li>{@link #enrich} forwards the requested detail plus the attestation-vouched subject / entitlement /
 *       workload to the governance engine, denies unless the decision is PERMIT, and applies the returned
 *       statements (downscoping / obligations).</li>
 *   <li>{@link #isEqualOrSubset} does a real containment check (for refresh-time narrowing).</li>
 * </ul>
 *
 * <p>The attestation context is published by the client-attestation issuance hook as a request attribute
 * (see {@link AttestationSubject#REQUEST_ATTRIBUTE}) and read here via {@code context.getRequest()}. All I/O
 * and mapping logic lives in framework-agnostic collaborators so it is unit-tested without the SDK.
 */
public class AttestationAwareRarProcessor implements AuthorizationDetailProcessor {

    private static final String VERSION = "0.1.0";
    private static final String TYPE_NAME = "Attestation-aware RAR to PingAuthorize";

    private static final String PDP_URL = "PDP URL";
    private static final String PDP_DOMAIN_PREFIX = "PDP Domain Prefix";
    private static final String PDP_SERVICE = "PDP Service";
    private static final String PDP_ACTION = "PDP Action";
    private static final String PDP_ATTRIBUTE_PREFIX = "Attribute Prefix";
    private static final String PDP_ATTR_TYPE_PREFIX = "Prefix Attributes with Type";
    private static final String PDP_SECRET_HEADER = "Shared Secret Header";
    private static final String PDP_SECRET = "Shared Secret";
    private static final String DENY_ON_NON_PERMIT = "Deny unless PERMIT";
    private static final String FAIL_OPEN = "Fail open on engine error";
    private static final String INSECURE_TLS = "Skip TLS verification (dev only)";
    private static final String TIMEOUT_MS = "Request timeout (ms)";

    private static final Set<String> SUPPORTED_TYPES =
            new LinkedHashSet<>(Arrays.asList("sales_agent", "payment_initiation", "account_information"));

    private final Logger log = Logger.getLogger(getClass().getName());
    private final ObjectMapper mapper = new ObjectMapper();

    private GovernanceEngineConfig config;
    private GovernanceEngineClient client;

    @Override
    public void configure(Configuration configuration) {
        this.config = GovernanceEngineConfig.builder()
                .pdpUrl(configuration.getFieldValue(PDP_URL))
                .domainPrefix(configuration.getFieldValue(PDP_DOMAIN_PREFIX))
                .service(configuration.getFieldValue(PDP_SERVICE))
                .action(configuration.getFieldValue(PDP_ACTION))
                .attributePrefix(configuration.getFieldValue(PDP_ATTRIBUTE_PREFIX))
                .prefixAttributesWithType(configuration.getBooleanFieldValue(PDP_ATTR_TYPE_PREFIX))
                .secretHeader(configuration.getFieldValue(PDP_SECRET_HEADER))
                .secret(configuration.getFieldValue(PDP_SECRET))
                .denyOnNonPermit(configuration.getBooleanFieldValue(DENY_ON_NON_PERMIT))
                .failOpenOnError(configuration.getBooleanFieldValue(FAIL_OPEN))
                .insecureTls(configuration.getBooleanFieldValue(INSECURE_TLS))
                .timeoutMillis(parseInt(configuration.getFieldValue(TIMEOUT_MS), 10_000))
                .build();
        HttpTransport transport = new JdkHttpTransport(config.isInsecureTls(), config.getTimeoutMillis());
        this.client = new GovernanceEngineClient(config, transport, new GovernanceEngineRequestBuilder(config, mapper), mapper);
        log.info("Configured AttestationAwareRarProcessor -> " + config.getPdpUrl());
    }

    @Override
    public PluginDescriptor getPluginDescriptor() {
        GuiConfigDescriptor gui = new GuiConfigDescriptor();
        gui.setDescription("Maps RFC 9396 authorization_details into a PingAuthorize governance-engine decision, "
                + "bounded by the client attestation's entitlement.");
        addText(gui, PDP_URL, "Governance engine decision URL", "https://", true);
        addText(gui, PDP_DOMAIN_PREFIX, "PDP domain prefix", "idpartners.authorization_details", false);
        addText(gui, PDP_SERVICE, "PDP service", "Authorization", false);
        addText(gui, PDP_ACTION, "PDP action", "authorize", false);
        addText(gui, PDP_ATTRIBUTE_PREFIX, "Attribute prefix", "idp", false);
        addCheck(gui, PDP_ATTR_TYPE_PREFIX, "Prefix attributes with detail type", true);
        addText(gui, PDP_SECRET_HEADER, "Shared-secret header name", "CLIENT-TOKEN", false);
        addText(gui, PDP_SECRET, "Shared-secret value", "", true);
        addCheck(gui, DENY_ON_NON_PERMIT, "Deny unless the decision is PERMIT", true);
        addCheck(gui, FAIL_OPEN, "Fail open if the governance engine is unreachable", false);
        addCheck(gui, INSECURE_TLS, "Skip TLS verification (dev only)", false);
        addText(gui, TIMEOUT_MS, "Request timeout (ms)", "10000", false);

        AuthorizationDetailProcessorDescriptor descriptor =
                new AuthorizationDetailProcessorDescriptor(TYPE_NAME, this, gui, VERSION);
        descriptor.setSupportedAuthorizationDetailTypes(new HashSet<>(SUPPORTED_TYPES));
        return descriptor;
    }

    @Override
    public AuthorizationDetailValidationResult validate(AuthorizationDetail authDetail,
                                                        AuthorizationDetailContext context,
                                                        Map<String, Object> parameters) {
        if (authDetail.getType() == null || authDetail.getType().isBlank()) {
            return AuthorizationDetailValidationResult.createInvalidResult("authorization_details entry is missing 'type'");
        }
        return AuthorizationDetailValidationResult.createValidResult();
    }

    @Override
    public AuthorizationDetail enrich(AuthorizationDetail authDetail,
                                      AuthorizationDetailContext context,
                                      Map<String, Object> parameters) throws AuthorizationDetailProcessingException {
        AttestationSubject subject = readSubject(context);
        String clientId = context == null ? null : context.getClientId();
        try {
            DecisionResponse decision = client.decide(authDetail.getType(), authDetail.getDetail(), subject, clientId);
            if (config.isDenyOnNonPermit() && !decision.isPermit()) {
                throw new AuthorizationDetailProcessingException(
                        "governance engine denied authorization_details of type '" + authDetail.getType()
                                + "' (decision=" + decision.getDecision() + ")");
            }
            Map<String, Object> base = authDetail.getDetail();
            Map<String, Object> enriched = base == null ? new HashMap<>() : new HashMap<>(base);
            StatementApplier.apply(decision.getStatements(), enriched, mapper);
            authDetail.setDetail(enriched);
            return authDetail;
        } catch (AuthorizationDetailProcessingException e) {
            throw e;
        } catch (Exception e) {
            if (config.isFailOpenOnError()) {
                log.log(Level.WARNING, "governance engine call failed; failing open for type '" + authDetail.getType() + "'", e);
                return authDetail;
            }
            throw new AuthorizationDetailProcessingException(
                    "governance engine call failed for type '" + authDetail.getType() + "'", e);
        }
    }

    @Override
    public boolean isEqualOrSubset(AuthorizationDetail requested, AuthorizationDetail accepted,
                                   AuthorizationDetailContext context, Map<String, Object> parameters) {
        Map<String, Object> req = requested == null ? null : requested.getDetail();
        Map<String, Object> acc = accepted == null ? null : accepted.getDetail();
        return RarContainment.isSubset(req, acc);
    }

    @Override
    public String getUserConsentDescription(AuthorizationDetail authDetail, AuthorizationDetailContext context,
                                            Map<String, Object> parameters) {
        Map<String, Object> detail = authDetail.getDetail();
        StringBuilder sb = new StringBuilder();
        sb.append("Authorization type: ").append(authDetail.getType()).append('\n');
        if (detail != null) {
            for (Map.Entry<String, Object> e : detail.entrySet()) {
                if ("type".equals(e.getKey())) {
                    continue;
                }
                sb.append(e.getKey().replace('_', ' ')).append(": ").append(e.getValue()).append('\n');
            }
        }
        return sb.toString();
    }

    private AttestationSubject readSubject(AuthorizationDetailContext context) {
        try {
            if (context != null) {
                HttpServletRequest request = context.getRequest();
                if (request != null) {
                    return AttestationSubject.fromAttribute(request.getAttribute(AttestationSubject.REQUEST_ATTRIBUTE));
                }
            }
        } catch (Exception e) {
            log.log(Level.WARNING, "could not read attestation context from request", e);
        }
        return AttestationSubject.empty();
    }

    private static void addText(GuiConfigDescriptor gui, String name, String label, String defaultValue, boolean required) {
        TextFieldDescriptor field = new TextFieldDescriptor(name, label);
        field.setDefaultValue(defaultValue);
        if (required) {
            field.addValidator(new RequiredFieldValidator());
        }
        gui.addField(field);
    }

    private static void addCheck(GuiConfigDescriptor gui, String name, String label, boolean defaultValue) {
        CheckBoxFieldDescriptor field = new CheckBoxFieldDescriptor(name, label);
        field.setDefaultValue(defaultValue);
        gui.addField(field);
    }

    private static int parseInt(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
