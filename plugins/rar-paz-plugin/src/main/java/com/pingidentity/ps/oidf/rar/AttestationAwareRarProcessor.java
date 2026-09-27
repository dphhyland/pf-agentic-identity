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

import jakarta.servlet.http.HttpServletRequest;
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
 *   <li>{@link #enrich} resolves who the decision is about ({@link PrincipalResolver}), refuses the types
 *       that need a person when there is none, forwards the requested detail plus the attestation-vouched
 *       subject / entitlement / workload to the governance engine, denies unless the decision is PERMIT,
 *       and applies the returned statements (downscoping / obligations).</li>
 *   <li>{@link #isEqualOrSubset} does a real containment check (for refresh-time narrowing).</li>
 * </ul>
 *
 * <p>The attestation context is published by the client-attestation issuance hook as a request attribute
 * (see {@link AttestationSubject#REQUEST_ATTRIBUTE}) and read here via {@code context.getJakartaRequest()}.
 * All I/O and mapping logic lives in framework-agnostic collaborators so it is unit-tested without the SDK.
 */
public class AttestationAwareRarProcessor implements AuthorizationDetailProcessor {

    /** The version shown for classes loaded from a directory (a unit test, an IDE), which have no manifest. */
    static final String DEVELOPMENT_VERSION = "development";

    /**
     * The version PingFederate shows for this plugin: the {@code Implementation-Version} the build writes into
     * the jar's manifest from the pom. It used to be the literal "0.1.0", so v0.1.1 to v0.1.5 all said 0.1.0.
     */
    private static final String VERSION =
            versionOf(AttestationAwareRarProcessor.class.getPackage().getImplementationVersion());

    private static final String TYPE_NAME = "Attestation-aware RAR to PingAuthorize";

    /** Internal authorization_details field the BFF folds the authenticated principal into (survives PAR).
     *  Consumed here and stripped so it never reaches the governance engine, the consent page, or the token. */
    private static final String PRINCIPAL_DETAIL_KEY = "_principal_sub";
    /**
     * The agent instance, carried inside each entry by the attestation filter at PAR. PingFederate calls
     * {@link #enrich} from the authorisation endpoint, a browser request the filter never sees, so the
     * attestation context is not there; {@code authorization_details} is the only channel that survives
     * from PAR, and the filter overwrites whatever a client puts under this name with the agent_id it verified.
     */
    static final String AGENT_DETAIL_KEY = "_agent_id";

    private static final String PDP_DIALECT = "PDP Dialect";
    private static final String DIALECT_GOVERNANCE = "governance-engine";
    private static final String DIALECT_AUTHZEN = "authzen";
    private static final String PDP_URL = "PDP URL";
    private static final String PDP_DOMAIN_PREFIX = "PDP Domain Prefix";
    private static final String PDP_SERVICE = "PDP Service";
    private static final String PDP_ACTION = "PDP Action";
    private static final String PDP_ATTRIBUTE_PREFIX = "Attribute Prefix";
    private static final String PDP_ATTR_TYPE_PREFIX = "Prefix Attributes with Type";
    private static final String PDP_SECRET_HEADER = "Shared Secret Header";
    /**
     * Same field name as before, now declared encrypted: the value is stored obfuscated under the master key
     * and handed here in the clear, the way PingFederate treats its own client secrets. An encrypted
     * {@code TextFieldDescriptor} over a {@code SecretReferenceFieldDescriptor} because the latter holds a
     * reference into a configured secret manager, which neither the rig nor any consumer runs; S2c can offer
     * it as a second option once the platform library's secret handling exists.
     */
    static final String PDP_SECRET = "Shared Secret";
    /**
     * Gone from the descriptor: the decision is always deny-unless-PERMIT. The name is kept only so a test
     * can pin that a value stored under it is ignored. PingFederate 13.1.3 hands an instance with no parent
     * its stored configuration as it is ({@code ConfigurationUtil.createCompositeConfiguration}, javap
     * 2026-09-27), and the admin API's {@code PluginConfigTranslator} raises no error for a field the
     * descriptor does not declare (its message keys are duplicate, encrypted-value, inherited and parent,
     * javap 2026-09-27), so a stored extra is carried and never read.
     */
    static final String DENY_ON_NON_PERMIT_REMOVED = "Deny unless PERMIT";
    private static final String FAIL_OPEN = "Fail open on engine error";
    private static final String ALLOW_CLIENT_ASSERTED_PRINCIPAL = "Trust a client-asserted principal";
    private static final String TRUST_AGENT_MARKER = "Trust the PAR-carried agent marker";
    private static final String INSECURE_TLS = "Skip TLS verification (dev only)";
    private static final String TIMEOUT_MS = "Request timeout (ms)";
    static final String AUTHENTICATED_PRINCIPAL_TYPES = "Types requiring an authenticated principal";

    // What each switch reads as when its field is missing from the stored configuration, which is also what
    // the admin console offers: the secure value in every case, so a missing field never relaxes a check.
    private static final boolean PDP_ATTR_TYPE_PREFIX_DEFAULT = true;
    private static final boolean FAIL_OPEN_DEFAULT = false;
    private static final boolean ALLOW_CLIENT_ASSERTED_PRINCIPAL_DEFAULT = false;
    private static final boolean TRUST_AGENT_MARKER_DEFAULT = false;
    private static final boolean INSECURE_TLS_DEFAULT = false;

    private static final Set<String> SUPPORTED_TYPES =
            new LinkedHashSet<>(Arrays.asList("sales_agent", "payment_initiation", "account_information"));

    /**
     * More types for this deployment, beyond the three built in: {@value #EXTRA_TYPES_PROPERTY} (system
     * property) or {@value #EXTRA_TYPES_ENV}, whitespace- or comma-separated. PingFederate reads the supported
     * types from the descriptor before any instance is configured, so they cannot be an instance field.
     */
    static final String EXTRA_TYPES_PROPERTY = "oidf.rar.extra.types";
    static final String EXTRA_TYPES_ENV = "OIDF_RAR_EXTRA_TYPES";

    private final Logger log = Logger.getLogger(getClass().getName());
    private final ObjectMapper mapper = new ObjectMapper();

    private GovernanceEngineConfig config;
    private PdpClient client;

    public AttestationAwareRarProcessor() {
    }

    /**
     * Test seam: inject the collaborators {@link #configure} would otherwise build, so
     * {@link #enrich} can be exercised without a live PDP or a PingFederate {@code Configuration}.
     */
    AttestationAwareRarProcessor(PdpClient client, GovernanceEngineConfig config) {
        this.client = client;
        this.config = config;
    }

    @Override
    public void configure(Configuration configuration) {
        configure(configuration, deploymentProfile());
    }

    /** {@link #configure(Configuration)} under a named profile, so a test can be production or development at will. */
    void configure(Configuration configuration, String profile) {
        this.config = settings(configuration, profile);
        HttpTransport transport = new JdkHttpTransport(config.isInsecureTlsHonoured(), config.getTimeoutMillis());
        String dialect = configuration.getFieldValue(PDP_DIALECT);
        if (DIALECT_AUTHZEN.equalsIgnoreCase(dialect == null ? "" : dialect.trim())) {
            this.client = new AuthZenPdpClient(config, transport, new AuthZenRequestBuilder(config), mapper);
        } else {
            this.client = new GovernanceEngineClient(config, transport, new GovernanceEngineRequestBuilder(config, mapper), mapper);
        }
        if (config.isAllowClientAssertedPrincipal() && !config.isDevelopment()) {
            log.warning("'" + ALLOW_CLIENT_ASSERTED_PRINCIPAL + "' is on but " + PdpUrlPolicy.PROFILE_ENV
                    + " is not development: login_hint and " + PRINCIPAL_DETAIL_KEY + " are ignored in this deployment.");
        }
        if (config.isInsecureTls() && !config.isDevelopment()) {
            log.warning("'" + INSECURE_TLS + "' is on but " + PdpUrlPolicy.PROFILE_ENV
                    + " is not development: the PDP's certificate is checked in this deployment.");
        }
        log.info("Configured AttestationAwareRarProcessor (" + (this.client instanceof AuthZenPdpClient
                ? DIALECT_AUTHZEN : DIALECT_GOVERNANCE) + ") -> " + config.getPdpUrl() + " profile=" + config.getDeploymentProfile()
                + " authenticatedPrincipalTypes=" + config.getAuthenticatedPrincipalTypes()
                + " failOpenOnUnavailable=" + config.isFailOpenOnError());
    }

    /**
     * {@code OIDF_DEPLOYMENT_PROFILE}, read straight from the environment: unset is production. PR-1 (the
     * platform library) centralises the profile and its parsing; until then this is the one read here.
     */
    static String deploymentProfile() {
        return GovernanceEngineConfig.profileOf(System.getenv(PdpUrlPolicy.PROFILE_ENV));
    }

    /**
     * The settings an instance's configuration holds, checked against the deployment profile.
     *
     * <p>Every switch is read with its secure default, which is also the default the admin console offers. A
     * field can be missing from a stored configuration: an instance saved before the field existed, or one
     * written through the admin API or an archive that left it out. PingFederate 13.1.3 hands an instance with
     * no parent its stored configuration as it is, and fills a child instance's missing fields from the
     * descriptor's defaults ({@code ConfigurationUtil.createCompositeConfiguration}, read with javap,
     * 2026-09-26). The two defaults are the same, so either way a missing switch is the secure value. The
     * one-argument {@code getBooleanFieldValue} read a missing field as false, so a missing "Deny unless
     * PERMIT" used to turn the check off; that switch no longer exists.
     *
     * <p>The PDP URL is held to {@link PdpUrlPolicy} here as well as by the field's validator, because an
     * archive import runs no validator: a plaintext URL outside development stops the instance configuring,
     * and an instance that is not configured denies every request that reaches it.
     */
    static GovernanceEngineConfig settings(Configuration configuration, String profile) {
        return GovernanceEngineConfig.builder()
                .pdpUrl(PdpUrlPolicy.check(configuration.getFieldValue(PDP_URL), profile))
                .domainPrefix(configuration.getFieldValue(PDP_DOMAIN_PREFIX))
                .service(configuration.getFieldValue(PDP_SERVICE))
                .action(configuration.getFieldValue(PDP_ACTION))
                .attributePrefix(configuration.getFieldValue(PDP_ATTRIBUTE_PREFIX))
                .prefixAttributesWithType(configuration.getBooleanFieldValue(PDP_ATTR_TYPE_PREFIX, PDP_ATTR_TYPE_PREFIX_DEFAULT))
                .secretHeader(configuration.getFieldValue(PDP_SECRET_HEADER))
                .secret(configuration.getFieldValue(PDP_SECRET))
                .failOpenOnError(configuration.getBooleanFieldValue(FAIL_OPEN, FAIL_OPEN_DEFAULT))
                .allowClientAssertedPrincipal(configuration.getBooleanFieldValue(ALLOW_CLIENT_ASSERTED_PRINCIPAL,
                        ALLOW_CLIENT_ASSERTED_PRINCIPAL_DEFAULT))
                .trustAgentMarker(configuration.getBooleanFieldValue(TRUST_AGENT_MARKER, TRUST_AGENT_MARKER_DEFAULT))
                .insecureTls(configuration.getBooleanFieldValue(INSECURE_TLS, INSECURE_TLS_DEFAULT))
                .timeoutMillis(parseInt(configuration.getFieldValue(TIMEOUT_MS), 10_000))
                .authenticatedPrincipalTypes(GovernanceEngineConfig.authenticatedPrincipalTypesOf(
                        configuration.getFieldValue(AUTHENTICATED_PRINCIPAL_TYPES)))
                .deploymentProfile(profile)
                .build();
    }

    /** A manifest's {@code Implementation-Version}, or {@value #DEVELOPMENT_VERSION} when there is none. */
    static String versionOf(String implementationVersion) {
        return implementationVersion == null || implementationVersion.isBlank()
                ? DEVELOPMENT_VERSION : implementationVersion.trim();
    }

    @Override
    public PluginDescriptor getPluginDescriptor() {
        GuiConfigDescriptor gui = new GuiConfigDescriptor();
        gui.setDescription("Maps RFC 9396 authorization_details into a PDP decision - the native PingAuthorize "
                + "governance engine or an OpenID AuthZEN 1.0 PDP - bounded by the client attestation's entitlement. "
                + "Denies unless the decision is PERMIT.");
        addText(gui, PDP_DIALECT, "PDP dialect: governance-engine | authzen", DIALECT_GOVERNANCE, false);
        TextFieldDescriptor url = new TextFieldDescriptor(PDP_URL,
                "PDP decision URL, https (authzen: point at /access/v1/evaluation); http only when "
                        + PdpUrlPolicy.PROFILE_ENV + "=development");
        url.setDefaultValue("https://");
        url.addValidator(new RequiredFieldValidator());
        url.addValidator(new PdpUrlPolicy.Validator(deploymentProfile()));
        gui.addField(url);
        addText(gui, PDP_DOMAIN_PREFIX, "PDP domain prefix", "idpartners.authorization_details", false);
        addText(gui, PDP_SERVICE, "PDP service", "Authorization", false);
        addText(gui, PDP_ACTION, "PDP action", "authorize", false);
        addText(gui, PDP_ATTRIBUTE_PREFIX, "Attribute prefix", "idp", false);
        addCheck(gui, PDP_ATTR_TYPE_PREFIX, "Prefix attributes with detail type", PDP_ATTR_TYPE_PREFIX_DEFAULT);
        addText(gui, PDP_SECRET_HEADER, "Shared-secret header name", "CLIENT-TOKEN", false);
        TextFieldDescriptor secret = new TextFieldDescriptor(PDP_SECRET, "Shared-secret value (stored encrypted)", true);
        secret.setDefaultValue("");
        secret.addValidator(new RequiredFieldValidator());
        gui.addField(secret);
        addText(gui, AUTHENTICATED_PRINCIPAL_TYPES,
                "Detail types refused before any PDP call unless the principal is a person PingFederate authenticated "
                        + "(comma-separated; a single '-' means none)",
                String.join(",", GovernanceEngineConfig.DEFAULT_AUTHENTICATED_PRINCIPAL_TYPES), false);
        addCheck(gui, FAIL_OPEN,
                "Fail open when the PDP is unreachable (connection refused or reset, name unresolved, deadline, "
                        + "HTTP 429/502/503/504) - any other answer, a malformed one and a TLS failure still deny",
                FAIL_OPEN_DEFAULT);
        addCheck(gui, ALLOW_CLIENT_ASSERTED_PRINCIPAL,
                "Use login_hint / _principal_sub as the decision subject when no principal is known - the caller "
                        + "chooses who the decision is about; takes effect only with " + PdpUrlPolicy.PROFILE_ENV
                        + "=development, and goes at 1.0",
                ALLOW_CLIENT_ASSERTED_PRINCIPAL_DEFAULT);
        addCheck(gui, TRUST_AGENT_MARKER,
                "Where the attestation is not in the request (the authorisation endpoint), take the agent instance from the "
                        + AGENT_DETAIL_KEY + " the attestation filter put in each entry at PAR - only for clients that must use PAR",
                TRUST_AGENT_MARKER_DEFAULT);
        addCheck(gui, INSECURE_TLS, "Trust any PDP certificate - takes effect only with " + PdpUrlPolicy.PROFILE_ENV
                + "=development; the hostname is still checked", INSECURE_TLS_DEFAULT);
        addText(gui, TIMEOUT_MS, "Request timeout (ms)", "10000", false);

        AuthorizationDetailProcessorDescriptor descriptor =
                new AuthorizationDetailProcessorDescriptor(TYPE_NAME, this, gui, VERSION);
        descriptor.setSupportedAuthorizationDetailTypes(supportedTypes(
                System.getProperty(EXTRA_TYPES_PROPERTY), System.getenv(EXTRA_TYPES_ENV)));
        return descriptor;
    }

    /** The built-in types plus the deployment's extra ones; the property wins over the environment. */
    static Set<String> supportedTypes(String property, String environment) {
        Set<String> types = new LinkedHashSet<>(SUPPORTED_TYPES);
        String extra = property != null && !property.isBlank() ? property : environment;
        if (extra != null) {
            for (String type : extra.split("[,\\s]+")) {
                if (!type.isBlank()) {
                    types.add(type.trim());
                }
            }
        }
        return new HashSet<>(types);
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
        String type = authDetail.getType();
        HttpServletRequest request = requestOf(context);
        AttestationSubject subject = readSubject(request);
        // Detail on which the decision is made - a copy without the internal markers so they never reach the
        // governance engine as payload fields, the consent page, or the issued token. (The SDK's
        // AuthorizationDetail always holds a map: getType() reads it without a null check.)
        Map<String, Object> detail = new HashMap<>(authDetail.getDetail());
        Object principalInDetail = detail.remove(PRINCIPAL_DETAIL_KEY);
        Object agentInDetail = detail.remove(AGENT_DETAIL_KEY);
        if (subject.getAgentId() == null && config.isTrustAgentMarker() && agentInDetail instanceof String marked && !marked.isBlank()) {
            subject = subject.withAgentId(marked);
        }

        // Who the decision is about, and how we know. PingFederate's user key is a different thing in each
        // flow, and two caller-supplied names (login_hint, _principal_sub) are honoured only in development.
        String clientId = context == null ? null : context.getClientId();
        String userKey = context == null ? null : context.getUserKey();
        PrincipalResolver.Flow flow = flowOf(request);
        String clientAsserted = firstNonBlank(readLoginHint(request), asString(principalInDetail));
        PrincipalResolver.Principal principal = PrincipalResolver.resolve(flow, userKey, clientId, subject,
                clientAsserted, config.isClientAssertedPrincipalHonoured());
        if (notBlank(clientAsserted) && !PrincipalResolver.CLIENT_ASSERTED.equals(principal.source())
                && log.isLoggable(Level.FINE)) {
            log.fine("RAR governance: a caller-asserted principal on this request was not used for type '" + type
                    + "' (source=" + principal.source() + ")");
        }
        if (log.isLoggable(Level.INFO)) {
            // The path and the parameter NAMES say which of PingFederate's callers this was (the resume after
            // authentication passes the mapped authentication attributes; the others pass none); the values
            // are the person's and stay out of the log.
            log.info("RAR governance: type=" + type + " flow=" + describe(flow) + " path=" + flow.requestPath()
                    + " principalSource=" + principal.source()
                    + " principal=" + PrincipalResolver.hashForLog(principal.subject())
                    + " userKey=" + PrincipalResolver.hashForLog(userKey)
                    + " paramKeys=" + (parameters == null ? "-" : parameters.keySet())
                    + " attestationClient=" + subject.getClientId() + " agentId=" + subject.getAgentId()
                    + " attester=" + subject.getAttesterIssuer() + " clientId=" + clientId);
        }
        if (PrincipalResolver.requiresAuthenticatedPrincipal(type, principal, config.getAuthenticatedPrincipalTypes())) {
            throw new AuthorizationDetailProcessingException("authorization_details of type '" + type
                    + "' needs an authenticated principal and this request has " + principal.source()
                    + " (flow " + describe(flow) + "); refused before any PDP call");
        }

        try {
            DecisionResponse decision = client.decide(type, detail, subject, principal.subject(), clientId, principal.source());
            if (!decision.isPermit()) {
                throw new AuthorizationDetailProcessingException(
                        "governance engine denied authorization_details of type '" + type
                                + "' (decision=" + decision.getDecision() + ")");
            }
            Map<String, Object> enriched = new HashMap<>(detail);
            StatementApplier.apply(decision.getStatements(), enriched, mapper);
            authDetail.setDetail(enriched);
            return authDetail;
        } catch (AuthorizationDetailProcessingException e) {
            throw e;
        } catch (PdpUnavailableException e) {
            if (config.isFailOpenOnError()) {
                log.log(Level.WARNING, "PDP unreachable; failing open for type '" + type
                        + "' as configured (principal=" + PrincipalResolver.hashForLog(principal.subject()) + ")", e);
                // Grant the cleaned copy, not the original: the markers must be stripped on this path too, or
                // failing open leaks them into the consent page and the issued token.
                authDetail.setDetail(detail);
                return authDetail;
            }
            throw new AuthorizationDetailProcessingException("PDP unreachable for type '" + type + "'", e);
        } catch (Exception e) {
            // A PDP that answered and could not be believed, a body that did not parse, a TLS failure, a detail
            // field that collided with a server attribute: none of these is "unreachable", and none is a permit.
            // The WARNING line quotes the failure with the principal hashed, because a PDP's error body can name
            // whom it was asked about; the exception with its stack goes to FINE.
            log.warning("PDP call failed for type '" + type + "'; refusing (principal="
                    + PrincipalResolver.hashForLog(principal.subject()) + "): "
                    + PrincipalResolver.redact(String.valueOf(e), principal.subject(), userKey));
            log.log(Level.FINE, "PDP call failure for type '" + type + "'", e);
            throw new AuthorizationDetailProcessingException(
                    "governance engine call failed for type '" + type + "'", e);
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
        if (detail == null) {
            return "";
        }
        // Attribute-focused consent: show ONLY the meaningful authorization_details fields the user is
        // actually approving — friendly labels, amount + currency combined, one per line. Bookkeeping
        // fields are dropped: 'type'/'purpose' duplicate the RAR type, the markers are internal.
        StringBuilder sb = new StringBuilder();
        Object amount = detail.get("amount");
        if (amount != null) {
            Object currency = detail.get("currency");
            line(sb, "Amount", currency == null ? String.valueOf(amount) : (amount + " " + currency));
        }
        line(sb, "From account", detail.get("debtorAccount"));
        line(sb, "To account", detail.get("creditorAccount"));
        line(sb, "Payee", detail.get("creditorName"));
        // Any remaining non-bookkeeping fields, so the description stays complete for other RAR types.
        Set<String> handled = Set.of("type", "purpose", PRINCIPAL_DETAIL_KEY, AGENT_DETAIL_KEY, "amount", "currency",
                "debtorAccount", "creditorAccount", "creditorName");
        for (Map.Entry<String, Object> e : detail.entrySet()) {
            if (!handled.contains(e.getKey())) {
                line(sb, prettyLabel(e.getKey()), e.getValue());
            }
        }
        return sb.toString().trim();
    }

    /**
     * The flow this request is, from what the servlet request says: the {@code grant_type} parameter at the
     * token endpoint, and the request path (PingFederate's CIBA backchannel endpoint is the one place the user
     * key is a hint). Absent a request - some tests, and nothing PingFederate does - the flow is unknown, and
     * the resolver treats the user key as a person unless it is the client id.
     */
    static PrincipalResolver.Flow flowOf(HttpServletRequest request) {
        if (request == null) {
            return PrincipalResolver.Flow.UNKNOWN;
        }
        String grantType;
        String path;
        try {
            grantType = request.getParameter("grant_type");
            path = request.getRequestURI();
        } catch (RuntimeException e) {
            return PrincipalResolver.Flow.UNKNOWN;
        }
        return new PrincipalResolver.Flow(grantType == null || grantType.isBlank() ? null : grantType.trim(), path);
    }

    private static String describe(PrincipalResolver.Flow flow) {
        if (flow.isCiba()) {
            return "ciba";
        }
        return flow.grantType() == null ? "authorization-endpoint" : flow.grantType();
    }

    private HttpServletRequest requestOf(AuthorizationDetailContext context) {
        try {
            return context == null ? null : context.getJakartaRequest();
        } catch (Exception e) {
            log.log(Level.WARNING, "could not read the request from the context", e);
            return null;
        }
    }

    private AttestationSubject readSubject(HttpServletRequest request) {
        try {
            if (request != null) {
                return AttestationSubject.fromAttribute(request.getAttribute(AttestationSubject.REQUEST_ATTRIBUTE));
            }
        } catch (Exception e) {
            log.log(Level.WARNING, "could not read attestation context from request", e);
        }
        return AttestationSubject.empty();
    }

    /**
     * The {@code login_hint} request parameter. A hint, as the name says: whatever the caller put in the
     * query string, and used only in development with the switch on ({@link PrincipalResolver}).
     */
    private String readLoginHint(HttpServletRequest request) {
        try {
            if (request != null) {
                String hint = request.getParameter("login_hint");
                if (hint != null && !hint.isBlank()) {
                    return hint;
                }
            }
        } catch (Exception e) {
            log.log(Level.WARNING, "could not read login_hint from request", e);
        }
        return null;
    }

    private static boolean notBlank(String v) {
        return v != null && !v.isBlank();
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

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    private static String asString(Object o) {
        if (o == null) {
            return null;
        }
        String s = String.valueOf(o);
        return s.isBlank() ? null : s;
    }

    private static void line(StringBuilder sb, String label, Object value) {
        if (value != null && !String.valueOf(value).isBlank()) {
            sb.append(label).append(": ").append(value).append('\n');
        }
    }

    private static String prettyLabel(String key) {
        String s = key.replace('_', ' ').trim();
        return s.isEmpty() ? key : Character.toUpperCase(s.charAt(0)) + s.substring(1);
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
