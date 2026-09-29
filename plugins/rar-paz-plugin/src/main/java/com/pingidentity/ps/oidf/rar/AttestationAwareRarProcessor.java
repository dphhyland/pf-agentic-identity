/*
 * PingFederate AuthorizationDetailProcessor that delegates the RFC 9396 decision to a PingAuthorize
 * governance engine, bounded by the client attestation's entitlement.
 */
package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessor;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessorDescriptor;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailValidationResult;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.SelectFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextAreaFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
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
 *   <li>{@link #enrich} resolves who the decision is about ({@link PrincipalResolver}), holds the requested
 *       detail to the RAR containment model, refuses the types that need a person when there is none, forwards
 *       the requested detail plus the attestation-vouched subject / entitlement / workload to the governance
 *       engine, denies unless the decision is PERMIT, applies the returned statements (downscoping /
 *       obligations), and refuses a result the model does not find within the request: the PDP may narrow,
 *       never widen.</li>
 *   <li>{@link #isEqualOrSubset} is the model's strict {@code contains} (refresh-time narrowing).</li>
 * </ul>
 *
 * <p>Every containment question goes to {@code libs/rar-model}, shaded into this jar, through {@link ModelGate}.
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
     *  Consumed here and stripped so it never reaches the model, the governance engine, the consent page, or the
     *  token. */
    private static final String PRINCIPAL_DETAIL_KEY = ModelGate.PRINCIPAL_MARKER;
    /**
     * The agent instance, carried inside each entry by the attestation filter at PAR. PingFederate calls
     * {@link #enrich} from the authorisation endpoint, a browser request the filter never sees, so the
     * attestation context is not there; {@code authorization_details} is the only channel that survives
     * from PAR, and the filter overwrites whatever a client puts under this name with the agent_id it verified.
     */
    static final String AGENT_DETAIL_KEY = ModelGate.AGENT_MARKER;

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
     * descriptor does not declare (its keys: duplicate, bad encrypted value, inherited, parent, empty entry;
     * javap 2026-09-27). On the rig a 0.3.0 archive holding it imported and the instance decided (2026-09-27).
     */
    static final String DENY_ON_NON_PERMIT_REMOVED = "Deny unless PERMIT";
    private static final String FAIL_OPEN = "Fail open on engine error";
    private static final String ALLOW_CLIENT_ASSERTED_PRINCIPAL = "Trust a client-asserted principal";
    private static final String TRUST_AGENT_MARKER = "Trust the PAR-carried agent marker";
    private static final String INSECURE_TLS = PdpTransport.INSECURE_TLS_SETTING;
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

    private final ModelGate gate;
    private GovernanceEngineConfig config;
    private PdpClient client;
    private HttpTransport transport;
    private PdpDecisions decisions;
    private CircuitBreaker breaker;
    /** The request attribute this instance's per-request memo lives under: one per instance, so two never share. */
    private final String memoAttribute = AttestationAwareRarProcessor.class.getName() + ".memo." + System.identityHashCode(this);

    /** What PingFederate calls: the process's RAR model set, read from the environment once per classloader. */
    public AttestationAwareRarProcessor() {
        this.gate = ModelGate.process();
    }

    /**
     * Test seam: inject the collaborators {@link #configure} would otherwise build, so
     * {@link #enrich} can be exercised without a live PDP or a PingFederate {@code Configuration}. The model set is
     * the built-in one with production semantics, whatever the test's environment says.
     */
    AttestationAwareRarProcessor(PdpClient client, GovernanceEngineConfig config) {
        this(client, config, ModelGate.of(RarModels.builtIn()));
    }

    /** Test seam with a model set of the test's choosing: a models document, the development fallback, none. */
    AttestationAwareRarProcessor(PdpClient client, GovernanceEngineConfig config, ModelGate gate) {
        this.client = client;
        this.config = config;
        this.gate = gate;
        this.decisions = client == null ? null : new PdpDecisions(client, null, null, memoAttribute);
    }

    /** Test seam with the PDP step of the test's choosing: a decision cache, a batch URL. */
    AttestationAwareRarProcessor(PdpDecisions decisions, GovernanceEngineConfig config, ModelGate gate) {
        this(decisions.client(), config, gate);
        this.decisions = decisions;
    }

    /** The per-request memo's attribute name, for a test that looks at the request. */
    String memoAttribute() {
        return memoAttribute;
    }

    @Override
    public void configure(Configuration configuration) {
        configure(configuration, deploymentProfile());
    }

    /** {@link #configure(Configuration)} under a named profile, so a test can be production or development at will. */
    void configure(Configuration configuration, String profile) {
        GovernanceEngineConfig settings = settings(configuration, profile);
        String dialect = configuration.getFieldValue(PDP_DIALECT);
        boolean authzen = DIALECT_AUTHZEN.equalsIgnoreCase(dialect == null ? "" : dialect.trim());
        PdpResilience resilience = PdpResilience.of(configuration, profile, authzen, settings.getAuthenticatedPrincipalTypes());
        CircuitBreaker newBreaker = new CircuitBreaker(resilience.breakerFailures(), resilience.breakerOpenSeconds());
        HttpTransport newTransport = new CircuitBreaker.Guarded(
                new PdpTransport(tlsOf(settings, resilience), settings.getTimeoutMillis(), settings.isDevelopment()), newBreaker);
        PdpClient newClient = authzen
                ? new AuthZenPdpClient(settings, newTransport, new AuthZenRequestBuilder(settings), mapper, resilience.batchUrl())
                : new GovernanceEngineClient(settings, newTransport, new GovernanceEngineRequestBuilder(settings, mapper), mapper);
        DecisionCache cache = resilience.cacheTypes().isEmpty() ? null
                : new DecisionCache(resilience.cacheTypes(), resilience.cacheTtlSeconds());
        this.config = settings;
        this.transport = newTransport;
        this.breaker = newBreaker;
        this.client = newClient;
        this.decisions = new PdpDecisions(newClient, cache,
                settings.getPdpUrl() + "\n" + (gate.loaded() ? gate.fingerprint() : "-"), memoAttribute);
        PdpMetrics.track(newBreaker);
        if (config.isAllowClientAssertedPrincipal() && !config.isDevelopment()) {
            log.warning("'" + ALLOW_CLIENT_ASSERTED_PRINCIPAL + "' is on but " + PdpUrlPolicy.PROFILE_ENV
                    + " is not development: login_hint and " + PRINCIPAL_DETAIL_KEY + " are ignored in this deployment.");
        }
        if (config.isInsecureTls() && !config.isDevelopment()) {
            log.warning("'" + INSECURE_TLS + "' is on but " + PdpUrlPolicy.PROFILE_ENV
                    + " is not development: the PDP's certificate is checked in this deployment.");
        }
        if (!gate.loaded()) {
            log.severe("This instance refuses every authorization_details request: " + gate.loadFailure());
        }
        log.info("Configured AttestationAwareRarProcessor (" + (this.client instanceof AuthZenPdpClient
                ? DIALECT_AUTHZEN : DIALECT_GOVERNANCE) + ") -> " + config.getPdpUrl() + " profile=" + config.getDeploymentProfile()
                + " authenticatedPrincipalTypes=" + config.getAuthenticatedPrincipalTypes()
                + " failOpenOnUnavailable=" + config.isFailOpenOnError()
                + " rarModels=" + (gate.loaded() ? gate.fingerprint() : "not loaded")
                + " tlsTrust=" + pdpTransport().tls().mode()
                + " totalMillis=" + PdpTransport.totalMillisOf(config.getTimeoutMillis())
                + " batch=" + (resilience.batchUrl() != null)
                + " cacheTypes=" + resilience.cacheTypes()
                + " breaker=" + resilience.breakerFailures() + "/" + resilience.breakerOpenSeconds() + "s");
    }

    /**
     * The trust for the PDP's certificate: the development-only switch first (any chain; honoured only in
     * development), then the instance's choice. PingFederate's trusted CAs are read on each call, not here, so this
     * never touches PingFederate's services at configure time.
     */
    static PdpTls tlsOf(GovernanceEngineConfig settings, PdpResilience resilience) {
        if (settings.isInsecureTlsHonoured()) {
            return PdpTls.insecure(INSECURE_TLS);
        }
        switch (resilience.tlsMode()) {
            case PdpTls.PINGFEDERATE_TRUSTED_CAS:
                return PdpTls.pingFederate(TRUSTED_CAS);
            case PdpTls.PINNED_CA:
                try {
                    return PdpTls.pinned(resilience.pinnedPem());
                } catch (java.security.GeneralSecurityException | java.io.IOException e) {
                    throw new IllegalStateException(PdpResilience.PINNED_CAS + " could not be used: " + e.getMessage(), e);
                }
            default:
                return PdpTls.jvmDefault();
        }
    }

    /**
     * PingFederate's trust anchors, through the SDK's accessor: {@code com.pingidentity.access.TrustedCAAccessor} is
     * public in pingfederate-sdk 13.1.3.0 ({@code public java.util.Set<java.security.cert.TrustAnchor>
     * getAllTrustAnchors()}, javap 2026-09-29) and resolves PingFederate's {@code TrustedCAAccessorService} each time.
     */
    static final java.util.function.Supplier<Set<java.security.cert.TrustAnchor>> TRUSTED_CAS =
            () -> new com.pingidentity.access.TrustedCAAccessor().getAllTrustAnchors();

    /** The platform transport under the breaker {@link #configure} built, or {@code null} before it ran. */
    PdpTransport pdpTransport() {
        return transport instanceof CircuitBreaker.Guarded guarded ? (PdpTransport) guarded.delegate() : null;
    }

    /** The circuit breaker {@link #configure} built, or {@code null} before it ran. */
    CircuitBreaker breaker() {
        return breaker;
    }

    /** The PDP step {@link #configure} built. */
    PdpDecisions decisions() {
        return decisions;
    }

    /** The transport {@link #configure} built, or {@code null} before it ran: for a test of what it trusts. */
    HttpTransport transport() {
        return transport;
    }

    /**
     * This process's profile, as platform's {@link DeploymentProfile} reads {@code OIDF_DEPLOYMENT_PROFILE}
     * (plan item PR-1): unset is production. The one read here.
     */
    static String deploymentProfile() {
        return DeploymentProfile.current().value();
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
                .timeoutMillis(PdpTransport.totalMillisOf(parseInt(configuration.getFieldValue(TIMEOUT_MS), PdpTransport.DEFAULT_TOTAL_MILLIS)))
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
        addText(gui, TIMEOUT_MS, "The PDP call's total deadline in milliseconds, connecting to the last byte of the answer ("
                + PdpTransport.MIN_TOTAL_MILLIS + "-" + PdpTransport.MAX_TOTAL_MILLIS + "); past it the PDP counts as unreachable",
                String.valueOf(PdpTransport.DEFAULT_TOTAL_MILLIS), false);
        SelectFieldDescriptor tls = new SelectFieldDescriptor(PdpResilience.TLS_TRUST,
                "How the PDP's certificate is trusted: the JVM's CAs, PingFederate's trusted CAs (which include the JVM's),"
                        + " or only the CAs pasted below. The certificate must name the PDP URL's host in every case",
                PdpTls.MODES.toArray(new String[0]));
        tls.setDefaultValue(PdpTls.JVM_DEFAULT);
        gui.addField(tls);
        TextAreaFieldDescriptor pinned = new TextAreaFieldDescriptor(PdpResilience.PINNED_CAS,
                "The CA certificates (PEM) to trust the PDP with when " + PdpResilience.TLS_TRUST + " is " + PdpTls.PINNED_CA,
                6, 64);
        pinned.setDefaultValue("");
        gui.addField(pinned);
        addText(gui, PdpResilience.BATCH_URL, "authzen only: the PDP's Access Evaluations URL (/access/v1/evaluations);"
                + " when set, a request's details are decided in one call. Blank: one call per detail", "", false);
        addText(gui, PdpResilience.CACHE_TYPES, "Detail types whose PDP decisions may be reused for up to the TTL"
                + " (comma-separated; blank means none). Never payment_initiation or a type requiring an authenticated principal",
                "", false);
        addText(gui, PdpResilience.CACHE_TTL, "How long a cached decision is reused, in seconds (1-" + DecisionCache.MAX_TTL_SECONDS + ")",
                String.valueOf(DecisionCache.DEFAULT_TTL_SECONDS), false);
        addText(gui, PdpResilience.BREAKER_FAILURES, "Transport failures in a row that open the circuit breaker, after which"
                + " the PDP is not called and counts as unreachable", String.valueOf(CircuitBreaker.DEFAULT_THRESHOLD), false);
        addText(gui, PdpResilience.BREAKER_OPEN, "Seconds the circuit breaker stays open before one trial call",
                String.valueOf(CircuitBreaker.DEFAULT_OPEN_SECONDS), false);
        gui.addValidator(new PdpResilience.Validator(deploymentProfile(), PDP_DIALECT, DIALECT_AUTHZEN, AUTHENTICATED_PRINCIPAL_TYPES));

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
        if (config == null || client == null) {
            // configure threw - a plaintext PDP URL outside development, say - or never ran. Refused as a
            // processing failure, which PingFederate answers with invalid_authorization_details, rather than
            // left to a NullPointerException below.
            throw new AuthorizationDetailProcessingException("the processor for type '" + type
                    + "' is not configured; see its configure error in the server log");
        }
        if (!gate.loaded()) {
            // The models document did not load, so the model cannot answer and nothing is decided (ModelGate).
            throw new AuthorizationDetailProcessingException("the processor for type '" + type
                    + "' has no RAR model to hold it to; see the RAR models line in the server log");
        }
        HttpServletRequest request = requestOf(context);
        AttestationSubject requestSubject = readSubject(request);
        Prepared prepared = prepare(type, authDetail.getDetail(), context, request, requestSubject, parameters, false);
        Map<String, Object> detail = prepared.detail();
        PrincipalResolver.Principal principal = prepared.principal();
        String userKey = prepared.userKey();

        try {
            DecisionResponse decision = decisions.decide(request, prepared.ask(type),
                    () -> batchCandidates(context, request, requestSubject, parameters));
            if (!decision.isPermit()) {
                throw new AuthorizationDetailProcessingException(
                        "governance engine denied authorization_details of type '" + type
                                + "' (decision=" + decision.getDecision() + ")");
            }
            // The grant is built on a copy of its own: StatementApplier writes into nested maps in place, and the
            // request the grant is compared with must stay the one the PDP was asked about.
            Map<String, Object> enriched = ModelGate.deepCopy(detail);
            StatementApplier.apply(decision.getStatements(), enriched, mapper);
            ModelGate.Verdict narrowed = gate.within(detail, enriched);
            if (!narrowed.contained()) {
                // The PDP may narrow a request, never widen it. What its statements wrote is not repeated: the
                // model's message names a field, never a value.
                String why = narrowed.isRefused()
                        ? "the model cannot compare it with the request (" + narrowed.reason() + "): " + narrowed.refusal()
                        : "it is not within the request";
                log.warning("RAR governance: refusing the PDP's answer for type '" + type + "': " + why
                        + " (principal=" + PrincipalResolver.hashForLog(principal.subject()) + ")");
                throw new AuthorizationDetailProcessingException("the PDP's answer for authorization_details of type '"
                        + type + "' is refused, because a PDP may narrow a request and never widen it: " + why);
            }
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
            // A PDP's error body can name whom it was asked about, and PingFederate 13.1.3 logs a processor's
            // exception with every cause at ERROR (seen on the rig, 2026-09-27). So the failure travels as text
            // with the principal hashed, in this line and in the exception, and the original is not chained.
            String failure = PrincipalResolver.redact(describe(e), principal.subject(), userKey);
            log.warning("PDP call failed for type '" + type + "'; refusing (principal="
                    + PrincipalResolver.hashForLog(principal.subject()) + "): " + failure);
            throw new AuthorizationDetailProcessingException(
                    "governance engine call failed for type '" + type + "': " + failure);
        }
    }

    /**
     * What {@link #enrich} asks the PDP about one detail: the stripped copy the decision is made on, the attestation
     * context (with the PAR-carried agent where that is trusted), the principal and how it was established.
     */
    private record Prepared(Map<String, Object> detail, AttestationSubject subject, PrincipalResolver.Principal principal,
                            String clientId, String userKey) {
        PdpDecisions.Ask ask(String type) {
            return new PdpDecisions.Ask(type, detail, subject, principal.subject(), clientId, principal.source());
        }
    }

    /**
     * The steps before the PDP call, for one detail: strip the markers, resolve the principal, and refuse - before any
     * PDP call - a model-set mismatch, a detail the model does not accept and a type that needs an authenticated
     * principal it does not have. {@link #enrich} runs it on the detail PingFederate hands it; the batch runs it,
     * {@code quiet}, on each detail the request carries, so the batch never asks the PDP a question {@code enrich}
     * would have refused.
     */
    private Prepared prepare(String type, Map<String, Object> raw, AuthorizationDetailContext context,
                             HttpServletRequest request, AttestationSubject requestSubject, Map<String, Object> parameters,
                             boolean quiet) throws AuthorizationDetailProcessingException {
        AttestationSubject subject = requestSubject;
        // Detail on which the decision is made - a copy without the internal markers, so they never reach the
        // model, the governance engine as payload fields, the consent page, or the issued token. Their values are
        // read first, for the principal resolver and the agent below. (The SDK's AuthorizationDetail always
        // holds a map: getType() reads it without a null check.)
        Object principalInDetail = raw.get(PRINCIPAL_DETAIL_KEY);
        Object agentInDetail = raw.get(AGENT_DETAIL_KEY);
        Map<String, Object> detail = ModelGate.strip(raw);
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
        if (!quiet && notBlank(clientAsserted) && !PrincipalResolver.CLIENT_ASSERTED.equals(principal.source())
                && log.isLoggable(Level.FINE)) {
            log.fine("RAR governance: a caller-asserted principal on this request was not used for type '" + type
                    + "' (source=" + principal.source() + ")");
        }
        if (!quiet && log.isLoggable(Level.INFO)) {
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
        // The attestation filter and this plugin must hold requests to one model: a context the filter published
        // names its model set by fingerprint. No context at all is a request the filter did not verify, decided
        // as before the model (the PDP sees no attested ceiling).
        String mismatch = gate.fingerprintProblem(subject);
        if (mismatch != null) {
            if (!quiet) {
                log.warning("RAR governance: refusing type '" + type + "' before any PDP call: " + mismatch);
            }
            throw new AuthorizationDetailProcessingException("authorization_details of type '" + type
                    + "' refused before any PDP call: " + mismatch);
        }
        // A detail the model cannot compare is refused here rather than decided: an unmodelled type, an undeclared
        // field, a value of the wrong shape (RFC 9396 section 5). Neither the PDP nor the fail-open path below is
        // ever handed one, so whatever is granted is something the refresh check can compare later.
        try {
            gate.check(detail);
        } catch (RarModelException e) {
            throw new AuthorizationDetailProcessingException("authorization_details of type '" + type
                    + "' is not one this processor's RAR model accepts (" + e.reason() + "): " + e.getMessage()
                    + "; refused before any PDP call");
        }
        if (PrincipalResolver.requiresAuthenticatedPrincipal(type, principal, config.getAuthenticatedPrincipalTypes())) {
            throw new AuthorizationDetailProcessingException("authorization_details of type '" + type
                    + "' needs an authenticated principal and this request has " + principal.source()
                    + " (flow " + describe(flow) + "); refused before any PDP call");
        }

        return new Prepared(detail, subject, principal, clientId, userKey);
    }

    /**
     * Every other detail the request carries that this processor would ask the PDP about, for an AuthZEN batch: the
     * {@code authorization_details} parameter of the request PingFederate passed (the token endpoint's and CIBA's
     * requests carry it; at the authorization endpoint PingFederate reads the details from the pushed request, the
     * parameter is not there, and each detail is asked on its own). An entry that is not an object, has no type, or
     * that {@link #prepare} refuses - another processor's type, one the model does not accept - is left out: it is
     * never sent to this PDP in a batch.
     */
    List<PdpDecisions.Ask> batchCandidates(AuthorizationDetailContext context, HttpServletRequest request,
                                           AttestationSubject requestSubject, Map<String, Object> parameters) {
        List<PdpDecisions.Ask> asks = new ArrayList<>();
        String param;
        try {
            param = request == null ? null : request.getParameter("authorization_details");
        } catch (RuntimeException e) {
            return asks;
        }
        if (param == null || param.isBlank()) {
            return asks;
        }
        JsonNode root;
        try {
            root = mapper.readTree(param);
        } catch (java.io.IOException e) {
            return asks;
        }
        if (!root.isArray()) {
            // Jackson reads blank text as a missing node, never null; the blank case returned above anyway.
            return asks;
        }
        for (JsonNode entry : root) {
            if (!entry.isObject() || !entry.path("type").isTextual() || entry.path("type").asText().isBlank()) {
                continue;
            }
            String type = entry.path("type").asText();
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> raw = mapper.convertValue(entry, Map.class);
                asks.add(prepare(type, raw, context, request, requestSubject, parameters, true).ask(type));
            } catch (AuthorizationDetailProcessingException | IllegalArgumentException e) {
                // Not one this processor would ask about: its own enrich, if PingFederate calls it, says why.
            }
        }
        return asks;
    }

    /**
     * Whether a refresh's detail stays within the detail already granted: the RAR model's strict {@code contains},
     * the grant as the ceiling (CAS section 7 rule 1). A field the grant constrains and the refresh leaves out is not
     * contained, and every field of both is compared by its type's rule, amounts and accounts included.
     *
     * <p>What PingFederate 13.1.3 does around this call, read with {@code javap} on 2026-09-27
     * ({@code RefreshTokenGrantProcessor.processGrant}, {@code AuthorizationDetailsServiceImpl} and
     * {@code AuthorizationDetailsUtil}): only a refresh that carries {@code authorization_details} is compared with
     * its grant. The requested details are enriched first, with the grant's user key, then each must be within some
     * stored detail of the same type ({@code allMatch} over the request, {@code anyMatch} over the grant, the type
     * compared by PingFederate before this method is called), with a context that carries the request, the client id
     * and the scope and no user key, and an empty parameter map. PingFederate passes copies of both details; a
     * {@code false}, or an {@link AuthorizationDetailProcessingException}, makes it answer
     * {@code invalid_authorization_details}. A refresh without the parameter reissues the stored details and the PDP
     * is not asked. This method is then called only where approved consent is reused ("bypass authorization for
     * approved consents" on, and a client that does not bypass the approval page), through
     * {@code OAuthConsentManagerDefaultImpl.isGranted}: the stored details against the user's consent, and a
     * {@code false} revokes the grant. That caller, like PingFederate's grant-reuse lookups, passes a context with no
     * request, so there is no attestation context to compare.
     */
    @Override
    public boolean isEqualOrSubset(AuthorizationDetail requested, AuthorizationDetail accepted,
                                   AuthorizationDetailContext context, Map<String, Object> parameters) {
        ModelGate.Verdict verdict = refreshVerdict(requested, accepted, context);
        if (!verdict.contained()) {
            log.info("RAR refresh: a requested authorization_details entry is not within the grant it was compared with"
                    + (verdict.isRefused() ? "; refused: " + verdict.refusal() : ""));
        }
        return verdict.contained();
    }

    /**
     * {@link #isEqualOrSubset}'s answer with its reason: the fingerprint comparison first, when the refresh request
     * carries an attestation context, then the model's {@code contains} over the two details without their
     * bookkeeping markers. A missing detail, like any question the model cannot answer, is a refusal.
     */
    ModelGate.Verdict refreshVerdict(AuthorizationDetail requested, AuthorizationDetail accepted,
                                     AuthorizationDetailContext context) {
        String mismatch = gate.fingerprintProblem(readSubject(requestOf(context)));
        if (mismatch != null) {
            return ModelGate.Verdict.refused(null, mismatch);
        }
        Map<String, Object> asked = requested == null ? null : ModelGate.strip(requested.getDetail());
        Map<String, Object> granted = accepted == null ? null : ModelGate.strip(accepted.getDetail());
        return gate.within(granted, asked);
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

    /**
     * A failure and up to three of its causes, as {@code toString()}s: what a stack trace would have said first.
     * Bounded, because a cycle of causes longer than one is constructible.
     */
    static String describe(Throwable failure) {
        StringBuilder text = new StringBuilder(String.valueOf(failure));
        Throwable cause = failure.getCause();
        for (int depth = 0; cause != null && depth < 3; cause = cause.getCause(), depth++) {
            text.append(" <- ").append(cause);
        }
        return text.toString();
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
