package com.pingidentity.ps.oidf.pf;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import com.pingidentity.ps.oidf.federation.TrustAnchor;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.TrustMarkPolicy;
import com.pingidentity.ps.oidf.trustmark.TrustMarkClaims;
import com.pingidentity.ps.oidf.trustmark.TrustMarkType;

/**
 * The deployment-wide federation settings, resolved once from the process environment.
 *
 * <p>These values are a property of the <em>deployment</em>, not of any one servlet: the OGNL
 * issuance criterion, the token-endpoint filters and the registration servlet all need the same
 * trust controller. They used to live in three {@code public static} fields on
 * {@code RegistrationConfiguration}, written as a side effect of its constructor — so whichever
 * component happened to initialise last won, and until something had initialised at all the values
 * were {@code ""}, which makes {@code knownTrustAnchor} empty and fails every attestation. Two
 * components wrote them with different meanings (one passed the bare host as the base URL), and each
 * reader had grown its own env-var fallback to paper over the ordering. This class is that fallback,
 * promoted to the only source: computed once, immutable, identical for every reader, and unaffected
 * by initialisation order.
 *
 * <p>Resolution is system property first, then environment variable — the same precedence the rest of
 * the codebase uses, so a JVM flag can override a container variable without a redeploy.
 */
public final class FederationRuntimeConfig {

    /** The trust controller's bare federation identity, for {@code knownTrustAnchor} matching. */
    public static final String HOST_ENV = "OIDF_FEDERATION_TRUST_CONTROLLER_HOST";
    /** The HTTP base actually used to reach the trust controller (may carry a context path). */
    public static final String BASE_URL_ENV = "OIDF_FEDERATION_TRUST_CONTROLLER_BASE_URL";
    /**
     * The trust controller's public Federation Entity Keys as a JWK Set document - the {@code jwks}
     * claim of its entity configuration, captured once at provisioning time. Required whenever
     * {@link #HOST_ENV} is set: OpenID Federation 1.0 §4 distributes a Trust Anchor's keys out of
     * band, and until this existed the anchor was whoever answered HTTPS at the host.
     */
    public static final String TRUST_ANCHOR_JWKS_ENV = "OIDF_FEDERATION_TRUST_ANCHOR_JWKS";
    public static final String IGNORE_SSL_ENV = "OIDF_FEDERATION_IGNORE_SSL_ERRORS";
    /** The bridge private JWK: what {@code attest_jwt_client_auth} is translated INTO for PF. */
    public static final String BRIDGE_KEY_ENV = "OIDF_BRIDGE_PRIVATE_JWK";
    /** Public half of a superseded bridge key, kept in client JWKS during a rotation overlap. */
    public static final String BRIDGE_PREVIOUS_PUBLIC_KEY_ENV = "OIDF_BRIDGE_PREVIOUS_PUBLIC_JWK";
    /** Default true: without the bridge key, attestation authentication silently does nothing. */
    public static final String REQUIRE_BRIDGE_KEY_ENV = "OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY";
    /**
     * Default true. Whether a client whose bridge-key entry names no {@code attesters} is refused at the
     * token endpoint. Trust in an attester is federation-wide; the binding is what says WHICH clients
     * it may vouch for. {@code false} lets an unbound client accept any trusted attester - an explicit
     * binding is still enforced.
     */
    public static final String REQUIRE_ATTESTER_BINDING_ENV = "OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING";
    /**
     * Default true: refuse to register a federation client whose metadata no superior constrained.
     * A trust chain may legally carry no {@code metadata_policy}, in which case the leaf's own
     * self-published {@code scope}, {@code grant_types} and {@code response_types} are what it gets.
     */
    public static final String REQUIRE_METADATA_POLICY_ENV = "OIDF_REQUIRE_METADATA_POLICY";

    /**
     * The longest a federation registration lives, in seconds (default 86400). OpenID Federation 1.0 §12.3:
     * a registration "MUST NOT exceed the lifetime of the Trust Chain" - it gets the shorter of the two.
     */
    public static final String REGISTRATION_MAX_TTL_ENV = "OIDF_REGISTRATION_MAX_TTL_SECONDS";
    /** A chain that would leave a registration less than this many seconds (default 60) is refused. */
    public static final String REGISTRATION_MIN_TTL_ENV = "OIDF_REGISTRATION_MIN_TTL_SECONDS";
    /** How long before expiry a registration is re-validated at the token endpoint (default 300). */
    public static final String REGISTRATION_REFRESH_BEFORE_EXPIRY_ENV = "OIDF_REGISTRATION_REFRESH_BEFORE_EXPIRY_SECONDS";
    /** What an expired registration that cannot be renewed gets: {@code refuse} (default), {@code disable} or {@code log}. */
    public static final String REGISTRATION_EXPIRY_ENFORCEMENT_ENV = "OIDF_REGISTRATION_EXPIRY_ENFORCEMENT";
    /** How often expired federation clients are disabled, in seconds (default 300; 0 turns the sweep off). */
    public static final String REGISTRATION_SWEEP_INTERVAL_ENV = "OIDF_REGISTRATION_SWEEP_INTERVAL_SECONDS";
    /**
     * Default true: a token request whose automatic registration fails is refused with the reason, rather
     * than passed on for PingFederate to refuse (or, for a client registered before, to accept) without it.
     */
    public static final String AUTO_REGISTRATION_FAIL_CLOSED_ENV = "OIDF_AUTO_REGISTRATION_FAIL_CLOSED";
    /** Automatic registration at the authorization and PAR endpoints (OpenID Federation 1.0 §12.1.1): default true. */
    public static final String AUTO_REGISTRATION_FRONT_CHANNEL_ENV = "OIDF_AUTO_REGISTRATION_FRONT_CHANNEL";
    /**
     * How a refusal at the authorization endpoint is answered: {@code page} (default), this module's error page -
     * never a redirect (§12.1.3) - or {@code passthrough}, leaving the request to PingFederate's own error handling.
     */
    public static final String AUTO_REGISTRATION_AUTHZ_ERROR_MODE_ENV = "OIDF_AUTO_REGISTRATION_AUTHZ_ERROR_MODE";
    /**
     * {@code allow} (default) or {@code refuse} registration from an encrypted request object. Only its header can be
     * read before PingFederate decrypts it, so its claims are checked, and its signature verified, only by
     * PingFederate, after the client is registered.
     */
    public static final String AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS_ENV = "OIDF_AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS";
    /** The scopes an RP that declares none is registered with (default {@code openid}). */
    public static final String AUTO_REGISTRATION_DEFAULT_SCOPES_ENV = "OIDF_AUTO_REGISTRATION_DEFAULT_SCOPES";
    /** Every RP registered at the front channel must use PAR (default false; an RP can ask for it in its metadata). */
    public static final String AUTO_REGISTRATION_REQUIRE_PAR_ENV = "OIDF_AUTO_REGISTRATION_REQUIRE_PAR";
    /** Every RP registered at the front channel must use PKCE (default true). */
    public static final String AUTO_REGISTRATION_REQUIRE_PKCE_ENV = "OIDF_AUTO_REGISTRATION_REQUIRE_PKCE";
    /** The largest request object or client assertion read for registration, in bytes (default 65536). */
    public static final String AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES_ENV = "OIDF_AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES";
    /** How many registrations may be resolved at once across all clients (default 8); more are answered 503. */
    public static final String AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS_ENV = "OIDF_AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS";
    /** How long a request waits for another registration of the same client to finish, in ms (default 2000). */
    public static final String AUTO_REGISTRATION_LOCK_WAIT_MS_ENV = "OIDF_AUTO_REGISTRATION_LOCK_WAIT_MS";
    /** A file holding the HTML page a refusal at the authorization endpoint is shown with; unset uses a built-in page. */
    public static final String FEDERATION_ERROR_PAGE_ENV = "OIDF_FEDERATION_ERROR_PAGE";
    /**
     * The Trust Marks an entity must carry before it is registered, by the Entity Type it is registered as:
     * {@code {"*": ["<trust mark type>", ...], "openid_relying_party": [...]}}. Unset requires none; a value that is
     * not such an object stops the deployment starting.
     */
    public static final String REQUIRED_TRUST_MARKS_ENV = "OIDF_FEDERATION_REQUIRED_TRUST_MARKS";
    /** Whether a Trust Mark is also checked at its issuer's status endpoint (§8.4) before it counts (default false). */
    public static final String TRUST_MARK_STATUS_CHECK_ENV = "OIDF_FEDERATION_TRUST_MARK_STATUS_CHECK";
    /**
     * The Trust Mark types this entity issues: {@code {"<type>": {"lifetime_seconds": 86400, "subjects": "hosted" | "any",
     * "delegation": "<jwt>", "ref": "https://...", "logo_uri": "https://..."}}}. Unset: it issues none.
     */
    public static final String TRUST_MARK_TYPES_ENV = "OIDF_FEDERATION_TRUST_MARK_TYPES";
    /** Trust Marks from other issuers this entity carries in its configuration: {@code [{"trust_mark_type": ..., "trust_mark": ...}]}. */
    public static final String TRUST_MARKS_ENV = "OIDF_FEDERATION_TRUST_MARKS";
    /** As a trust anchor, whose Trust Marks of each type the federation accepts: {@code {"<type>": ["<entity id>", ...]}}. */
    public static final String TRUST_MARK_ISSUERS_ENV = "OIDF_FEDERATION_TRUST_MARK_ISSUERS";
    /** As a trust anchor, who owns which Trust Mark type: {@code {"<type>": {"sub": "<entity id>", "jwks": {...}}}}. */
    public static final String TRUST_MARK_OWNERS_ENV = "OIDF_FEDERATION_TRUST_MARK_OWNERS";

    /**
     * Superseded names for the settings above. The attestation issuer's wallet-provider trust read the same
     * three concepts under these names, so one deployment could name two different trust controllers without
     * noticing. They are still accepted, with a warning naming the replacement; setting an old and a new
     * name to different values refuses to start, because two anchors for one concept is the mistake the
     * rename exists to prevent.
     */
    public static final String DEPRECATED_HOST_ENV = "OIDF_TRUST_CONTROLLER_HOST";
    public static final String DEPRECATED_TRUST_ANCHOR_JWKS_ENV = "OIDF_TRUST_ANCHOR_JWKS";
    public static final String DEPRECATED_IGNORE_SSL_ENV = "OIDF_TRUST_CONTROLLER_IGNORE_SSL";
    private static final String DEPRECATED_HOST_PROP = "oidf.trust.controller.host";
    private static final String DEPRECATED_TRUST_ANCHOR_JWKS_PROP = "oidf.trust.anchor.jwks";
    private static final String DEPRECATED_IGNORE_SSL_PROP = "oidf.trust.controller.ignore.ssl";

    private static final String HOST_PROP = "oidf.federation.trust.controller.host";
    private static final String BASE_URL_PROP = "oidf.federation.trust.controller.base.url";
    private static final String TRUST_ANCHOR_JWKS_PROP = "oidf.federation.trust.anchor.jwks";
    private static final String IGNORE_SSL_PROP = "oidf.federation.ignore.ssl.errors";
    private static final String BRIDGE_KEY_PROP = "oidf.bridge.private.jwk";
    private static final String BRIDGE_PREVIOUS_PUBLIC_KEY_PROP = "oidf.bridge.previous.public.jwk";
    private static final String REQUIRE_BRIDGE_KEY_PROP = "oidf.attestation.require.bridge.key";
    private static final String REQUIRE_ATTESTER_BINDING_PROP = "oidf.attestation.require.attester.binding";
    private static final String REQUIRE_METADATA_POLICY_PROP = "oidf.require.metadata.policy";
    private static final String REGISTRATION_MAX_TTL_PROP = "oidf.registration.max.ttl.seconds";
    private static final String REGISTRATION_MIN_TTL_PROP = "oidf.registration.min.ttl.seconds";
    private static final String REGISTRATION_REFRESH_BEFORE_EXPIRY_PROP = "oidf.registration.refresh.before.expiry.seconds";
    private static final String REGISTRATION_EXPIRY_ENFORCEMENT_PROP = "oidf.registration.expiry.enforcement";
    private static final String REGISTRATION_SWEEP_INTERVAL_PROP = "oidf.registration.sweep.interval.seconds";
    private static final String AUTO_REGISTRATION_FAIL_CLOSED_PROP = "oidf.auto.registration.fail.closed";
    private static final String AUTO_REGISTRATION_FRONT_CHANNEL_PROP = "oidf.auto.registration.front.channel";
    private static final String AUTO_REGISTRATION_AUTHZ_ERROR_MODE_PROP = "oidf.auto.registration.authz.error.mode";
    private static final String AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS_PROP = "oidf.auto.registration.encrypted.request.objects";
    private static final String AUTO_REGISTRATION_DEFAULT_SCOPES_PROP = "oidf.auto.registration.default.scopes";
    private static final String AUTO_REGISTRATION_REQUIRE_PAR_PROP = "oidf.auto.registration.require.par";
    private static final String AUTO_REGISTRATION_REQUIRE_PKCE_PROP = "oidf.auto.registration.require.pkce";
    private static final String AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES_PROP = "oidf.auto.registration.max.request.object.bytes";
    private static final String AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS_PROP = "oidf.auto.registration.max.concurrent.resolutions";
    private static final String AUTO_REGISTRATION_LOCK_WAIT_MS_PROP = "oidf.auto.registration.lock.wait.ms";
    private static final String FEDERATION_ERROR_PAGE_PROP = "oidf.federation.error.page";
    private static final String REQUIRED_TRUST_MARKS_PROP = "oidf.federation.required.trust.marks";
    private static final String TRUST_MARK_STATUS_CHECK_PROP = "oidf.federation.trust.mark.status.check";
    private static final String TRUST_MARK_TYPES_PROP = "oidf.federation.trust.mark.types";
    private static final String TRUST_MARKS_PROP = "oidf.federation.trust.marks";
    private static final String TRUST_MARK_ISSUERS_PROP = "oidf.federation.trust.mark.issuers";
    private static final String TRUST_MARK_OWNERS_PROP = "oidf.federation.trust.mark.owners";

    /**
     * What this entity publishes and issues as a Trust Mark Issuer and, when it is one, as a trust anchor.
     *
     * @param types   the types it issues, by identifier, in the order configured
     * @param carried the marks from other issuers it carries in its own configuration
     * @param issuers as an anchor, whose marks of each type the federation accepts
     * @param owners  as an anchor, who owns which type
     */
    public record TrustMarkIssuingSettings(Map<String, TrustMarkType> types, List<Map<String, Object>> carried,
                                           Map<String, List<String>> issuers, Map<String, Object> owners) {
        public static final TrustMarkIssuingSettings NONE = new TrustMarkIssuingSettings(Map.of(), List.of(), Map.of(), Map.of());
    }

    /** What happens to an expired registration that cannot be renewed. */
    public enum ExpiryEnforcement {
        /** The request is refused; the client stays as it is, to be renewed later. The default. */
        REFUSE,
        /** The request is refused and the client disabled until a renewal succeeds. */
        DISABLE,
        /** The expiry is logged and the request goes on - for a deployment not yet ready to enforce §12.3. */
        LOG
    }

    /**
     * How long federation registrations live and what happens when they end.
     *
     * @param maxTtlSeconds                the longest a registration lives, whatever its chain allows
     * @param minTtlSeconds                a registration that would live less than this is refused
     * @param refreshBeforeExpirySeconds   how long before expiry the token endpoint re-validates
     * @param expiryEnforcement            what an expired registration that cannot be renewed gets
     * @param sweepIntervalSeconds         how often expired clients are disabled; 0 turns it off
     * @param failClosed                   whether a failed automatic registration refuses the token request
     */
    public record RegistrationSettings(long maxTtlSeconds, long minTtlSeconds, long refreshBeforeExpirySeconds,
                                       ExpiryEnforcement expiryEnforcement, long sweepIntervalSeconds, boolean failClosed) {

        public static final RegistrationSettings DEFAULTS = new RegistrationSettings(86_400L, 60L, 300L, ExpiryEnforcement.REFUSE, 300L, true);

        public RegistrationSettings {
            if (minTtlSeconds < 0 || maxTtlSeconds < minTtlSeconds || refreshBeforeExpirySeconds < 0 || sweepIntervalSeconds < 0) {
                throw new IllegalStateException("registration lifetimes must satisfy 0 <= " + REGISTRATION_MIN_TTL_ENV + " <= "
                        + REGISTRATION_MAX_TTL_ENV + ", and " + REGISTRATION_REFRESH_BEFORE_EXPIRY_ENV + " and "
                        + REGISTRATION_SWEEP_INTERVAL_ENV + " must not be negative");
            }
            Objects.requireNonNull(expiryEnforcement, "expiryEnforcement");
        }
    }

    /**
     * Automatic registration at the authorization and PAR endpoints, and the limits on registration work any
     * unauthenticated request can start.
     *
     * @param frontChannel               whether the authorization and PAR endpoints register at all
     * @param pageOnAuthorizationError   answer a refusal at the authorization endpoint with the error page (else pass it on)
     * @param allowEncryptedRequestObjects register from a request object only PingFederate can decrypt
     * @param defaultScopes              what an RP that declares no {@code scope} is registered with
     * @param requirePar                 register every front-channel RP as PAR-only
     * @param requirePkce                register every front-channel RP as PKCE-only
     * @param maxRequestObjectBytes      the largest request object or client assertion read
     * @param maxConcurrentResolutions   registrations resolved at once, across all clients
     * @param lockWaitMillis             how long a request waits for another registration of the same client
     * @param errorPage                  the file the error page is rendered from, or null for the built-in page
     */
    public record AutoRegistrationSettings(boolean frontChannel, boolean pageOnAuthorizationError, boolean allowEncryptedRequestObjects,
                                           String defaultScopes, boolean requirePar, boolean requirePkce, int maxRequestObjectBytes,
                                           int maxConcurrentResolutions, long lockWaitMillis, String errorPage) {

        public static final AutoRegistrationSettings DEFAULTS =
                new AutoRegistrationSettings(true, true, true, "openid", false, true, 65_536, 8, 2_000L, null);

        public AutoRegistrationSettings {
            if (maxRequestObjectBytes < 1 || maxConcurrentResolutions < 1 || lockWaitMillis < 0) {
                throw new IllegalStateException(AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES_ENV + " and "
                        + AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS_ENV + " must be at least 1, and "
                        + AUTO_REGISTRATION_LOCK_WAIT_MS_ENV + " must not be negative");
            }
            defaultScopes = defaultScopes == null || defaultScopes.isBlank() ? "openid" : defaultScopes.trim();
        }
    }

    private static volatile FederationRuntimeConfig instance;

    private final String trustControllerHost;
    private final String trustControllerBaseUrl;
    private final String trustAnchorJwks;
    private final boolean ignoreSslErrors;
    private final String bridgePrivateJwk;
    private final String bridgePreviousPublicJwk;
    private final boolean requireBridgeKey;
    private final boolean requireMetadataPolicy;
    private final boolean requireAttesterBinding;
    private final List<String> deprecationWarnings;
    private final RegistrationSettings registration;
    private final AutoRegistrationSettings autoRegistration;
    private final TrustMarkPolicy requiredTrustMarks;
    private final boolean trustMarkStatusCheck;
    private final TrustMarkIssuingSettings trustMarkIssuing;

    private FederationRuntimeConfig(String trustControllerHost, String trustControllerBaseUrl, String trustAnchorJwks,
            boolean ignoreSslErrors, String bridgePrivateJwk, String bridgePreviousPublicJwk, boolean requireBridgeKey,
            boolean requireMetadataPolicy, boolean requireAttesterBinding, List<String> deprecationWarnings,
            RegistrationSettings registration, AutoRegistrationSettings autoRegistration, TrustMarkPolicy requiredTrustMarks,
            boolean trustMarkStatusCheck, TrustMarkIssuingSettings trustMarkIssuing) {
        this.deprecationWarnings = List.copyOf(deprecationWarnings);
        this.registration = Objects.requireNonNull(registration, "registration");
        this.autoRegistration = Objects.requireNonNull(autoRegistration, "autoRegistration");
        this.requiredTrustMarks = Objects.requireNonNull(requiredTrustMarks, "requiredTrustMarks");
        this.trustMarkStatusCheck = trustMarkStatusCheck;
        this.trustMarkIssuing = Objects.requireNonNull(trustMarkIssuing, "trustMarkIssuing");
        this.trustAnchorJwks = blankToNull(trustAnchorJwks);
        this.bridgePrivateJwk = blankToNull(bridgePrivateJwk);
        this.bridgePreviousPublicJwk = blankToNull(bridgePreviousPublicJwk);
        this.requireBridgeKey = requireBridgeKey;
        this.requireMetadataPolicy = requireMetadataPolicy;
        this.requireAttesterBinding = requireAttesterBinding;
        this.trustControllerHost = trustControllerHost == null ? "" : trustControllerHost.trim();
        String base = trustControllerBaseUrl == null ? "" : trustControllerBaseUrl.trim();
        // The identity and its reachable location are the same thing in most deployments; only a PF
        // serving federation under a context path (e.g. /oidf) needs them to differ.
        this.trustControllerBaseUrl = base.isBlank() ? this.trustControllerHost : base;
        this.ignoreSslErrors = ignoreSslErrors;
    }

    /** The process-wide configuration, resolved on first use and cached. */
    public static FederationRuntimeConfig get() {
        FederationRuntimeConfig local = instance;
        if (local == null) {
            synchronized (FederationRuntimeConfig.class) {
                local = instance;
                if (local == null) {
                    local = from(System::getenv, System::getProperty);
                    instance = local;
                }
            }
        }
        return local;
    }

    /**
     * Installs {@code config} as the process-wide configuration. Tests use it in place of reflection; a
     * deployment never needs it, since {@link #get()} resolves from the environment on first use.
     */
    public static void install(FederationRuntimeConfig config) {
        synchronized (FederationRuntimeConfig.class) {
            instance = Objects.requireNonNull(config, "config");
        }
    }

    /** Tests only: forget the resolved configuration so the next {@link #get()} resolves again. */
    public static void resetForTests() {
        synchronized (FederationRuntimeConfig.class) {
            instance = null;
        }
    }

    /**
     * Test seam: resolve from supplied lookups instead of the real process environment.
     *
     * @throws IllegalStateException when a superseded name and its replacement are both set to different values
     */
    public static FederationRuntimeConfig from(Function<String, String> env, Function<String, String> props) {
        Objects.requireNonNull(env, "env");
        Objects.requireNonNull(props, "props");
        List<String> deprecations = new ArrayList<>();
        String requireBridge = setting(env, props, REQUIRE_BRIDGE_KEY_PROP, REQUIRE_BRIDGE_KEY_ENV);
        String requirePolicy = setting(env, props, REQUIRE_METADATA_POLICY_PROP, REQUIRE_METADATA_POLICY_ENV);
        String requireBinding = setting(env, props, REQUIRE_ATTESTER_BINDING_PROP, REQUIRE_ATTESTER_BINDING_ENV);
        return new FederationRuntimeConfig(
                aliased(env, props, HOST_PROP, HOST_ENV, DEPRECATED_HOST_PROP, DEPRECATED_HOST_ENV, deprecations),
                setting(env, props, BASE_URL_PROP, BASE_URL_ENV),
                aliased(env, props, TRUST_ANCHOR_JWKS_PROP, TRUST_ANCHOR_JWKS_ENV, DEPRECATED_TRUST_ANCHOR_JWKS_PROP,
                        DEPRECATED_TRUST_ANCHOR_JWKS_ENV, deprecations),
                Boolean.parseBoolean(aliased(env, props, IGNORE_SSL_PROP, IGNORE_SSL_ENV, DEPRECATED_IGNORE_SSL_PROP,
                        DEPRECATED_IGNORE_SSL_ENV, deprecations)),
                setting(env, props, BRIDGE_KEY_PROP, BRIDGE_KEY_ENV),
                setting(env, props, BRIDGE_PREVIOUS_PUBLIC_KEY_PROP, BRIDGE_PREVIOUS_PUBLIC_KEY_ENV),
                // Default TRUE: an absent bridge key makes attestation authentication a no-op, which
                // is exactly the failure that should be loud rather than silent.
                requireBridge == null || requireBridge.isBlank() || Boolean.parseBoolean(requireBridge),
                // Default TRUE for the same reason: a chain with no metadata_policy constrains nothing,
                // so the leaf's self-published scope and grant_types are simply granted. Silently.
                requirePolicy == null || requirePolicy.isBlank() || Boolean.parseBoolean(requirePolicy),
                // Default TRUE: a client anyone trusted may vouch for is a client anyone trusted may
                // impersonate at the bridge.
                requireBinding == null || requireBinding.isBlank() || Boolean.parseBoolean(requireBinding),
                deprecations,
                registrationSettings(env, props),
                autoRegistrationSettings(env, props),
                requiredTrustMarks(env, props),
                bool(env, props, TRUST_MARK_STATUS_CHECK_PROP, TRUST_MARK_STATUS_CHECK_ENV, false),
                new TrustMarkIssuingSettings(
                        strictly(TRUST_MARK_TYPES_ENV, () -> TrustMarkType.parseAll(setting(env, props, TRUST_MARK_TYPES_PROP, TRUST_MARK_TYPES_ENV))),
                        strictly(TRUST_MARKS_ENV, () -> TrustMarkClaims.parseMarks(setting(env, props, TRUST_MARKS_PROP, TRUST_MARKS_ENV))),
                        strictly(TRUST_MARK_ISSUERS_ENV, () -> TrustMarkClaims.parseIssuers(setting(env, props, TRUST_MARK_ISSUERS_PROP,
                                TRUST_MARK_ISSUERS_ENV))),
                        strictly(TRUST_MARK_OWNERS_ENV, () -> TrustMarkClaims.parseOwners(setting(env, props, TRUST_MARK_OWNERS_PROP,
                                TRUST_MARK_OWNERS_ENV)))));
    }

    /** A setting parsed by {@code parse}; one it refuses stops the deployment, naming the setting. */
    private static <T> T strictly(String var, java.util.function.Supplier<T> parse) {
        try {
            return parse.get();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(var + ": " + e.getMessage());
        }
    }

    private static TrustMarkPolicy requiredTrustMarks(Function<String, String> env, Function<String, String> props) {
        return strictly(REQUIRED_TRUST_MARKS_ENV, () -> TrustMarkPolicy.parse(setting(env, props, REQUIRED_TRUST_MARKS_PROP, REQUIRED_TRUST_MARKS_ENV)));
    }

    private static AutoRegistrationSettings autoRegistrationSettings(Function<String, String> env, Function<String, String> props) {
        AutoRegistrationSettings d = AutoRegistrationSettings.DEFAULTS;
        String errorMode = blankToNull(setting(env, props, AUTO_REGISTRATION_AUTHZ_ERROR_MODE_PROP, AUTO_REGISTRATION_AUTHZ_ERROR_MODE_ENV));
        if (errorMode != null && !errorMode.equalsIgnoreCase("page") && !errorMode.equalsIgnoreCase("passthrough")) {
            throw new IllegalStateException(AUTO_REGISTRATION_AUTHZ_ERROR_MODE_ENV + " must be page or passthrough, not " + errorMode);
        }
        String encrypted = blankToNull(setting(env, props, AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS_PROP, AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS_ENV));
        if (encrypted != null && !encrypted.equalsIgnoreCase("allow") && !encrypted.equalsIgnoreCase("refuse")) {
            throw new IllegalStateException(AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS_ENV + " must be allow or refuse, not " + encrypted);
        }
        return new AutoRegistrationSettings(
                bool(env, props, AUTO_REGISTRATION_FRONT_CHANNEL_PROP, AUTO_REGISTRATION_FRONT_CHANNEL_ENV, d.frontChannel()),
                errorMode == null ? d.pageOnAuthorizationError() : errorMode.equalsIgnoreCase("page"),
                encrypted == null ? d.allowEncryptedRequestObjects() : encrypted.equalsIgnoreCase("allow"),
                blankToNull(setting(env, props, AUTO_REGISTRATION_DEFAULT_SCOPES_PROP, AUTO_REGISTRATION_DEFAULT_SCOPES_ENV)),
                bool(env, props, AUTO_REGISTRATION_REQUIRE_PAR_PROP, AUTO_REGISTRATION_REQUIRE_PAR_ENV, d.requirePar()),
                bool(env, props, AUTO_REGISTRATION_REQUIRE_PKCE_PROP, AUTO_REGISTRATION_REQUIRE_PKCE_ENV, d.requirePkce()),
                (int) seconds(env, props, AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES_PROP, AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES_ENV,
                        d.maxRequestObjectBytes()),
                (int) seconds(env, props, AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS_PROP, AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS_ENV,
                        d.maxConcurrentResolutions()),
                seconds(env, props, AUTO_REGISTRATION_LOCK_WAIT_MS_PROP, AUTO_REGISTRATION_LOCK_WAIT_MS_ENV, d.lockWaitMillis()),
                blankToNull(setting(env, props, FEDERATION_ERROR_PAGE_PROP, FEDERATION_ERROR_PAGE_ENV)));
    }

    private static boolean bool(Function<String, String> env, Function<String, String> props, String prop, String var, boolean fallback) {
        String value = blankToNull(setting(env, props, prop, var));
        return value == null ? fallback : strictBoolean(value, var);
    }

    private static RegistrationSettings registrationSettings(Function<String, String> env, Function<String, String> props) {
        RegistrationSettings d = RegistrationSettings.DEFAULTS;
        String enforcement = blankToNull(setting(env, props, REGISTRATION_EXPIRY_ENFORCEMENT_PROP, REGISTRATION_EXPIRY_ENFORCEMENT_ENV));
        ExpiryEnforcement parsed;
        try {
            parsed = enforcement == null ? d.expiryEnforcement() : ExpiryEnforcement.valueOf(enforcement.toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(REGISTRATION_EXPIRY_ENFORCEMENT_ENV + " must be refuse, disable or log, not " + enforcement);
        }
        String failClosed = blankToNull(setting(env, props, AUTO_REGISTRATION_FAIL_CLOSED_PROP, AUTO_REGISTRATION_FAIL_CLOSED_ENV));
        return new RegistrationSettings(
                seconds(env, props, REGISTRATION_MAX_TTL_PROP, REGISTRATION_MAX_TTL_ENV, d.maxTtlSeconds()),
                seconds(env, props, REGISTRATION_MIN_TTL_PROP, REGISTRATION_MIN_TTL_ENV, d.minTtlSeconds()),
                seconds(env, props, REGISTRATION_REFRESH_BEFORE_EXPIRY_PROP, REGISTRATION_REFRESH_BEFORE_EXPIRY_ENV, d.refreshBeforeExpirySeconds()),
                parsed,
                seconds(env, props, REGISTRATION_SWEEP_INTERVAL_PROP, REGISTRATION_SWEEP_INTERVAL_ENV, d.sweepIntervalSeconds()),
                failClosed == null || strictBoolean(failClosed, AUTO_REGISTRATION_FAIL_CLOSED_ENV));
    }

    /** {@code true} or {@code false}, any case; anything else is refused rather than read as {@code false}. */
    private static boolean strictBoolean(String value, String var) {
        if ("true".equalsIgnoreCase(value.trim())) {
            return true;
        }
        if ("false".equalsIgnoreCase(value.trim())) {
            return false;
        }
        throw new IllegalStateException(var + " must be true or false, not " + value);
    }

    private static long seconds(Function<String, String> env, Function<String, String> props, String prop, String var, long fallback) {
        String value = blankToNull(setting(env, props, prop, var));
        if (value == null) {
            return fallback;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw new IllegalStateException(var + " must be a whole number, not " + value);
        }
    }

    /**
     * {@link #setting} for a name with a superseded spelling: the new name wins; the old one is used only
     * when the new one is unset, and leaves a warning; both set to different values is a refusal.
     */
    private static String aliased(Function<String, String> env, Function<String, String> props, String prop, String var,
            String oldProp, String oldVar, List<String> deprecations) {
        String current = blankToNull(setting(env, props, prop, var));
        String old = blankToNull(setting(env, props, oldProp, oldVar));
        if (old == null) {
            return current;
        }
        if (current == null) {
            deprecations.add(oldVar + " is deprecated; set " + var + " instead (the value was taken from " + oldVar + ")");
            return old;
        }
        if (!current.equals(old)) {
            throw new IllegalStateException(var + " and its superseded name " + oldVar + " are both set, to different values."
                    + " They name one thing - set only " + var);
        }
        deprecations.add(oldVar + " is deprecated and redundant beside " + var + "; remove it");
        return current;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String setting(Function<String, String> env, Function<String, String> props, String prop, String var) {
        String value = props.apply(prop);
        if (value == null || value.isBlank()) {
            value = env.apply(var);
        }
        return value;
    }

    public String trustControllerHost() {
        return this.trustControllerHost;
    }

    public String trustControllerBaseUrl() {
        return this.trustControllerBaseUrl;
    }

    public boolean ignoreSslErrors() {
        return this.ignoreSslErrors;
    }

    /** The raw configured anchor JWKS document, or null when unset. */
    public String trustAnchorJwks() {
        return this.trustAnchorJwks;
    }

    /**
     * The trust anchor every chain in this deployment is validated against: the trust controller's
     * identity plus its out-of-band Federation Entity Keys. This is the only way a
     * {@code TrustChainValidator} is built in this module, so a deployment that names a trust
     * controller without pinning its keys cannot validate any chain: the registration servlet fails
     * its init, the OGNL criteria refuse, and the two token-endpoint filters log it at startup and
     * refuse per request (they do not fail init, because that would also stop this web app serving
     * its own entity configuration - which a self-anchored PF must do before its keys can be pinned).
     * A configured JWKS that is not a usable key set does fail filter init.
     *
     * @throws IllegalStateException when no trust controller is configured, or one is named but
     *                               {@link #TRUST_ANCHOR_JWKS_ENV} is unset
     * @throws IllegalArgumentException when the configured JWKS is not a usable public key set
     */
    public TrustAnchor trustAnchor() {
        if (!isTrustControllerConfigured()) {
            throw new IllegalStateException("No trust controller configured: set " + HOST_ENV + " (and " + TRUST_ANCHOR_JWKS_ENV
                    + ") - every trust chain is refused until then");
        }
        if (this.trustAnchorJwks == null) {
            throw new IllegalStateException(HOST_ENV + " names " + this.trustControllerHost + " but " + TRUST_ANCHOR_JWKS_ENV
                    + " is unset. A trust anchor's keys are configured out of band (OpenID Federation 1.0 §4), not read from"
                    + " its .well-known over HTTPS: capture the jwks claim of " + this.trustControllerHost
                    + "/.well-known/openid-federation once, from a position you trust, and set it as " + TRUST_ANCHOR_JWKS_ENV);
        }
        if (TrustAnchorSet.looksLikeAnchorMap(this.trustAnchorJwks)) {
            return TrustAnchorSet.parseJson(this.trustAnchorJwks).find(this.trustControllerHost).orElseThrow(() ->
                    new IllegalStateException(HOST_ENV + " names " + this.trustControllerHost + " but the anchor map in "
                            + TRUST_ANCHOR_JWKS_ENV + " has no entry for it"));
        }
        return TrustAnchor.parse(this.trustControllerHost, this.trustAnchorJwks);
    }

    /**
     * Every Trust Anchor this deployment validates chains against, in preference order.
     *
     * <p>{@link #TRUST_ANCHOR_JWKS_ENV} holds either one JWK Set - the anchor named by {@link #HOST_ENV}, as
     * before - or a map of anchors, {@code {"<anchor entity id>": {"keys":[...]}, ...}}, whose member order is
     * the preference order (OpenID Federation 1.0 §10.3). In map form the controller host need not be an
     * anchor at all.
     *
     * @throws IllegalStateException when nothing is configured, or a host is named without keys
     * @throws IllegalArgumentException when a configured key set is not usable
     */
    public TrustAnchorSet trustAnchors() {
        if (TrustAnchorSet.looksLikeAnchorMap(this.trustAnchorJwks)) {
            return TrustAnchorSet.parseJson(this.trustAnchorJwks);
        }
        return TrustAnchorSet.of(this.trustAnchor());
    }

    /** Warnings about superseded setting names in use, for logging once at start-up. */
    public List<String> deprecationWarnings() {
        return this.deprecationWarnings;
    }

    /**
     * Raw superseded bridge private JWK JSON, or null. Retained ONLY so {@code BridgeSigners} can
     * refuse to start when it is still set - bridge signing is per client now, and a key here signs
     * nothing.
     */
    public String bridgePrivateJwk() {
        return this.bridgePrivateJwk;
    }

    /** Raw public JWK JSON of a superseded bridge key during rotation, or null. */
    public String bridgePreviousPublicJwk() {
        return this.bridgePreviousPublicJwk;
    }

    public boolean requireBridgeKey() {
        return this.requireBridgeKey;
    }

    /**
     * True (the default) when federation registration must refuse a client whose entity type no
     * superior in the trust chain constrained with a {@code metadata_policy}.
     *
     * <p>Set {@code OIDF_REQUIRE_METADATA_POLICY=false} to accept unconstrained leaf metadata — an
     * interop or bootstrap posture, not one to run a real AS on: without a policy the leaf decides its
     * own {@code scope}, {@code grant_types} and {@code response_types}, and the anchor is reduced to
     * asserting that the entity exists.
     */
    public boolean requireMetadataPolicy() {
        return this.requireMetadataPolicy;
    }

    /** How long federation registrations live, and what happens when they end (§12.3). */
    /** Automatic registration at the front channel, and the limits on registration work. */
    /** The Trust Marks registration requires ({@link #REQUIRED_TRUST_MARKS_ENV}); none when unset. */
    public TrustMarkPolicy requiredTrustMarks() {
        return this.requiredTrustMarks;
    }

    /** Whether a Trust Mark is also checked at its issuer's status endpoint ({@link #TRUST_MARK_STATUS_CHECK_ENV}). */
    public boolean trustMarkStatusCheck() {
        return this.trustMarkStatusCheck;
    }

    /** What this entity issues and publishes as a Trust Mark Issuer, and as an anchor; {@link TrustMarkIssuingSettings#NONE} when unset. */
    public TrustMarkIssuingSettings trustMarkIssuing() {
        return this.trustMarkIssuing;
    }

    public AutoRegistrationSettings autoRegistration() {
        return this.autoRegistration;
    }

    public RegistrationSettings registration() {
        return this.registration;
    }

    /** Whether a bridge-key entry with no {@code attesters} refuses attestation authentication for that client. Default true. */
    public boolean requireAttesterBinding() {
        return this.requireAttesterBinding;
    }

    /**
     * True when no trust controller is configured. Attestation and trust-chain validation cannot
     * succeed in that state — they fail closed on an empty {@code knownTrustAnchor} — so callers log
     * it once rather than failing every request with an unexplained rejection.
     */
    public boolean isTrustControllerConfigured() {
        return !this.trustControllerHost.isBlank();
    }

    @Override
    public String toString() {
        return "FederationRuntimeConfig[host=" + this.trustControllerHost
                + ", baseUrl=" + this.trustControllerBaseUrl
                + ", trustAnchorJwks=" + (this.trustAnchorJwks == null ? "unset" : "set")
                + ", ignoreSslErrors=" + this.ignoreSslErrors + "]";
    }
}
