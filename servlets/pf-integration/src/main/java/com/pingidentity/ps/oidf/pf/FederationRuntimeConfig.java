package com.pingidentity.ps.oidf.pf;

import static com.pingidentity.ps.oidf.platform.settings.Parsers.blankToNull;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import com.pingidentity.ps.oidf.federation.Constraints;
import com.pingidentity.ps.oidf.federation.EndpointAuthPolicy;
import com.pingidentity.ps.oidf.federation.MetadataPolicy;
import com.pingidentity.ps.oidf.federation.TrustAnchor;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.TrustMarkPolicy;
import com.pingidentity.ps.oidf.federation.FederationConfiguration;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.json.Json;
import com.pingidentity.ps.oidf.platform.settings.Parsers;
import com.pingidentity.ps.oidf.platform.settings.Resolved;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.ps.oidf.trustmark.TrustMarkClaims;
import com.pingidentity.ps.oidf.trustmark.TrustMarkType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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
 * <p>Every value is read through {@code platform.settings} and its catalogue entry ({@value #CATALOGUE}, plan item
 * ST-5): system property first, then environment variable - the same precedence the rest of the codebase uses, so a
 * JVM flag can override a container variable without a redeploy - then the superseded names the entry lists, with a
 * warning; a secret may come from the file its {@code _FILE} variant names; and every value is parsed strictly, a
 * number within the entry's range. {@link #IGNORE_SSL_ENV} is read from openid-federation's entry, the one the
 * federation servlet reads, so the two cannot disagree (F-0197). Where each value came from is kept
 * ({@link #provenance()}) and logged as the configuration's banner.
 */
public final class FederationRuntimeConfig {
    private static final Log LOGGER = LogFactory.getLog(FederationRuntimeConfig.class);

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
    /**
     * This deployment's own Entity Identifier, when it is a Trust Anchor itself: chains that end at it are checked with
     * the keys it signs with, read from its own key store every time, so nothing is pinned and a rotation needs no
     * change here.
     */
    public static final String SELF_ANCHOR_ENV = "OIDF_FEDERATION_SELF_ANCHOR";
    /** {@link FederationConfiguration#IGNORE_SSL_ERRORS}: one Setting for the federation servlet and this class (F-0197). */
    public static final String IGNORE_SSL_ENV = FederationConfiguration.IGNORE_SSL_ERRORS;
    /**
     * The single bridge private JWK, removed in 0.1.2 for per-client keys ({@code OIDF_BRIDGE_SIGNING_KEYS}): the
     * catalogue lists it as removed, so a deployment that still sets it is refused, naming the replacement.
     */
    public static final String BRIDGE_KEY_ENV = "OIDF_BRIDGE_PRIVATE_JWK";
    /** Public half of a superseded bridge key, removed with it: refused when set, as {@link #BRIDGE_KEY_ENV} is. */
    public static final String BRIDGE_PREVIOUS_PUBLIC_KEY_ENV = "OIDF_BRIDGE_PREVIOUS_PUBLIC_JWK";
    /**
     * The superseded name of {@code OIDF_ATTESTATION_AUTH_ENABLED} (S9A): {@code false} switches attestation
     * authentication off. Read as that switch's alias ({@link #requireBridgeKey()}).
     */
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
    /**
     * How many registrations each registration filter resolves at once, across all clients (default 8); more are answered
     * 503. The token-endpoint and front-channel filters have a pool each.
     */
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
    /** Whether this entity records its key rotations and publishes the keys it signed with before (§8.7; default false). */
    public static final String HISTORICAL_KEYS_ENV = "OIDF_FEDERATION_HISTORICAL_KEYS";
    /** How long a retired key stays valid for what it signed before it was retired, in seconds (default 86400). */
    public static final String KEY_HISTORY_GRACE_ENV = "OIDF_FEDERATION_KEY_HISTORY_GRACE_SECONDS";
    /**
     * The {@code metadata_policy} every hosted entity's Subordinate Statement starts from, by Entity Type:
     * {@code {"oauth_client": {"scope": {"subset_of": [...]}}}}. An entity's own policy can only narrow it.
     */
    public static final String AUTHORITY_METADATA_POLICY_ENV = "OIDF_AUTHORITY_METADATA_POLICY";
    /** The {@code constraints} (§6.2) every Subordinate Statement this entity issues carries. */
    public static final String SUBORDINATE_CONSTRAINTS_ENV = "OIDF_FEDERATION_SUBORDINATE_CONSTRAINTS";
    /**
     * Client authentication at this entity's federation endpoints (OpenID Federation 1.0 §8.8), as JSON naming each endpoint
     * that takes it: {@code {"federation_fetch_endpoint": "required", "federation_resolve_endpoint": "optional"}}. An endpoint
     * not named takes none, and unset none does - §8.8's default.
     */
    public static final String ENDPOINT_AUTH_ENV = "OIDF_FEDERATION_ENDPOINT_AUTH";
    /** What a client may sign its endpoint client assertion with; default {@code RS256 PS256 ES256}. */
    public static final String ENDPOINT_AUTH_SIGNING_ALGS_ENV = "OIDF_FEDERATION_ENDPOINT_AUTH_SIGNING_ALGS";
    /** §5.1.1: "Servers SHOULD support RS256." */
    static final List<String> DEFAULT_ENDPOINT_AUTH_SIGNING_ALGS = List.of("RS256", "PS256", "ES256");
    /** Which policy decides federation requests: {@code off}, {@code local} (the default) or {@code authzen}. */
    public static final String PDP_MODE_ENV = "OIDF_PDP_MODE";
    /** The AuthZEN PDP's base URL; its evaluation endpoint is {@code /access/v1/evaluation} under it unless discovered. */
    public static final String PDP_URL_ENV = "OIDF_PDP_URL";
    /** The AuthZEN evaluation endpoint itself, when it is not at the default path. */
    public static final String PDP_EVALUATION_URL_ENV = "OIDF_PDP_EVALUATION_URL";
    /** Whether the evaluation endpoint is read from the PDP's {@code /.well-known/authzen-configuration} (default false). */
    public static final String PDP_DISCOVER_ENV = "OIDF_PDP_DISCOVER";
    /** How this deployment authenticates to the PDP: {@code none} (the default), {@code bearer} or {@code header}. */
    public static final String PDP_AUTH_ENV = "OIDF_PDP_AUTH";
    /** The bearer token or shared secret for {@link #PDP_AUTH_ENV}. */
    public static final String PDP_AUTH_TOKEN_ENV = "OIDF_PDP_AUTH_TOKEN";
    /** The header the shared secret goes in (default {@code CLIENT-TOKEN}, as the RAR plugin sends it). */
    public static final String PDP_AUTH_HEADER_ENV = "OIDF_PDP_AUTH_HEADER";
    /** Whether a request goes ahead when the PDP gives no decision (default false: it is refused, 503). */
    public static final String PDP_FAIL_OPEN_ENV = "OIDF_PDP_FAIL_OPEN";
    /** Whether a permit carrying context this deployment does not understand is refused: {@code ignore} (default) or {@code reject}. */
    public static final String PDP_UNKNOWN_CONTEXT_ENV = "OIDF_PDP_UNKNOWN_CONTEXT";
    /** How long a decision is kept, in seconds (default 0: never). */
    public static final String PDP_CACHE_TTL_ENV = "OIDF_PDP_CACHE_TTL_SECONDS";
    public static final String PDP_CONNECT_TIMEOUT_ENV = "OIDF_PDP_CONNECT_TIMEOUT_MS";
    public static final String PDP_REQUEST_TIMEOUT_ENV = "OIDF_PDP_REQUEST_TIMEOUT_MS";
    /** Whether the PDP's {@code reason_user} is shown to the refused caller (default false). */
    public static final String PDP_SURFACE_USER_REASON_ENV = "OIDF_PDP_SURFACE_USER_REASON";
    /**
     * Which decisions the PDP is asked for: {@code explicit_registration}, {@code automatic_registration},
     * {@code hosted_entity_enrol}, {@code token_issuance}. Default the two registrations; the others are asked only when
     * listed, so a PDP with no policy for them does not start refusing enrolments or tokens the day it is switched on.
     */
    public static final String PDP_DECISION_POINTS_ENV = "OIDF_PDP_DECISION_POINTS";
    /** The scopes a federation client may keep, whatever its metadata asks (space or comma separated; unset: no limit). */
    public static final String REGISTRATION_ALLOWED_SCOPES_ENV = "OIDF_REGISTRATION_ALLOWED_SCOPES";

    /**
     * Superseded names for the settings above, now the catalogue's aliases: the attestation issuer's wallet-provider
     * trust read the same three concepts under these names, so one deployment could name two different trust
     * controllers without noticing. They are still read, with a warning naming the replacement; an old and a new name
     * set to different values is refused, because two anchors for one concept is the mistake the rename exists to
     * prevent. {@code OIDF_TRUST_CONTROLLER_IGNORE_SSL} is {@link FederationConfiguration#IGNORE_SSL_ERRORS}'s alias,
     * in openid-federation's catalogue, since the federation servlet reads the same setting (F-0197).
     */
    public static final String DEPRECATED_HOST_ENV = "OIDF_TRUST_CONTROLLER_HOST";
    public static final String DEPRECATED_TRUST_ANCHOR_JWKS_ENV = "OIDF_TRUST_ANCHOR_JWKS";
    public static final String DEPRECATED_IGNORE_SSL_ENV = "OIDF_TRUST_CONTROLLER_IGNORE_SSL";

    /** The settings catalogue this class reads ({@code META-INF/oidf-settings/federation-runtime.json}). */
    public static final String CATALOGUE = "federation-runtime";

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

    /**
     * Whether this entity keeps and publishes its key history (§8.7), and how long a retired key stays valid.
     *
     * @param enabled      whether rotations are recorded and the historical keys endpoint answers
     * @param graceSeconds how long after it is retired a key still vouches for what it signed before
     */
    public record KeyHistorySettings(boolean enabled, long graceSeconds) {
        public static final KeyHistorySettings DEFAULTS = new KeyHistorySettings(false, 86_400L);

        public KeyHistorySettings {
            if (graceSeconds < 0) {
                throw new IllegalStateException(KEY_HISTORY_GRACE_ENV + " must not be negative");
            }
        }
    }

    /**
     * Who decides federation requests beyond the federation's own checks, and how it is reached.
     *
     * @param mode                 {@code OFF}: nobody; {@code LOCAL}: this deployment's own policy; {@code AUTHZEN}: that, then an AuthZEN PDP
     * @param url                  the PDP's base URL (its identifier, when discovered)
     * @param evaluationUrl        its evaluation endpoint, when configured outright
     * @param discover             whether the evaluation endpoint is read from the PDP's metadata
     * @param auth                 how this deployment authenticates to the PDP
     * @param authToken            the bearer token or shared secret
     * @param authHeader           the header a shared secret goes in
     * @param failOpen             whether a request goes ahead when the PDP gives no decision
     * @param rejectUnknownContext whether a permit with context this deployment does not understand is refused
     * @param cacheTtlSeconds      how long a decision is kept; 0 never
     * @param connectTimeoutMs     the PDP connection timeout
     * @param requestTimeoutMs     the PDP request timeout
     * @param surfaceUserReason    whether the PDP's {@code reason_user} is shown to a refused caller
     * @param allowedScopes        the scopes a federation client may keep; null for no limit
     * @param decisionPoints       which decisions are asked for
     */
    public record PdpSettings(PdpMode mode, String url, String evaluationUrl, boolean discover, PdpAuth auth, String authToken, String authHeader,
                              boolean failOpen, boolean rejectUnknownContext, long cacheTtlSeconds, long connectTimeoutMs, long requestTimeoutMs,
                              boolean surfaceUserReason, java.util.Set<String> allowedScopes,
                              java.util.Set<com.pingidentity.ps.oidf.federation.policy.DecisionPoint> decisionPoints) {
        public static final PdpSettings DEFAULTS = new PdpSettings(PdpMode.LOCAL, null, null, false, PdpAuth.NONE, null, "CLIENT-TOKEN", false,
                false, 0L, 2_000L, 3_000L, false, null, java.util.EnumSet.of(com.pingidentity.ps.oidf.federation.policy.DecisionPoint.EXPLICIT_REGISTRATION,
                com.pingidentity.ps.oidf.federation.policy.DecisionPoint.AUTOMATIC_REGISTRATION));

        public PdpSettings {
            Objects.requireNonNull(mode, "mode");
            Objects.requireNonNull(auth, "auth");
            decisionPoints = java.util.Set.copyOf(decisionPoints);
            allowedScopes = allowedScopes == null ? null : java.util.Set.copyOf(allowedScopes);
            if (mode == PdpMode.AUTHZEN && url == null && evaluationUrl == null) {
                throw new IllegalStateException(PDP_MODE_ENV + "=authzen needs " + PDP_URL_ENV + " or " + PDP_EVALUATION_URL_ENV);
            }
            if (discover && url == null) {
                throw new IllegalStateException(PDP_DISCOVER_ENV + "=true needs " + PDP_URL_ENV + ", the PDP's identifier");
            }
            if (auth != PdpAuth.NONE && authToken == null) {
                throw new IllegalStateException(PDP_AUTH_ENV + "=" + auth.name().toLowerCase(java.util.Locale.ROOT) + " needs " + PDP_AUTH_TOKEN_ENV);
            }
            if (cacheTtlSeconds < 0 || connectTimeoutMs <= 0 || requestTimeoutMs <= 0) {
                throw new IllegalStateException("the PDP cache and timeouts must be positive (" + PDP_CACHE_TTL_ENV + " may be 0)");
            }
            if (mode == PdpMode.OFF && allowedScopes != null) {
                throw new IllegalStateException(REGISTRATION_ALLOWED_SCOPES_ENV + " is this deployment's own policy, which "
                        + PDP_MODE_ENV + "=off turns off; unset one of them");
            }
        }

        /** Whether an external PDP is asked for {@code point}. */
        public boolean asksExternally(com.pingidentity.ps.oidf.federation.policy.DecisionPoint point) {
            return this.mode == PdpMode.AUTHZEN && this.decisionPoints.contains(point);
        }
    }

    /** Who decides federation requests beyond the federation's own checks. */
    public enum PdpMode { OFF, LOCAL, AUTHZEN }

    /** How this deployment authenticates to an AuthZEN PDP. */
    public enum PdpAuth { NONE, BEARER, HEADER }

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
    /** The loaded catalogue, read afresh from each call's sources ({@link #settings(Sources)}). */
    private static volatile Settings catalogueSettings;

    private final String trustControllerHost;
    private final String trustControllerBaseUrl;
    private final String trustAnchorJwks;
    private final String selfAnchor;
    private final boolean ignoreSslErrors;
    private final boolean requireBridgeKey;
    private final boolean requireMetadataPolicy;
    private final boolean requireAttesterBinding;
    private final List<String> deprecationWarnings;
    private final List<String> provenance;
    private final RegistrationSettings registration;
    private final AutoRegistrationSettings autoRegistration;
    private final TrustMarkPolicy requiredTrustMarks;
    private final boolean trustMarkStatusCheck;
    private final TrustMarkIssuingSettings trustMarkIssuing;
    private final KeyHistorySettings keyHistory;
    private final Map<String, Object> authorityMetadataPolicy;
    private final Map<String, Object> subordinateConstraints;
    private final PdpSettings pdp;
    private final EndpointAuthPolicy endpointAuth;

    private FederationRuntimeConfig(Read read, RegistrationSettings registration, AutoRegistrationSettings autoRegistration,
            TrustMarkPolicy requiredTrustMarks, TrustMarkIssuingSettings trustMarkIssuing, KeyHistorySettings keyHistory,
            Map<String, Object> authorityMetadataPolicy, Map<String, Object> subordinateConstraints, PdpSettings pdp,
            EndpointAuthPolicy endpointAuth, Values values) {
        this.selfAnchor = values.selfAnchor;
        this.endpointAuth = Objects.requireNonNull(endpointAuth, "endpointAuth");
        this.deprecationWarnings = List.copyOf(read.warnings);
        this.provenance = List.copyOf(read.provenance);
        this.registration = Objects.requireNonNull(registration, "registration");
        this.autoRegistration = Objects.requireNonNull(autoRegistration, "autoRegistration");
        this.requiredTrustMarks = Objects.requireNonNull(requiredTrustMarks, "requiredTrustMarks");
        this.trustMarkStatusCheck = values.trustMarkStatusCheck;
        this.trustMarkIssuing = Objects.requireNonNull(trustMarkIssuing, "trustMarkIssuing");
        this.keyHistory = Objects.requireNonNull(keyHistory, "keyHistory");
        this.authorityMetadataPolicy = Objects.requireNonNull(authorityMetadataPolicy, "authorityMetadataPolicy");
        this.subordinateConstraints = subordinateConstraints;
        this.pdp = Objects.requireNonNull(pdp, "pdp");
        this.trustAnchorJwks = blankToNull(values.trustAnchorJwks);
        this.requireBridgeKey = values.requireBridgeKey;
        this.requireMetadataPolicy = values.requireMetadataPolicy;
        this.requireAttesterBinding = values.requireAttesterBinding;
        this.trustControllerHost = values.trustControllerHost == null ? "" : values.trustControllerHost.trim();
        String base = values.trustControllerBaseUrl == null ? "" : values.trustControllerBaseUrl.trim();
        // The identity and its reachable location are the same thing in most deployments; only a PF
        // serving federation under a context path (e.g. /oidf) needs them to differ.
        this.trustControllerBaseUrl = base.isBlank() ? this.trustControllerHost : base;
        this.ignoreSslErrors = values.ignoreSslErrors;
    }

    /** The plain values {@link #from(Sources)} reads, before the constructor checks and keeps them. */
    private static final class Values {
        String trustControllerHost;
        String trustControllerBaseUrl;
        String trustAnchorJwks;
        String selfAnchor;
        boolean ignoreSslErrors;
        boolean requireBridgeKey;
        boolean requireMetadataPolicy;
        boolean requireAttesterBinding;
        boolean trustMarkStatusCheck;
    }

    /**
     * The process-wide configuration, resolved on first use and cached. The first resolution logs this configuration's
     * banner at INFO: every federation setting that is set, with the source and the name that supplied it
     * ({@link #provenance()}), never a value.
     */
    public static FederationRuntimeConfig get() {
        FederationRuntimeConfig local = instance;
        if (local == null) {
            synchronized (FederationRuntimeConfig.class) {
                local = instance;
                if (local == null) {
                    local = from(Sources.process());
                    LOGGER.info("Federation settings (" + CATALOGUE + ", " + FederationConfiguration.CATALOGUE + "): "
                            + (local.provenance().isEmpty() ? "none set, every one at its default" : String.join("; ", local.provenance())));
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
    static void resetForTests() {
        synchronized (FederationRuntimeConfig.class) {
            instance = null;
            ownKeys = FederationRuntimeConfig::pfSigningJwks;
        }
    }

    /** Test seam: {@link #from(Sources)} with this environment and these system properties, and no init-params. */
    public static FederationRuntimeConfig from(Function<String, String> env, Function<String, String> props) {
        Objects.requireNonNull(env, "env");
        Objects.requireNonNull(props, "props");
        return from(Sources.of(env, props, null));
    }

    /**
     * The federation runtime's settings read from {@code sources}, through its catalogue ({@value #CATALOGUE}). The
     * catalogue is loaded once: BridgeSigners reads through here on every attestation token request, and a load is a
     * class-loader scan and a parse. Only the catalogue is kept; each call reads its sources afresh.
     */
    public static Settings settings(Sources sources) {
        Settings local = catalogueSettings;
        if (local == null) {
            local = Settings.load(FederationRuntimeConfig.class.getClassLoader(), CATALOGUE);
            catalogueSettings = local;
        }
        return local.with(sources);
    }

    /**
     * The configuration {@code sources} give (plan item ST-5): every setting through its catalogue entry - the system
     * property, then the environment variable, then the superseded names the entry lists, with a warning - parsed
     * strictly, a secret's {@code _FILE} variant read, and where each value came from kept for the banner. Four entries
     * are other catalogues' and read as their owners read them: {@link FederationConfiguration#IGNORE_SSL_ERRORS}
     * (openid-federation's, which the federation servlet reads too - F-0197), {@code OIDF_FETCH_ALLOW_HTTP}
     * (oidf-jose's) and {@code OIDF_ATTESTATION_AUTH_ENABLED} (platform's switch, whose superseded name is
     * {@link #REQUIRE_BRIDGE_KEY_ENV}).
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused naming the setting, for a value its entry refuses,
     *                                                                   or a superseded name and its replacement set to
     *                                                                   different values; an {@link IllegalStateException}
     *                                                                   for settings that disagree with each other
     */
    public static FederationRuntimeConfig from(Sources sources) {
        Objects.requireNonNull(sources, "sources");
        Read read = new Read();
        Settings runtime = settings(sources);
        Settings entity = FederationConfiguration.settings(sources);
        Settings fetch = OutboundUrlPolicy.settings(sources);
        Settings switches = Settings.load(ComponentSwitches.class.getClassLoader(), ComponentSwitches.CATALOGUE).with(sources);
        Values v = new Values();
        v.trustControllerHost = (String) read.from(runtime).resolve(HOST_ENV);
        v.trustControllerBaseUrl = (String) read.from(runtime).resolve(BASE_URL_ENV);
        v.trustAnchorJwks = json(read.from(runtime).resolve(TRUST_ANCHOR_JWKS_ENV));
        v.ignoreSslErrors = (Boolean) read.from(entity).resolve(FederationConfiguration.IGNORE_SSL_ERRORS);
        // OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY is the switch's superseded name (S9A): false says attestation authentication
        // is off, which is what requireBridgeKey() has always answered for it.
        v.requireBridgeKey = !"false".equals(read.from(switches).resolve(ComponentSwitches.ATTESTATION_AUTH));
        // Default true: a chain with no metadata_policy constrains nothing, so the leaf's self-published scope and
        // grant_types would simply be granted.
        v.requireMetadataPolicy = (Boolean) read.from(runtime).resolve(REQUIRE_METADATA_POLICY_ENV);
        // Default true: a client anyone trusted may vouch for is a client anyone trusted may impersonate at the bridge.
        v.requireAttesterBinding = (Boolean) read.from(runtime).resolve(REQUIRE_ATTESTER_BINDING_ENV);
        v.trustMarkStatusCheck = (Boolean) read.from(runtime).resolve(TRUST_MARK_STATUS_CHECK_ENV);
        URI self = (URI) read.from(runtime).resolve(SELF_ANCHOR_ENV);
        v.selfAnchor = self == null ? null : self.toString();
        boolean allowHttp = (Boolean) read.from(fetch).resolve(OutboundUrlPolicy.ALLOW_HTTP_ENV);
        Read r = read.from(runtime);
        TrustMarkIssuingSettings marks = new TrustMarkIssuingSettings(
                strictly(TRUST_MARK_TYPES_ENV, () -> TrustMarkType.parseAll(json(r.resolve(TRUST_MARK_TYPES_ENV)))),
                strictly(TRUST_MARKS_ENV, () -> TrustMarkClaims.parseMarks((String) r.resolve(TRUST_MARKS_ENV))),
                strictly(TRUST_MARK_ISSUERS_ENV, () -> TrustMarkClaims.parseIssuers(json(r.resolve(TRUST_MARK_ISSUERS_ENV)))),
                strictly(TRUST_MARK_OWNERS_ENV, () -> TrustMarkClaims.parseOwners(json(r.resolve(TRUST_MARK_OWNERS_ENV)))));
        return new FederationRuntimeConfig(read,
                registrationSettings(r),
                autoRegistrationSettings(r),
                strictly(REQUIRED_TRUST_MARKS_ENV, () -> TrustMarkPolicy.parse(json(r.resolve(REQUIRED_TRUST_MARKS_ENV)))),
                marks,
                new KeyHistorySettings((Boolean) r.resolve(HISTORICAL_KEYS_ENV), seconds(r.resolve(KEY_HISTORY_GRACE_ENV))),
                strictly(AUTHORITY_METADATA_POLICY_ENV, () -> metadataPolicyByType(object(r.resolve(AUTHORITY_METADATA_POLICY_ENV)))),
                strictly(SUBORDINATE_CONSTRAINTS_ENV, () -> constraints(object(r.resolve(SUBORDINATE_CONSTRAINTS_ENV)))),
                pdpSettings(r, allowHttp),
                endpointAuth(r),
                v);
    }

    /**
     * The settings {@link #from(Sources)} read, and what their resolution said: the warnings (a superseded name in use, a
     * legacy spelling under development) and, for each setting that was set, where its value came from.
     */
    private static final class Read {
        final List<String> warnings = new ArrayList<>();
        final List<String> provenance = new ArrayList<>();
        private Settings settings;

        /** These reads, from {@code settings}. */
        Read from(Settings settings) {
            this.settings = settings;
            return this;
        }

        /** {@code name}'s value, typed as its entry says; its warnings and, when it was set, its provenance kept. */
        Object resolve(String name) {
            Resolved resolved = this.settings.resolve(name);
            this.warnings.addAll(resolved.warnings());
            if (!resolved.provenance().isDefault()) {
                this.provenance.add(name + " from " + resolved.provenance());
            }
            return resolved.value();
        }
    }

    /** A {@code json-object} entry's value as JSON text for the parsers that read text, or null when unset. */
    private static String json(Object value) {
        return value == null ? null : Json.write(value);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        return (Map<String, Object>) value;
    }

    /** A {@code seconds} or {@code millis} entry's value in its own unit. */
    private static long seconds(Object value) {
        return ((Duration) value).toSeconds();
    }

    private static long millis(Object value) {
        return ((Duration) value).toMillis();
    }

    /** {@link #ENDPOINT_AUTH_ENV} with the algorithms {@link #ENDPOINT_AUTH_SIGNING_ALGS_ENV} accepts. */
    private static EndpointAuthPolicy endpointAuth(Read r) {
        @SuppressWarnings("unchecked")
        java.util.Set<String> named = (java.util.Set<String>) r.resolve(ENDPOINT_AUTH_SIGNING_ALGS_ENV);
        List<String> algorithms = strictly(ENDPOINT_AUTH_SIGNING_ALGS_ENV, () -> EndpointAuthPolicy.asymmetric(List.copyOf(named)));
        return strictly(ENDPOINT_AUTH_ENV, () -> EndpointAuthPolicy.parse(json(r.resolve(ENDPOINT_AUTH_ENV)), algorithms));
    }

    @SuppressWarnings("unchecked")
    private static PdpSettings pdpSettings(Read r, boolean allowHttp) {
        // AuthZEN 1.0 §10.1: "All API requests within this binding are made via an HTTPS POST request"; §11.1: the PEP-PDP
        // connection "MUST be secured ... (e.g. TLS for HTTP REST)". A decision - and the token that asks for it - is not
        // sent in the clear unless the deployment allows plaintext fetches at all.
        String url = pdpUrl(PDP_URL_ENV, (URI) r.resolve(PDP_URL_ENV), allowHttp);
        String evaluationUrl = pdpUrl(PDP_EVALUATION_URL_ENV, (URI) r.resolve(PDP_EVALUATION_URL_ENV), allowHttp);
        Secret token = (Secret) r.resolve(PDP_AUTH_TOKEN_ENV);
        return new PdpSettings(
                PdpMode.valueOf(((String) r.resolve(PDP_MODE_ENV)).toUpperCase(java.util.Locale.ROOT)),
                url,
                evaluationUrl,
                (Boolean) r.resolve(PDP_DISCOVER_ENV),
                PdpAuth.valueOf(((String) r.resolve(PDP_AUTH_ENV)).toUpperCase(java.util.Locale.ROOT)),
                token == null ? null : token.reveal(),
                (String) r.resolve(PDP_AUTH_HEADER_ENV),
                (Boolean) r.resolve(PDP_FAIL_OPEN_ENV),
                "reject".equals(r.resolve(PDP_UNKNOWN_CONTEXT_ENV)),
                seconds(r.resolve(PDP_CACHE_TTL_ENV)),
                millis(r.resolve(PDP_CONNECT_TIMEOUT_ENV)),
                millis(r.resolve(PDP_REQUEST_TIMEOUT_ENV)),
                (Boolean) r.resolve(PDP_SURFACE_USER_REASON_ENV),
                (java.util.Set<String>) r.resolve(REGISTRATION_ALLOWED_SCOPES_ENV),
                decisionPoints((java.util.Set<String>) r.resolve(PDP_DECISION_POINTS_ENV)));
    }

    /** A PDP URL, https unless {@code OIDF_FETCH_ALLOW_HTTP} allows plaintext; null when unset. */
    private static String pdpUrl(String var, URI url, boolean allowHttp) {
        if (url == null) {
            return null;
        }
        if (!"https".equalsIgnoreCase(url.getScheme()) && !allowHttp) {
            throw new SettingRefused(var, var + " must be an https URL (AuthZEN 1.0 §10.1, §11.1), not " + url + "; set "
                    + OutboundUrlPolicy.ALLOW_HTTP_ENV + "=true for a plaintext development PDP");
        }
        return url.toString();
    }

    private static java.util.Set<com.pingidentity.ps.oidf.federation.policy.DecisionPoint> decisionPoints(java.util.Set<String> names) {
        java.util.Set<com.pingidentity.ps.oidf.federation.policy.DecisionPoint> points = java.util.EnumSet.noneOf(
                com.pingidentity.ps.oidf.federation.policy.DecisionPoint.class);
        for (String name : names) {
            try {
                points.add(com.pingidentity.ps.oidf.federation.policy.DecisionPoint.valueOf(name.toUpperCase(java.util.Locale.ROOT)));
            } catch (IllegalArgumentException e) {
                throw new SettingRefused(PDP_DECISION_POINTS_ENV, PDP_DECISION_POINTS_ENV + " names " + name
                        + ", which is not a decision this deployment asks for");
            }
        }
        return points;
    }

    /** One {@code metadata_policy} per Entity Type, each one a policy {@link MetadataPolicy} can apply. */
    private static Map<String, Object> metadataPolicyByType(Map<String, Object> policy) {
        if (policy == null) {
            return Map.of();
        }
        for (Map.Entry<String, Object> type : policy.entrySet()) {
            if (!(type.getValue() instanceof Map<?, ?> operators)) {
                throw new IllegalArgumentException("the policy for " + type.getKey() + " is not a JSON object");
            }
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> typed = (Map<String, Object>) operators;
                MetadataPolicy.parse(typed, null);
            } catch (MetadataPolicy.PolicyException e) {
                throw new IllegalArgumentException("the policy for " + type.getKey() + " is not one: " + e.getMessage());
            }
        }
        return Map.copyOf(policy);
    }

    private static Map<String, Object> constraints(Map<String, Object> constraints) {
        Constraints.requireValid(constraints);
        return constraints == null ? null : Map.copyOf(constraints);
    }

    /** A setting parsed by {@code parse}; one it refuses stops the deployment, naming the setting ({@link Parsers#strictly}). */
    private static <T> T strictly(String var, java.util.function.Supplier<T> parse) {
        return Parsers.strictly(var, parse);
    }

    @SuppressWarnings("unchecked")
    private static AutoRegistrationSettings autoRegistrationSettings(Read r) {
        java.nio.file.Path errorPage = (java.nio.file.Path) r.resolve(FEDERATION_ERROR_PAGE_ENV);
        return new AutoRegistrationSettings(
                (Boolean) r.resolve(AUTO_REGISTRATION_FRONT_CHANNEL_ENV),
                "page".equals(r.resolve(AUTO_REGISTRATION_AUTHZ_ERROR_MODE_ENV)),
                "allow".equals(r.resolve(AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS_ENV)),
                String.join(" ", (java.util.Set<String>) r.resolve(AUTO_REGISTRATION_DEFAULT_SCOPES_ENV)),
                (Boolean) r.resolve(AUTO_REGISTRATION_REQUIRE_PAR_ENV),
                (Boolean) r.resolve(AUTO_REGISTRATION_REQUIRE_PKCE_ENV),
                // Read as ints with the catalogue's range (1 to 2147483647), so a number past an int is refused rather
                // than wrapped to one the check below accepts (F-0198).
                (Integer) r.resolve(AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES_ENV),
                (Integer) r.resolve(AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS_ENV),
                millis(r.resolve(AUTO_REGISTRATION_LOCK_WAIT_MS_ENV)),
                errorPage == null ? null : errorPage.toString());
    }

    private static RegistrationSettings registrationSettings(Read r) {
        return new RegistrationSettings(
                seconds(r.resolve(REGISTRATION_MAX_TTL_ENV)),
                seconds(r.resolve(REGISTRATION_MIN_TTL_ENV)),
                seconds(r.resolve(REGISTRATION_REFRESH_BEFORE_EXPIRY_ENV)),
                ExpiryEnforcement.valueOf(((String) r.resolve(REGISTRATION_EXPIRY_ENFORCEMENT_ENV)).toUpperCase(java.util.Locale.ROOT)),
                seconds(r.resolve(REGISTRATION_SWEEP_INTERVAL_ENV)),
                (Boolean) r.resolve(AUTO_REGISTRATION_FAIL_CLOSED_ENV));
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
        if (this.selfAnchor != null && this.trustAnchorJwks == null) {
            return TrustAnchorSet.of(this.selfTrustAnchor());
        }
        TrustAnchorSet pinned = TrustAnchorSet.looksLikeAnchorMap(this.trustAnchorJwks) ? TrustAnchorSet.parseJson(this.trustAnchorJwks)
                : TrustAnchorSet.of(this.trustAnchor());
        if (this.selfAnchor == null) {
            return pinned;
        }
        if (pinned.contains(this.selfAnchor)) {
            throw new IllegalStateException(SELF_ANCHOR_ENV + " names " + this.selfAnchor + ", which " + TRUST_ANCHOR_JWKS_ENV
                    + " also pins. Trust it one way: pinned keys go stale when this deployment's own key rotates");
        }
        return pinned.plus(this.selfTrustAnchor());
    }

    /** This deployment as a Trust Anchor, with the keys it signs with as they are when a chain is checked. */
    private TrustAnchor selfTrustAnchor() {
        java.util.function.Supplier<Map<String, Object>> keys = ownKeys;
        return TrustAnchor.live(this.selfAnchor, keys);
    }

    /** How this deployment's own keys are read for {@link #SELF_ANCHOR_ENV}; a test supplies its own. */
    private static volatile java.util.function.Supplier<Map<String, Object>> ownKeys = FederationRuntimeConfig::pfSigningJwks;

    /** PingFederate's signing key as its Entity Configuration publishes it, without an {@code alg}: any it signs with. */
    private static Map<String, Object> pfSigningJwks() {
        try {
            return com.pingidentity.ps.oidf.federation.FederationService.publishedJwks(new PfJwksSigningKeyProvider(), null);
        } catch (org.jose4j.lang.JoseException e) {
            throw new IllegalStateException("this deployment's own signing key could not be read", e);
        }
    }

    /** Test seam: this deployment's own keys, for {@link #SELF_ANCHOR_ENV}. */
    static void useOwnKeys(java.util.function.Supplier<Map<String, Object>> keys) {
        ownKeys = Objects.requireNonNull(keys, "keys");
    }

    /** This deployment's Entity Identifier when it is its own Trust Anchor ({@link #SELF_ANCHOR_ENV}), or null. */
    public String selfAnchor() {
        return this.selfAnchor;
    }

    /** Whether any Trust Anchor is configured to validate chains against: pinned keys, or this deployment itself. */
    public boolean hasTrustAnchors() {
        return this.trustAnchorJwks != null || this.selfAnchor != null;
    }

    /**
     * What resolving the settings warned about: a superseded name in use, or a legacy spelling read under development.
     * {@code platform.settings} logs each one once, when it is first resolved.
     */
    public List<String> deprecationWarnings() {
        return this.deprecationWarnings;
    }

    /**
     * Where each setting that is set came from, as {@code NAME from <source> <name>} - {@code env
     * OIDF_FEDERATION_IGNORE_SSL_ERRORS}, {@code system-property oidf.federation.ignore.ssl.errors}, a superseded name, a
     * {@code _FILE} variant with its file - in the order they were read, never with a value. {@link #get()} logs it as the
     * configuration's banner.
     */
    public List<String> provenance() {
        return this.provenance;
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

    /** The {@code metadata_policy} every hosted entity starts from ({@link #AUTHORITY_METADATA_POLICY_ENV}); empty when unset. */
    public Map<String, Object> authorityMetadataPolicy() {
        return this.authorityMetadataPolicy;
    }

    /** The {@code constraints} on every Subordinate Statement ({@link #SUBORDINATE_CONSTRAINTS_ENV}); null when unset. */
    public Map<String, Object> subordinateConstraints() {
        return this.subordinateConstraints;
    }

    /** Which federation endpoints take client authentication (§8.8); {@link EndpointAuthPolicy#none()} unless configured. */
    public EndpointAuthPolicy endpointAuth() {
        return this.endpointAuth;
    }

    /** Who decides federation requests beyond the federation's own checks. */
    public PdpSettings pdp() {
        return this.pdp;
    }

    /** Whether this entity keeps and publishes its key history (§8.7). */
    public KeyHistorySettings keyHistory() {
        return this.keyHistory;
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
