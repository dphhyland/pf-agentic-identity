package com.pingidentity.ps.oidf.pf;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import com.pingidentity.ps.oidf.federation.TrustAnchor;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;

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

    private FederationRuntimeConfig(String trustControllerHost, String trustControllerBaseUrl, String trustAnchorJwks,
            boolean ignoreSslErrors, String bridgePrivateJwk, String bridgePreviousPublicJwk, boolean requireBridgeKey,
            boolean requireMetadataPolicy, boolean requireAttesterBinding, List<String> deprecationWarnings) {
        this.deprecationWarnings = List.copyOf(deprecationWarnings);
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
                deprecations);
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
