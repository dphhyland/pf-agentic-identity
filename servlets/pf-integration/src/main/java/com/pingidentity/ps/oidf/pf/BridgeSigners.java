package com.pingidentity.ps.oidf.pf;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import com.pingidentity.ps.oidf.jose.OpenBaoTransitSigner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-client signing keys for {@code attest_jwt_client_auth}.
 *
 * <p>PingFederate has no native attestation-based client authentication, so a verified attestation is
 * translated into a credential PF understands: a {@code private_key_jwt} client assertion for the
 * client the attestation names. This resolves the key that assertion is signed with.
 *
 * <p><b>Per client, deliberately.</b> This replaces {@link BridgeKey}, which held ONE deployment key
 * whose public half was injected into every attestation client's JWKS at registration. That key could
 * mint an assertion for any of them — its own javadoc called it "the highest-value secret in the
 * system" — and it created an ordering trap, because a client registered before the key existed never
 * carried it. Signing with the key the client is <em>already registered with</em> removes both: there
 * is no shared credential, and nothing has to be injected at registration.
 *
 * <p>The client's public half is already where PF looks for it — in its registered JWKS, arriving
 * either from a federation entity statement or from whatever an administrator registered. Federation
 * clients are not a special case; they are the case where the key showed up on its own.
 *
 * <p><b>Backing is configuration, not a compile-time choice</b> ({@code OIDF_BRIDGE_SIGNER_BACKING}):
 *
 * <ul>
 *   <li>{@code vault} — each client names a transit key; the private half never enters this process.
 *   <li>{@code config} — each client carries an inline private JWK. Dev and demo only.
 * </ul>
 *
 * The setting is an assertion about the deployment and is enforced as one: in {@code vault} mode an
 * inline JWK is rejected rather than quietly used, so a demo key cannot ride into production in a
 * config file. Same shape as {@code AttesterSigningKey} on the issuing side, which already solves this
 * problem for attestation minting — including "exactly one source must be set".
 *
 * <p>Failure is per client, not per deployment. A client with no usable key cannot authenticate; every
 * other client is unaffected. Whether a deployment may run with NO bridge signing at all is still
 * {@link #isRequired()} ({@code OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY}, default true).
 */
public final class BridgeSigners {

    /** {@code vault} or {@code config}. Absent means no bridge signing is configured at all. */
    public static final String BACKING_ENV = "OIDF_BRIDGE_SIGNER_BACKING";
    /** Path to the JSON map of client id -> {@code {"key_ref": …}} or {@code {"jwk": {…}}}. */
    public static final String KEYS_ENV = "OIDF_BRIDGE_SIGNING_KEYS";
    public static final String VAULT_ADDR_ENV = "OIDF_BRIDGE_VAULT_ADDR";
    public static final String VAULT_TOKEN_ENV = "OIDF_BRIDGE_VAULT_TOKEN";

    private static final String BACKING_PROP = "oidf.bridge.signer.backing";
    private static final String KEYS_PROP = "oidf.bridge.signing.keys";
    private static final String VAULT_ADDR_PROP = "oidf.bridge.vault.addr";
    private static final String VAULT_TOKEN_PROP = "oidf.bridge.vault.token";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final ConcurrentHashMap<String, JwsSigner> SIGNERS = new ConcurrentHashMap<>();
    private static volatile Map<String, Object> keysByClient;
    private static volatile String loadedFrom;

    private BridgeSigners() {
    }

    /** True when this deployment insists attestation authentication actually works. */
    public static boolean isRequired() {
        return FederationRuntimeConfig.get().requireBridgeKey();
    }

    /** True when a backing and a key map are configured, whether or not any given client has a key. */
    public static boolean isConfigured() {
        refuseSupersededConfig();
        return backing() != null && setting(KEYS_PROP, KEYS_ENV) != null;
    }

    /**
     * Refuses to start when the superseded single-key variable is still set.
     *
     * <p>{@code OIDF_BRIDGE_PRIVATE_JWK} configured one deployment-wide key. Signing is per client now, so
     * that variable does nothing — and a security setting that silently does nothing is worse than one
     * that is absent, because the deployment looks configured. Say so instead.
     */
    private static void refuseSupersededConfig() {
        if (FederationRuntimeConfig.get().bridgePrivateJwk() != null) {
            throw new IllegalStateException(FederationRuntimeConfig.BRIDGE_KEY_ENV
                    + " is set but is no longer used: bridge signing is per client. Move that key to "
                    + KEYS_ENV + " under the client it belongs to (as \"jwk\", with " + BACKING_ENV
                    + "=config), or to a vault transit key (as \"key_ref\", with " + BACKING_ENV
                    + "=vault), then unset " + FederationRuntimeConfig.BRIDGE_KEY_ENV + ".");
        }
    }

    /**
     * The signer for one client, or empty when that client has no bridge key configured.
     *
     * @throws IllegalStateException when the deployment's configuration is itself broken — an
     *     unreadable key map, an unknown backing, or a key of the wrong form for the declared backing.
     *     A misconfigured deployment is a deployment error; it is never a reason to fall through to no
     *     authentication.
     */
    public static Optional<JwsSigner> forClient(String clientId) {
        if (clientId == null || clientId.isBlank() || !isConfigured()) {
            return Optional.empty();
        }
        JwsSigner cached = SIGNERS.get(clientId);
        if (cached != null) {
            return Optional.of(cached);
        }
        Object entry = keys().get(clientId);
        if (entry == null) {
            return Optional.empty();
        }
        if (!(entry instanceof Map)) {
            throw new IllegalStateException("bridge signing key for " + clientId
                    + " must be an object with either \"key_ref\" or \"jwk\"");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> spec = (Map<String, Object>) entry;
        JwsSigner signer = build(clientId, spec);
        SIGNERS.put(clientId, signer);
        return Optional.of(signer);
    }

    /** The signer, or a failure naming what to configure for this specific client. */
    public static JwsSigner require(String clientId) {
        return forClient(clientId).orElseThrow(() -> new IllegalStateException(
                "no bridge signing key for " + clientId + ". Add it to " + KEYS_ENV
                        + " (\"key_ref\" for " + BACKING_ENV + "=vault, \"jwk\" for =config), or set "
                        + FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV
                        + "=false to run without attestation-based client authentication."));
    }

    private static JwsSigner build(String clientId, Map<String, Object> spec) {
        String backing = backing();
        Object keyRef = spec.get("key_ref");
        Object jwk = spec.get("jwk");
        boolean hasRef = keyRef instanceof String && !((String) keyRef).isBlank();
        boolean hasJwk = jwk instanceof Map && !((Map<?, ?>) jwk).isEmpty();

        if (hasRef == hasJwk) {
            throw new IllegalStateException("bridge signing key for " + clientId
                    + ": exactly one of \"key_ref\" or \"jwk\" must be set");
        }
        // The declared backing is enforced, not merely defaulted: an inline key in a vault deployment is
        // a configuration mistake worth failing on, not a convenience to honour.
        if ("vault".equals(backing)) {
            if (!hasRef) {
                throw new IllegalStateException("bridge signing key for " + clientId + " is an inline \"jwk\", but "
                        + BACKING_ENV + "=vault. Inline keys are refused in a vault-backed deployment.");
            }
            String addr = setting(VAULT_ADDR_PROP, VAULT_ADDR_ENV);
            String token = setting(VAULT_TOKEN_PROP, VAULT_TOKEN_ENV);
            if (addr == null || token == null) {
                throw new IllegalStateException(BACKING_ENV + "=vault requires " + VAULT_ADDR_ENV
                        + " and " + VAULT_TOKEN_ENV);
            }
            return new OpenBaoTransitSigner(addr, token, (String) keyRef);
        }
        if ("config".equals(backing)) {
            if (!hasJwk) {
                throw new IllegalStateException("bridge signing key for " + clientId + " is a \"key_ref\", but "
                        + BACKING_ENV + "=config. Set " + BACKING_ENV + "=vault to use transit keys.");
            }
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> params = (Map<String, Object>) jwk;
                return new LocalJwkSigner(params);
            }
            catch (Exception e) {
                throw new IllegalStateException("bridge signing key for " + clientId
                        + " is not a usable private JWK: " + e.getMessage(), e);
            }
        }
        throw new IllegalStateException(BACKING_ENV + " must be \"vault\" or \"config\", got \"" + backing + "\"");
    }

    private static Map<String, Object> keys() {
        String path = setting(KEYS_PROP, KEYS_ENV);
        Map<String, Object> local = keysByClient;
        if (local != null && java.util.Objects.equals(loadedFrom, path)) {
            return local;
        }
        synchronized (BridgeSigners.class) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> parsed = MAPPER.readValue(Files.readString(Path.of(path)), Map.class);
                keysByClient = parsed;
            }
            catch (Exception e) {
                keysByClient = null;
                throw new IllegalStateException(KEYS_ENV + "=" + path + " could not be read as a JSON object "
                        + "of client id -> key: " + e.getMessage(), e);
            }
            loadedFrom = path;
            return keysByClient;
        }
    }

    private static String backing() {
        String raw = setting(BACKING_PROP, BACKING_ENV);
        return raw == null ? null : raw.trim().toLowerCase(Locale.ROOT);
    }

    /** System property first, then environment - the convention the rest of this package follows. */
    private static String setting(String prop, String env) {
        String value = System.getProperty(prop);
        if (value == null || value.isBlank()) {
            value = System.getenv(env);
        }
        return value == null || value.isBlank() ? null : value.trim();
    }

    /** Test seam: drop memoised keys and signers so a test can change the environment. */
    static void resetForTest() {
        SIGNERS.clear();
        keysByClient = null;
        loadedFrom = null;
    }
}
