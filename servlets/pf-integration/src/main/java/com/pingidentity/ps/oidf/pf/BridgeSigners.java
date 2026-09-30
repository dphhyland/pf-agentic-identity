package com.pingidentity.ps.oidf.pf;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import com.pingidentity.ps.oidf.jose.OpenBaoTransitSigner;
import com.pingidentity.ps.oidf.platform.component.ComponentRegistry;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Map;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Per-client signing keys for {@code attest_jwt_client_auth}.
 *
 * <p>PingFederate has no native attestation-based client authentication, so a verified attestation is
 * translated into a credential PF understands: a {@code private_key_jwt} client assertion for the
 * client the attestation names. This resolves the key that assertion is signed with.
 *
 * <p><b>Per client, deliberately.</b> This replaces {@code BridgeKey}, which held ONE deployment key
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
 *
 * <p><b>Checked at start (plan item H-JOSE-2).</b> {@link #startCheck()} builds every configured client's signer once
 * the attestation filter starts, and again every {@link #CHECK_INTERVAL}, and records the clients whose key does not
 * build - an RSA key under 2048 bits, an EC key off P-256/P-384/P-521, an {@code alg} the key cannot sign, a transit key
 * the vault will not describe - as a {@code DEGRADED} part of {@code ATTESTATION_AUTH} ({@value #CHECK_PART}), naming
 * the clients, never the keys. Until 0.6.0 such a key was found by the client's first bridged request, as a 500
 * (F-0112).
 */
public final class BridgeSigners {

    /** {@code vault} or {@code config}. Absent means no bridge signing is configured at all. */
    public static final String BACKING_ENV = "OIDF_BRIDGE_SIGNER_BACKING";
    /** Path to the JSON map of client id -> {@code {"key_ref": …}} or {@code {"jwk": {…}}}. */
    public static final String KEYS_ENV = "OIDF_BRIDGE_SIGNING_KEYS";
    public static final String VAULT_ADDR_ENV = "OIDF_BRIDGE_VAULT_ADDR";
    public static final String VAULT_TOKEN_ENV = "OIDF_BRIDGE_VAULT_TOKEN";

    /** The part of {@code ATTESTATION_AUTH} the start-up check of every client's key records its findings as. */
    public static final String CHECK_PART = "BridgeSigners";
    /** The executor the check runs on. */
    public static final String CHECK_JOB = "bridge-signer-check";
    /**
     * How often the check runs again: a vault that was down at start is found again, and so is a key file that could
     * not be read at all. A file that was read is kept until PingFederate restarts, so a key mended in it is not.
     */
    public static final Duration CHECK_INTERVAL = Duration.ofMinutes(10);

    private static final Log LOGGER = LogFactory.getLog(BridgeSigners.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Object CHECK_LOCK = new Object();
    private static ManagedExecutor checker;
    private static volatile Set<String> unusable = Set.of();

    private static final ConcurrentHashMap<String, JwsSigner> SIGNERS = new ConcurrentHashMap<>();
    private static volatile Map<String, Object> keysByClient;
    private static volatile String loadedFrom;

    private BridgeSigners() {
    }

    /** True when this deployment insists attestation authentication actually works. */
    public static boolean isRequired() {
        return FederationRuntimeConfig.get().requireBridgeKey();
    }

    /**
     * True when a backing and a key map are configured, whether or not any given client has a key. Each is read through
     * its entry in the {@code federation-runtime} catalogue (plan item ST-5), which also refuses the superseded
     * single-key {@code OIDF_BRIDGE_PRIVATE_JWK} and {@code OIDF_BRIDGE_PREVIOUS_PUBLIC_JWK} when either is still set,
     * naming what replaces it: bridge signing is per client now, and a security setting that silently does nothing is
     * worse than one that is absent, because the deployment looks configured.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused for a value an entry refuses - a backing that is
     *                                                                   not {@code vault} or {@code config} - or a removed
     *                                                                   name that is set
     */
    public static boolean isConfigured() {
        return backing() != null && keysPath() != null;
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

    /**
     * The attester issuers this client's entry binds it to, or empty when the entry names none.
     *
     * <p>Same per-client entry as the signing key — {@code {"jwk": …, "attesters": ["https://…"]}} —
     * because that entry is already the deployment's statement that this client authenticates by
     * attestation; it is the natural place to say by whose. An entry with no {@code attesters} is
     * distinguishable from one with an empty list only in that both mean "nobody named": the caller
     * decides what an unbound client gets ({@link FederationRuntimeConfig#requireAttesterBinding}).
     *
     * @throws IllegalStateException when the entry's {@code attesters} is not an array of strings, or
     *     the key map itself cannot be read — a misconfiguration, never a reason to fall through
     */
    public static Set<String> attestersFor(String clientId) {
        if (clientId == null || clientId.isBlank() || !isConfigured()) {
            return Set.of();
        }
        Object entry = keys().get(clientId);
        if (!(entry instanceof Map)) {
            return Set.of();
        }
        Object raw = ((Map<?, ?>) entry).get("attesters");
        if (raw == null) {
            return Set.of();
        }
        if (!(raw instanceof List)) {
            throw new IllegalStateException("bridge entry for " + clientId
                    + ": \"attesters\" must be an array of attester issuer identifiers");
        }
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (Object item : (List<?>) raw) {
            if (!(item instanceof String) || ((String) item).isBlank()) {
                throw new IllegalStateException("bridge entry for " + clientId
                        + ": \"attesters\" must contain only non-blank issuer identifiers");
            }
            out.add(((String) item).trim());
        }
        return Set.copyOf(out);
    }

    /**
     * Starts the check of every configured client's key in this copy, once: a later call while it runs does nothing.
     * Called from the attestation filter's start function, so only the webapp's copy runs it. Never throws and never
     * blocks the filter's start: a vault-backed key is described by the vault, which is a network call.
     */
    public static void startCheck() {
        try {
            synchronized (CHECK_LOCK) {
                if (checker != null && !checker.isClosed()) {
                    return;
                }
                ComponentParts.Part part = Startup.begin(Startup.ATTESTATION_AUTH, CHECK_PART);
                Optional<ManagedExecutor> started = ManagedExecutors.every(CHECK_JOB, Duration.ZERO, CHECK_INTERVAL,
                        () -> BridgeSigners.checkOnce(part));
                if (started.isEmpty()) {
                    part.degraded("the check of the bridge signing keys could not start in this copy");
                    return;
                }
                checker = started.get();
            }
        } catch (RuntimeException e) {
            LOGGER.warn((Object) "the check of the bridge signing keys could not start", e);
        }
    }

    /**
     * One check: every client named in {@value #KEYS_ENV} has its signer built (and kept, so its first request does not
     * build it again). The part is {@code READY} when every one builds, and {@code DEGRADED} naming the clients whose
     * key does not otherwise; each is logged with the reason when first found. Never throws.
     *
     * @return the ids of the clients whose key does not build, or null when the key map could not be read
     */
    static List<String> checkOnce(ComponentParts.Part part) {
        try {
            if (!isConfigured()) {
                part.ready();
                return List.of();
            }
            List<String> bad = new ArrayList<>();
            Set<String> before = unusable;
            for (String clientId : keys().keySet()) {
                try {
                    forClient(clientId);
                } catch (RuntimeException e) {
                    bad.add(clientId);
                    if (!before.contains(clientId)) {
                        LOGGER.warn((Object) ("bridge signing: " + e.getMessage() + "; every attested request for " + clientId
                                + " is refused until it is fixed"));
                    }
                }
            }
            unusable = Set.copyOf(bad);
            if (bad.isEmpty()) {
                part.ready();
            } else {
                part.degraded(checkDetail(bad));
            }
            return bad;
        } catch (RuntimeException e) {
            part.degraded("the bridge signing keys could not be read (" + e.getClass().getSimpleName() + ")");
            return null;
        }
    }

    /** The health detail naming the clients whose key does not build: as many as fit, then how many more. */
    static String checkDetail(List<String> clients) {
        StringBuilder text = new StringBuilder(clients.size() + " client(s) whose bridge signing key does not build, refused at"
                + " the token endpoint until it is fixed (see the log): ");
        int shown = 0;
        for (String client : clients) {
            String next = (shown == 0 ? "" : ", ") + client;
            String more = " and " + (clients.size() - shown - 1) + " more";
            if (text.length() + next.length() + (shown == clients.size() - 1 ? 0 : more.length()) > ComponentRegistry.MAX_REASON) {
                break;
            }
            text.append(next);
            shown++;
        }
        if (shown < clients.size()) {
            text.append(shown == 0 ? "" : " and ").append(clients.size() - shown).append(shown == 0 ? " not named here" : " more");
        }
        return text.toString();
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
            Settings settings = settings();
            String addr = settings.string(VAULT_ADDR_ENV);
            Secret token = settings.secret(VAULT_TOKEN_ENV);
            if (addr == null || token == null) {
                throw new IllegalStateException(BACKING_ENV + "=vault requires " + VAULT_ADDR_ENV
                        + " and " + VAULT_TOKEN_ENV);
            }
            return new OpenBaoTransitSigner(addr, token.reveal(), (String) keyRef);
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
        throw new IllegalStateException(BACKING_ENV + " is unset");
    }

    private static Map<String, Object> keys() {
        Path path = keysPath();
        String from = String.valueOf(path);
        Map<String, Object> local = keysByClient;
        if (local != null && java.util.Objects.equals(loadedFrom, from)) {
            return local;
        }
        synchronized (BridgeSigners.class) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> parsed = MAPPER.readValue(Files.readString(path), Map.class);
                keysByClient = parsed;
            }
            catch (Exception e) {
                keysByClient = null;
                throw new IllegalStateException(KEYS_ENV + "=" + path + " could not be read as a JSON object "
                        + "of client id -> key: " + e.getMessage(), e);
            }
            loadedFrom = from;
            return keysByClient;
        }
    }

    /** {@value #BACKING_ENV}: {@code vault}, {@code config}, or null when unset. */
    private static String backing() {
        Settings settings = settings();
        return settings.choice(BACKING_ENV);
    }

    private static Path keysPath() {
        Settings settings = settings();
        return settings.path(KEYS_ENV);
    }

    /** This process's federation runtime settings: the system property, then the environment variable, for each. */
    private static Settings settings() {
        return FederationRuntimeConfig.settings(Sources.process());
    }

    /** Test seam: drop memoised keys and signers, and stop this copy's check, so a test can change the environment. */
    static void resetForTest() {
        SIGNERS.clear();
        keysByClient = null;
        loadedFrom = null;
        synchronized (CHECK_LOCK) {
            if (checker != null) {
                checker.close();
            }
            checker = null;
            unusable = Set.of();
        }
    }
}
