/*
 * Resolves a hosted entity's OpenBao-backed signer, keyed by hostingKeyRef.
 */
package com.pingidentity.ps.oidf.authority;

import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.OpenBaoTransitSigner;
import java.util.concurrent.ConcurrentHashMap;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;

/**
 * The default {@link HostedEntitySigner}: for a {@link HostingMode#AUTHORITY_SIGNED} entity, resolves
 * its {@code hostingKeyRef} to an OpenBao transit key on one deployment-wide vault (the same
 * address/token for every hosted entity; only the transit key name varies) and caches the resulting
 * {@link OpenBaoTransitSigner} by key name — it is immutable and pins its key version on construction,
 * so constructing it twice for the same key only wastes a round trip, following the same pattern
 * {@code AttesterSigningKey} already uses for per-client attestation signing keys.
 *
 * <p>{@link HostingMode#SELF_SIGNED} has no signer here by design — the authority holds no key for a
 * self-signed entity (see {@link HostingMode}'s own javadoc); resolving one is a caller error.
 */
public final class RegistryHostedEntitySigner implements HostedEntitySigner {

    private final String baoUrl;
    private final String baoToken;
    private final ConcurrentHashMap<String, JwsSigner> cache = new ConcurrentHashMap<>();

    public RegistryHostedEntitySigner(String baoUrl, String baoToken) {
        this.baoUrl = blankToNull(baoUrl);
        this.baoToken = blankToNull(baoToken);
    }

    /** The settings catalogue OpenBao's address and token are in ({@code META-INF/oidf-settings/hosted-entity-signing.json}). */
    public static final String CATALOGUE = "hosted-entity-signing";
    static final String URL = "OIDF_OPENBAO_URL";
    static final String TOKEN = "OIDF_OPENBAO_TOKEN";

    /**
     * OpenBao's address and token from this process: {@code OIDF_OPENBAO_URL} and {@code OIDF_OPENBAO_TOKEN}, each read
     * through its entry in the {@value #CATALOGUE} catalogue - the system property, then the environment variable, then
     * the superseded {@code OPENBAO_*}, {@code BAO_*} and {@code VAULT_*} names with a warning (plan item ST-5). The
     * attestation issuer's signing key reads the same two entries, so one vault serves both.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused for a value its entry refuses: a superseded name
     *                                                                   holding another value, a token file that cannot be read
     */
    public static RegistryHostedEntitySigner fromEnvironment() {
        return from(Sources.process());
    }

    /** As {@link #fromEnvironment}, from {@code sources}. */
    static RegistryHostedEntitySigner from(Sources sources) {
        Settings settings = Settings.load(RegistryHostedEntitySigner.class.getClassLoader(), CATALOGUE).with(sources);
        Secret token = settings.secret(TOKEN);
        return new RegistryHostedEntitySigner(settings.string(URL), token == null ? null : token.reveal());
    }

    @Override
    public JwsSigner signerFor(HostedEntity entity) {
        if (entity.hostingMode() != HostingMode.AUTHORITY_SIGNED) {
            throw new IllegalStateException("HostingMode." + entity.hostingMode()
                    + " has no authority-held signer (entity " + entity.entityId() + ")");
        }
        if (this.baoUrl == null || this.baoToken == null) {
            throw new IllegalStateException(
                    "entity " + entity.entityId() + " is AUTHORITY_SIGNED but no OpenBao address/token is configured");
        }
        String keyRef = entity.hostingKeyRef();
        try {
            return this.cache.computeIfAbsent(keyRef, k -> new OpenBaoTransitSigner(this.baoUrl, this.baoToken, k));
        } catch (RuntimeException e) {
            throw new IllegalStateException(
                    "OpenBao transit signer unavailable for entity " + entity.entityId() + ": " + e.getMessage(), e);
        }
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
