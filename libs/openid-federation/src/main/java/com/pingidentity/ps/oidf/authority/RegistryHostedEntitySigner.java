/*
 * Resolves a hosted entity's OpenBao-backed signer, keyed by hostingKeyRef.
 */
package com.pingidentity.ps.oidf.authority;

import com.pingidentity.ps.oidf.common.JwsSigner;
import com.pingidentity.ps.oidf.common.OpenBaoTransitSigner;
import java.util.concurrent.ConcurrentHashMap;

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

    /**
     * Resolves the OpenBao address/token the same way {@code AttesterSigningKey.fromEnvironment()}
     * does: system property, then environment variable, sharing the same names — one vault serves both
     * attestation issuance and hosted-entity signing.
     */
    public static RegistryHostedEntitySigner fromEnvironment() {
        return new RegistryHostedEntitySigner(
                resolve("oidf.openbao.url", "OIDF_OPENBAO_URL", "OPENBAO_ADDR", "BAO_ADDR", "VAULT_ADDR"),
                resolve("oidf.openbao.token", "OIDF_OPENBAO_TOKEN", "OPENBAO_TOKEN", "BAO_TOKEN", "VAULT_TOKEN"));
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

    private static String resolve(String sysProp, String... envVars) {
        String value = System.getProperty(sysProp);
        if (value != null && !value.isBlank()) {
            return value.trim();
        }
        for (String env : envVars) {
            value = System.getenv(env);
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
