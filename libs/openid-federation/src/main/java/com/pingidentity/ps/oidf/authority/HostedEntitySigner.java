/*
 * Resolves the signer that should sign a hosted entity's federation metadata.
 */
package com.pingidentity.ps.oidf.authority;

import com.pingidentity.ps.oidf.common.JwsSigner;

/**
 * Turns a {@link HostedEntity}'s {@code hostingKeyRef} into the {@link JwsSigner} that actually holds
 * (or can reach) the private key — the seam between the registry (which only stores an opaque key
 * reference) and the vault/local key material behind it.
 */
public interface HostedEntitySigner {

    /**
     * @throws IllegalStateException if {@code entity}'s {@link HostingMode} has no signer this resolver
     *                                can produce (e.g. {@link HostingMode#SELF_SIGNED}, not yet
     *                                implemented) or the signer is unavailable (vault unreachable) —
     *                                unchecked, matching {@code JwsSigner}'s own fail-closed convention
     */
    JwsSigner signerFor(HostedEntity entity);
}
