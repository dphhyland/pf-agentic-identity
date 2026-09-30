/*
 * Seam: resolves a client_id to its attestation-issuance configuration (and status).
 */
package com.pingidentity.ps.oidf.issuer;

/**
 * Resolves a {@code client_id} to its {@link AttestationIssuanceConfig}, applying the client-status gate
 * in the process. This is the seam that keeps the issuance servlet decoupled from where client state
 * lives: the runtime implementation reads a PingFederate client and its {@code attestation_*} extended
 * properties (status = {@code Client.isEnabled()}), while a later implementation can consult a trust
 * controller (membership + policy + status) and source the SPIFFE bundle from federation metadata. Tests
 * supply a prebuilt config directly.
 *
 * <p>Implementations MUST throw {@link IssuanceException} {@code invalid_client} for an unknown, disabled,
 * or unconfigured client rather than returning null.
 */
public interface IssuanceClientResolver {
    AttestationIssuanceConfig resolve(String clientId) throws IssuanceException;

    /**
     * Every attestation-enabled client the attester serves. The issuance endpoint enumerates these to
     * reverse-map a workload's evidence identity onto a client — the workload itself names no client.
     * Returns an empty list if none are configured.
     */
    java.util.List<AttesterClient> attestationClients() throws IssuanceException;

    /**
     * Called when evidence matched none of {@link #attestationClients()}: a resolver that caches its clients may read
     * them again, and answers whether it did, so the caller looks once more. It must bound how often it reads, since
     * anyone can send evidence that matches nothing (plan item H-ATT-2). Nothing is cached by default: {@code false}.
     */
    default boolean refreshAfterMiss() {
        return false;
    }

    /**
     * Stable id of the resolver plugin backing this resolver (e.g. {@code pf-client-metadata},
     * {@code cimd}, {@code openid-federation}) — surfaced in the attester discovery document so operators
     * can see where the SPIFFE-ID → client mapping and its entitlement ceiling (downscoping) come from.
     */
    default String pluginId() {
        return "unknown";
    }
}
