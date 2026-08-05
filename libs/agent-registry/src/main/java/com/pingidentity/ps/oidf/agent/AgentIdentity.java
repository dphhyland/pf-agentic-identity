/*
 * The resolved identity of one running agent instance.
 */
package com.pingidentity.ps.oidf.agent;

import java.time.Instant;

/**
 * One row of {@link AgentRegistry}: the stable, pseudonymous {@code agent_id} minted for a running agent
 * instance, and the natural key it was minted against.
 *
 * <p>{@code agentId} is 256 random bits (see {@link AgentIdMinter}), never derived from anything —
 * unlike an HMAC over the natural key, a random id has no failure mode where a leaked key
 * retroactively de-anonymises every id this registry has ever minted.
 *
 * @param agentId          the minted identifier — opaque outside this registry, unique only within its
 *                         issuer, so the full identity is the pair {@code (iss, agentId)}
 * @param iss              the attestation issuer this instance authenticates through
 * @param clientId         the registered client (agent type) this instance is an instance of
 * @param instanceFormat   the shape of {@code instanceSubject} (e.g. {@code "spiffe_id"},
 *                         {@code "wallet_instance"}) — evidence types are free to introduce new formats
 *                         without this registry's schema changing
 * @param instanceSubject  the proven, format-specific identifier for this instance (e.g. the SPIFFE ID)
 * @param mintedAt         when this row was first created — never updated on a later resolve
 */
public record AgentIdentity(
        String agentId,
        String iss,
        String clientId,
        String instanceFormat,
        String instanceSubject,
        Instant mintedAt) {

    public AgentIdentity {
        if (agentId == null || agentId.isBlank()) {
            throw new IllegalArgumentException("agentId must not be blank");
        }
        if (iss == null || iss.isBlank()) {
            throw new IllegalArgumentException("iss must not be blank");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        if (instanceFormat == null || instanceFormat.isBlank()) {
            throw new IllegalArgumentException("instanceFormat must not be blank");
        }
        if (instanceSubject == null || instanceSubject.isBlank()) {
            throw new IllegalArgumentException("instanceSubject must not be blank");
        }
        if (mintedAt == null) {
            throw new IllegalArgumentException("mintedAt must not be null");
        }
    }
}
