/*
 * How a hosted entity's federation metadata is signed.
 */
package com.pingidentity.ps.oidf.authority;

/**
 * OpenID Federation requires an Entity Configuration to be self-signed — signed by a key present in its
 * own published {@code jwks}. An ephemeral entity (a container that lives minutes, most protected
 * resources) cannot host that document itself, so the authority hosts it on the entity's behalf. Two
 * ways to satisfy the self-signed requirement while doing that:
 *
 * <ul>
 *   <li>{@link #AUTHORITY_SIGNED} — the authority generates and holds a dedicated key pair for this one
 *       entity (its {@code hostingKeyRef}), publishes that key as the entity's own {@code jwks}, and
 *       signs the entity's configuration with it. The entity's own runtime/instance key never appears
 *       in federation metadata at all — it is bound only in the per-request Client Attestation
 *       ({@code cnf}). Keeping the two apart is deliberate: if the entity's own key also signed its
 *       federation metadata, the entity could rewrite its own scopes and metadata, which is exactly
 *       what having an authority is meant to prevent. This is the mode Phase 1 implements.</li>
 *   <li>{@link #SELF_SIGNED} — the entity supplies its own self-signed statement (signed with a key it
 *       holds), and the authority merely hosts and serves those bytes. Fully conformant, but the
 *       statement's freshness is then bounded by the entity being reachable to re-sign — workable for a
 *       long-lived, capable entity, not the default for an ephemeral one. Modelled here for schema
 *       forward-compatibility; not yet implemented.</li>
 * </ul>
 *
 * <p>An entity that hosts its own {@code /.well-known/openid-federation} and is reached by fetching it
 * (today's pre-existing behaviour, unchanged by this package) is not represented here at all — it never
 * becomes a {@link HostedEntity} row, because the authority does nothing on its behalf.
 */
public enum HostingMode {
    AUTHORITY_SIGNED,
    SELF_SIGNED
}
