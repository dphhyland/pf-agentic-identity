/*
 * Seam: the authoritative store resolving a running agent instance to its stable agent_id.
 */
package com.pingidentity.ps.oidf.agent;

/**
 * Resolves a running agent instance — identified by the natural key {@code (iss, clientId,
 * instanceFormat, instanceSubject)} — to a stable {@link AgentIdentity}, minting one on first sight and
 * returning the same row on every later call. A sibling of, and deliberately not coupled to, the
 * (not-yet-merged) device-instance module's own instance registry: that module pre-registers an
 * instance at enrolment time and already has a stable id ({@code agent_instance.id}) to rename into
 * {@code agent_id} (Phase 2.5); this registry is for runtimes with no enrolment step of their own (a
 * SPIFFE workload has no pre-registration beyond its SPIRE entry) and mints lazily instead.
 *
 * <p>Implementations must be safe for concurrent use, and {@link #resolveOrMint} must be race-safe: two
 * concurrent calls for the same natural key must never mint two different ids, and both callers must see
 * the same {@link AgentIdentity} once both calls return.
 */
public interface AgentRegistry {

    /**
     * Resolves the natural key to its {@link AgentIdentity}, minting and durably recording a new one if
     * this is the first time this instance has been seen. Idempotent: repeated calls with the same
     * natural key return the same {@code agentId} and the same {@code mintedAt} every time.
     *
     * @throws AgentRegistryException on a genuine storage fault — never for "not seen before", which
     *                                mints instead of failing
     */
    AgentIdentity resolveOrMint(String iss, String clientId, String instanceFormat, String instanceSubject)
            throws AgentRegistryException;
}
