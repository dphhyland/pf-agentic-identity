/*
 * A per-process AgentRegistry. Development and tests only.
 */
package com.pingidentity.ps.oidf.agent;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * In-memory {@link AgentRegistry}. State does not survive a restart — every instance the attestation
 * service has ever seen would be re-minted a fresh {@code agent_id} on the next attestation after a
 * restart, silently breaking any audit trail, rate limit, or revocation keyed on the old one. This is
 * opt-in for exactly that reason: unlike {@link com.pingidentity.ps.oidf.authority.InMemoryHostedEntityRegistry}'s
 * safe-by-default fallback (a missing registry there only means "not hosted" for entities that were
 * never going to resolve without one), a missing durable {@code AgentRegistry} here means every restart
 * quietly re-anonymises the whole fleet — so nothing in this module reaches for this class as a silent
 * default; the caller must choose it explicitly.
 *
 * <p>{@link #resolveOrMint} is race-safe via {@link ConcurrentHashMap#computeIfAbsent}, which the JDK
 * guarantees invokes its mapping function at most once per key even under concurrent callers.
 */
public final class InMemoryAgentRegistry implements AgentRegistry {
    private static final Log LOGGER = LogFactory.getLog(InMemoryAgentRegistry.class);

    private final ConcurrentHashMap<NaturalKey, AgentIdentity> entries = new ConcurrentHashMap<>();

    public InMemoryAgentRegistry() {
        LOGGER.warn("DEV MODE: in-memory AgentRegistry in use — every agent_id will be re-minted on the "
                + "next restart, breaking audit trails, rate limits and revocations keyed on the old value");
    }

    @Override
    public AgentIdentity resolveOrMint(String iss, String clientId, String instanceFormat, String instanceSubject) {
        // Validated up front, not left to AgentIdentity's own compact constructor: that constructor only
        // runs inside computeIfAbsent's mapping function, i.e. only on the first call for a given key — a
        // second call with blank input against an already-minted key would otherwise silently succeed by
        // returning the earlier (valid) identity instead of failing consistently every time.
        NaturalKey key = NaturalKey.validated(iss, clientId, instanceFormat, instanceSubject);
        return this.entries.computeIfAbsent(key, k -> new AgentIdentity(
                AgentIdMinter.mint(), k.iss(), k.clientId(), k.instanceFormat(), k.instanceSubject(), Instant.now()));
    }

    private record NaturalKey(String iss, String clientId, String instanceFormat, String instanceSubject) {
        static NaturalKey validated(String iss, String clientId, String instanceFormat, String instanceSubject) {
            requireNonBlank(iss, "iss");
            requireNonBlank(clientId, "clientId");
            requireNonBlank(instanceFormat, "instanceFormat");
            requireNonBlank(instanceSubject, "instanceSubject");
            return new NaturalKey(iss, clientId, instanceFormat, instanceSubject);
        }

        private static void requireNonBlank(String value, String field) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(field + " must not be blank");
            }
        }
    }
}
