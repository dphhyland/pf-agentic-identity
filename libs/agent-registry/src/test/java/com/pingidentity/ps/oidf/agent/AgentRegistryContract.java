/*
 * The semantics every AgentRegistry implementation must satisfy identically.
 */
package com.pingidentity.ps.oidf.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * The registry's semantics, which the JDBC implementation must satisfy identically to the in-memory one.
 * Idempotency of {@code resolveOrMint} against its natural key, and race-safety under concurrent first
 * sight, are the properties the rest of the attestation-issuance path relies on.
 */
abstract class AgentRegistryContract {

    /** The implementation under test. Each test method gets a freshly-empty one. */
    protected abstract AgentRegistry newRegistry() throws Exception;

    @Test
    void firstSightMintsANonBlankAgentId() throws Exception {
        AgentIdentity identity = newRegistry().resolveOrMint(
                "https://as.example.com", "client-1", "spiffe_id", "spiffe://example.org/agent-1");
        assertTrue(identity.agentId() != null && !identity.agentId().isBlank());
        assertEquals("https://as.example.com", identity.iss());
        assertEquals("client-1", identity.clientId());
        assertEquals("spiffe_id", identity.instanceFormat());
        assertEquals("spiffe://example.org/agent-1", identity.instanceSubject());
    }

    @Test
    void resolvingTheSameNaturalKeyTwiceReturnsTheIdenticalIdentity() throws Exception {
        AgentRegistry registry = newRegistry();
        AgentIdentity first = registry.resolveOrMint(
                "https://as.example.com", "client-1", "spiffe_id", "spiffe://example.org/agent-1");
        AgentIdentity second = registry.resolveOrMint(
                "https://as.example.com", "client-1", "spiffe_id", "spiffe://example.org/agent-1");

        assertEquals(first.agentId(), second.agentId());
        assertEquals(first.mintedAt(), second.mintedAt(), "a repeat resolve must not re-mint mintedAt either");
    }

    @Test
    void differentInstanceSubjectsMintDifferentIds() throws Exception {
        AgentRegistry registry = newRegistry();
        AgentIdentity a = registry.resolveOrMint(
                "https://as.example.com", "client-1", "spiffe_id", "spiffe://example.org/agent-a");
        AgentIdentity b = registry.resolveOrMint(
                "https://as.example.com", "client-1", "spiffe_id", "spiffe://example.org/agent-b");
        assertNotEquals(a.agentId(), b.agentId());
    }

    @Test
    void theSameInstanceSubjectUnderADifferentClientIdIsADifferentInstance() throws Exception {
        // The natural key is the full 4-tuple, not just instance_subject: two different clients that
        // happen to share a SPIFFE ID prefix (or, more realistically, two independently-registered
        // clients pointed at the same workload during a migration) must not collide onto one agent_id.
        AgentRegistry registry = newRegistry();
        AgentIdentity underClientA = registry.resolveOrMint(
                "https://as.example.com", "client-a", "spiffe_id", "spiffe://example.org/shared");
        AgentIdentity underClientB = registry.resolveOrMint(
                "https://as.example.com", "client-b", "spiffe_id", "spiffe://example.org/shared");
        assertNotEquals(underClientA.agentId(), underClientB.agentId());
    }

    @Test
    void blankNaturalKeyFieldsAreRejected() throws Exception {
        AgentRegistry registry = newRegistry();
        assertThrows(IllegalArgumentException.class,
                () -> registry.resolveOrMint(null, "client-1", "spiffe_id", "spiffe://example.org/agent-1"));
        assertThrows(IllegalArgumentException.class,
                () -> registry.resolveOrMint("https://as.example.com", " ", "spiffe_id", "spiffe://example.org/agent-1"));
        assertThrows(IllegalArgumentException.class,
                () -> registry.resolveOrMint("https://as.example.com", "client-1", "", "spiffe://example.org/agent-1"));
        assertThrows(IllegalArgumentException.class,
                () -> registry.resolveOrMint("https://as.example.com", "client-1", "spiffe_id", null));
    }

    @Test
    void concurrentFirstSightOfTheSameNaturalKeyMintsExactlyOneAgentId() throws Exception {
        AgentRegistry registry = newRegistry();
        int racers = 16;
        ExecutorService pool = Executors.newFixedThreadPool(racers);
        try {
            List<Callable<AgentIdentity>> tasks = java.util.stream.IntStream.range(0, racers)
                    .<Callable<AgentIdentity>>mapToObj(i -> () -> registry.resolveOrMint(
                            "https://as.example.com", "client-1", "spiffe_id", "spiffe://example.org/racer"))
                    .toList();
            List<Future<AgentIdentity>> futures = pool.invokeAll(tasks);
            Set<String> distinctIds = futures.stream()
                    .map(f -> {
                        try {
                            return f.get().agentId();
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .collect(Collectors.toSet());
            assertEquals(1, distinctIds.size(),
                    "every racer must observe the same, single minted agent_id: " + distinctIds);
        } finally {
            pool.shutdownNow();
        }
    }
}
