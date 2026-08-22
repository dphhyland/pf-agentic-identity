package com.pingidentity.ps.oidf.agent;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * {@link AgentIdentity}'s own compact-constructor validation. In practice every caller in this module
 * goes through {@code InMemoryAgentRegistry}'s {@code NaturalKey.validated} or
 * {@code JdbcAgentRegistry}'s {@code requireNonBlank} first, so these branches are never hit from
 * inside the module today - but the record is public, constructible directly by any consumer, and its
 * own guard is the last line of defence against a blank identity field, so it is tested directly here.
 */
class AgentIdentityTest {

    private static final Instant NOW = Instant.now();

    @Test
    void rejectsABlankAgentId() {
        assertThrows(IllegalArgumentException.class,
                () -> new AgentIdentity("", "https://as.example.com", "client-1", "spiffe_id", "spiffe://x", NOW));
        assertThrows(IllegalArgumentException.class,
                () -> new AgentIdentity(null, "https://as.example.com", "client-1", "spiffe_id", "spiffe://x", NOW));
    }

    @Test
    void rejectsABlankIssuer() {
        assertThrows(IllegalArgumentException.class,
                () -> new AgentIdentity("id-1", " ", "client-1", "spiffe_id", "spiffe://x", NOW));
    }

    @Test
    void rejectsABlankClientId() {
        assertThrows(IllegalArgumentException.class,
                () -> new AgentIdentity("id-1", "https://as.example.com", "", "spiffe_id", "spiffe://x", NOW));
    }

    @Test
    void rejectsABlankInstanceFormat() {
        assertThrows(IllegalArgumentException.class,
                () -> new AgentIdentity("id-1", "https://as.example.com", "client-1", null, "spiffe://x", NOW));
    }

    @Test
    void rejectsABlankInstanceSubject() {
        assertThrows(IllegalArgumentException.class,
                () -> new AgentIdentity("id-1", "https://as.example.com", "client-1", "spiffe_id", "  ", NOW));
    }

    @Test
    void rejectsANullMintedAt() {
        assertThrows(IllegalArgumentException.class,
                () -> new AgentIdentity("id-1", "https://as.example.com", "client-1", "spiffe_id", "spiffe://x", null));
    }
}
