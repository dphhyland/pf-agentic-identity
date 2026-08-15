package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SpiffeBindingTest {

    @Test
    void aLiteralPatternMatchesOnlyItsExactSubject() {
        SpiffeBinding binding = new SpiffeBinding(
                "spiffe://example.org/agents/agent-1", List.of(), Map.of());
        assertTrue(binding.matches("spiffe://example.org/agents/agent-1"));
        assertFalse(binding.matches("spiffe://example.org/agents/agent-2"));
        assertFalse(binding.matches("spiffe://example.org/agents/agent-1-extra"));
    }

    @Test
    void aTrailingWildcardMatchesByPrefix() {
        SpiffeBinding archetype = new SpiffeBinding(
                "spiffe://example.org/agents/*", List.of(), Map.of());
        assertTrue(archetype.matches("spiffe://example.org/agents/agent-1"));
        assertTrue(archetype.matches("spiffe://example.org/agents/agent-2"));
        assertTrue(archetype.matches("spiffe://example.org/agents/"));
        assertFalse(archetype.matches("spiffe://example.org/other/agent-1"));
    }

    @Test
    void noSubjectNeverMatchesAnything() {
        SpiffeBinding archetype = new SpiffeBinding("spiffe://example.org/agents/*", List.of(), Map.of());
        assertFalse(archetype.matches(null));
    }

    @Test
    void exactMatchOutranksAnyPrefixMatchRegardlessOfPrefixLength() {
        SpiffeBinding exact = new SpiffeBinding("spiffe://example.org/agents/agent-1", List.of(), Map.of());
        SpiffeBinding longPrefix = new SpiffeBinding("spiffe://example.org/agents/agent-*", List.of(), Map.of());
        assertTrue(exact.specificity() > longPrefix.specificity());
    }

    @Test
    void aLongerPrefixIsMoreSpecificThanAShorterOne() {
        SpiffeBinding narrow = new SpiffeBinding("spiffe://example.org/agents/agent-*", List.of(), Map.of());
        SpiffeBinding wide = new SpiffeBinding("spiffe://example.org/*", List.of(), Map.of());
        assertTrue(narrow.specificity() > wide.specificity());
    }
}
