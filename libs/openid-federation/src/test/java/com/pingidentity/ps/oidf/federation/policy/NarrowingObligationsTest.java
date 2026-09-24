package com.pingidentity.ps.oidf.federation.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** A policy decision can refuse or narrow what the federation allows - never widen it. */
class NarrowingObligationsTest {
    private static final ClientDraft DRAFT = new ClientDraft(List.of("openid", "read", "write"), Set.of("authorization_code", "refresh_token"),
            List.of("code"), 5_000L);

    @Test
    void obligationsOnlyEverTakeAway() {
        NarrowingObligations obligations = new NarrowingObligations(Set.of("read", "admin"), Set.of("authorization_code", "client_credentials"),
                Set.of("code", "code id_token"), 600L, Set.of());

        ClientDraft narrowed = obligations.applyTo(DRAFT, 1_000L);

        assertEquals(List.of("read"), narrowed.scopes(), "admin was never the client's to have");
        assertEquals(Set.of("authorization_code"), narrowed.grantTypes());
        assertEquals(List.of("code"), narrowed.responseTypes());
        assertEquals(1_600L, narrowed.expiresAt(), "brought forward");
        assertEquals(5_000L, new NarrowingObligations(null, null, null, 86_400L, Set.of()).applyTo(DRAFT, 1_000L).expiresAt(), "never put back");
    }

    @Test
    void noObligationLeavesTheDraftAsItIs() {
        assertEquals(DRAFT, NarrowingObligations.NONE.applyTo(DRAFT, 1_000L));
        assertTrue(NarrowingObligations.NONE.isEmpty());
        assertFalse(new NarrowingObligations(Set.of(), null, null, null, null).isEmpty(), "an empty scope set allows no scope at all");
        assertEquals(List.of(), new NarrowingObligations(Set.of(), null, null, null, null).applyTo(DRAFT, 0L).scopes());
    }

    @Test
    void twoSetsOfObligationsHoldTogether() {
        NarrowingObligations local = new NarrowingObligations(Set.of("openid", "read"), null, Set.of("code"), 3600L, Set.of("https://m/one"));
        NarrowingObligations external = new NarrowingObligations(Set.of("read", "write"), Set.of("authorization_code"), null, 600L,
                Set.of("https://m/two"));

        NarrowingObligations both = local.and(external);

        assertEquals(Set.of("read"), both.scopes());
        assertEquals(Set.of("authorization_code"), both.grantTypes());
        assertEquals(Set.of("code"), both.responseTypes());
        assertEquals(600L, both.maxTtlSeconds());
        assertEquals(Set.of("https://m/one", "https://m/two"), both.requiredTrustMarks());
        assertEquals(local, local.and(NarrowingObligations.NONE));
        assertEquals(local, NarrowingObligations.NONE.and(local));
    }

    @Test
    void aRegistrationCannotBeObligedToLiveLessThanNoTime() {
        assertThrows(IllegalArgumentException.class, () -> new NarrowingObligations(null, null, null, -1L, null));
    }

    @Test
    void aDenialCarriesNoObligationsAndAPermitMustSayWhatItNarrows() {
        assertEquals(NarrowingObligations.NONE, new PolicyDecision(false, new NarrowingObligations(Set.of("x"), null, null, null, null),
                "a", "u", null, 0L, null).obligations());
        assertThrows(NullPointerException.class, () -> new PolicyDecision(true, null, null, null, null, 0L, null));
        assertEquals(Set.of(), PolicyDecision.permit(NarrowingObligations.NONE).ignoredContextKeys());
        assertEquals("u", PolicyDecision.deny("a", "u").reasonUser());
    }
}
