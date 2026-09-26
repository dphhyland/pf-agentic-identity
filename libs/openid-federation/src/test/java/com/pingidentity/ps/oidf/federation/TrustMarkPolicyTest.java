package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Which Trust Marks registration requires, read from the operator's JSON. */
class TrustMarkPolicyTest {
    private static final String CERTIFIED = "https://ta.example.com/marks/certified";
    private static final String AUDITED = "https://ta.example.com/marks/audited";

    private static TrustMarkValidator.Result carrying(String... types) {
        List<TrustMarkValidator.Verified> verified = java.util.Arrays.stream(types)
                .map(t -> new TrustMarkValidator.Verified(t, "https://tmi.example.com", "https://rp.example.com", 0L, -1L, "jwt"))
                .toList();
        return new TrustMarkValidator.Result(verified, List.of());
    }

    @Test
    void theEveryTypeListAppliesToAllAndATypesOwnListAddsToIt() {
        TrustMarkPolicy policy = TrustMarkPolicy.parse("{\"*\": [\"" + CERTIFIED + "\"], \"openid_relying_party\": [\"" + AUDITED
                + "\", \"" + CERTIFIED + "\"]}");

        assertEquals(List.of(CERTIFIED), policy.requiredFor("oauth_client"));
        assertEquals(List.of(CERTIFIED, AUDITED), policy.requiredFor("openid_relying_party"), "each type once, in order");
        assertFalse(policy.isEmpty());
    }

    @Test
    void everyListedMarkIsRequired() {
        TrustMarkPolicy policy = TrustMarkPolicy.parse("{\"openid_relying_party\": [\"" + CERTIFIED + "\", \"" + AUDITED + "\"]}");

        assertEquals(List.of(AUDITED), policy.missing(carrying(CERTIFIED), "openid_relying_party"));
        assertEquals(List.of(), policy.missing(carrying(AUDITED, CERTIFIED), "openid_relying_party"));
        assertEquals(List.of(), policy.missing(carrying(), "oauth_client"), "nothing is asked of another type");
    }

    @Test
    void blankRequiresNothing() {
        assertSame(TrustMarkPolicy.none(), TrustMarkPolicy.parse(null));
        assertSame(TrustMarkPolicy.none(), TrustMarkPolicy.parse("  "));
        assertTrue(TrustMarkPolicy.none().isEmpty());
        assertTrue(TrustMarkPolicy.parse("{\"*\": []}").isEmpty(), "an empty list requires nothing");
        assertEquals(List.of(), TrustMarkPolicy.none().requiredFor("openid_relying_party"));
    }

    /** A policy the operator got wrong stops the deployment starting, rather than registering without it. */
    @Test
    void anythingButAnObjectOfTypeArraysIsRefused() {
        for (String bad : List.of("[\"" + CERTIFIED + "\"]", "not json", "{\"*\": \"" + CERTIFIED + "\"}", "{\"*\": [1]}", "{\"*\": [\" \"]}")) {
            assertThrows(IllegalArgumentException.class, () -> TrustMarkPolicy.parse(bad), bad);
        }
    }
}
