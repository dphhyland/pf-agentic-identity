package com.pingidentity.ps.oidf.rs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The RFC 8693 {@code act} claim.
 *
 * <p>The load-bearing test here is {@link #onlyTheOutermostActorMayBeAuthorisedOn}. Authorising on a
 * nested actor grants a party that has already handed the token on, and the API is shaped so that
 * mistake is awkward to make.
 */
class ActChainTest {

    private static final String HUMAN = "pingone|alice";
    private static final String INSTANCE = "8Kx2_opaque_instance_id";
    private static final String SERVER_AGENT = "https://agents.example.com/planner";

    @Test
    void theObjectFormIsTheSpecShape() {
        ActChain.Parsed parsed = ActChain.parse(Map.of(
                "sub", HUMAN,
                "act", Map.of("sub", INSTANCE)));

        assertFalse(parsed.legacyStringForm());
        assertFalse(parsed.malformed());
        assertEquals(1, parsed.depth());
        assertEquals(INSTANCE, parsed.currentActor().orElseThrow().subject());
    }

    @Test
    void nestingIsOrderedMostRecentFirst() {
        // The server-side agent received the token from the on-device instance.
        ActChain.Parsed parsed = ActChain.parse(Map.of(
                "sub", HUMAN,
                "act", Map.of("sub", SERVER_AGENT, "act", Map.of("sub", INSTANCE))));

        assertEquals(2, parsed.depth());
        assertEquals(SERVER_AGENT, parsed.currentActor().orElseThrow().subject());
        assertEquals(List.of(INSTANCE),
                parsed.priorActors().stream().map(ActChain.Actor::subject).toList());
    }

    /**
     * RFC 8693 §4.1: the nested entries record prior delegation and are informational. Only the
     * outermost actor is presently acting.
     */
    @Test
    void onlyTheOutermostActorMayBeAuthorisedOn() {
        ActChain.Parsed parsed = ActChain.parse(Map.of(
                "sub", HUMAN,
                "act", Map.of("sub", SERVER_AGENT, "act", Map.of("sub", INSTANCE))));

        // currentActor() is the single-value accessor, and it is the last hop, not the first.
        assertEquals(SERVER_AGENT, parsed.currentActor().orElseThrow().subject());
        // The instance that started the chain is available only as history.
        assertTrue(parsed.priorActors().stream().anyMatch(a -> INSTANCE.equals(a.subject())));
    }

    // ---- the legacy string form ------------------------------------------------------------------

    /**
     * This platform's PingFederate mapping historically emitted {@code act} as a JSON string for
     * consumers to decode. It is still parsed so older tokens work, but reported so the deviation is
     * visible rather than permanent.
     */
    @Test
    void theLegacyStringFormIsParsedButFlagged() {
        ActChain.Parsed parsed = ActChain.parse(Map.of(
                "sub", HUMAN,
                "act", "{\"sub\":\"" + INSTANCE + "\"}"));

        assertTrue(parsed.legacyStringForm(), "a string-valued act must be reported as a deviation");
        assertFalse(parsed.malformed());
        assertEquals(INSTANCE, parsed.currentActor().orElseThrow().subject());
    }

    @Test
    void aLegacyStringThatIsNotJsonIsMalformedRatherThanIgnored() {
        ActChain.Parsed parsed = ActChain.parse(Map.of("act", "not json at all"));
        assertTrue(parsed.malformed());
        assertTrue(parsed.isEmpty());
    }

    @Test
    void aStringHoldingAJsonScalarIsMalformed() {
        assertTrue(ActChain.parse(Map.of("act", "\"just-a-string\"")).malformed());
    }

    // ---- absent and hostile input -----------------------------------------------------------------

    @Test
    void aTokenWithNoActIsNotDelegated() {
        ActChain.Parsed parsed = ActChain.parse(Map.of("sub", HUMAN));
        assertTrue(parsed.isEmpty());
        assertTrue(parsed.currentActor().isEmpty());
        assertEquals(0, parsed.depth());
        // Callers must read this as "no agent is acting", never as "any agent may".
    }

    @Test
    void nullClaimsAreHandled() {
        assertTrue(ActChain.parse(null).isEmpty());
    }

    @Test
    void anActOfTheWrongTypeIsMalformed() {
        assertTrue(ActChain.parse(Map.of("act", List.of("nope"))).malformed());
        assertTrue(ActChain.parse(Map.of("act", 42)).malformed());
    }

    /** A hostile token must not be able to nest until the parser exhausts the stack. */
    @Test
    void nestingIsBounded() {
        Map<String, Object> deepest = Map.of("sub", "leaf");
        Map<String, Object> current = deepest;
        for (int i = 0; i < 200; i++) {
            current = Map.of("sub", "hop-" + i, "act", current);
        }
        ActChain.Parsed parsed = ActChain.parse(Map.of("act", current));
        assertTrue(parsed.depth() <= 16, "depth was " + parsed.depth());
    }

    @Test
    void anActorMayCarryAnIssuerAsWellAsASubject() {
        ActChain.Parsed parsed = ActChain.parse(Map.of(
                "act", Map.of("sub", INSTANCE, "iss", "https://platform.example.com")));
        ActChain.Actor actor = parsed.currentActor().orElseThrow();
        assertEquals(INSTANCE, actor.subject());
        assertEquals("https://platform.example.com", actor.issuer());
    }
}
