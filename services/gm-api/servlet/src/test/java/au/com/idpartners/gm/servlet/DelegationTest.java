package au.com.idpartners.gm.servlet;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An agent asking whether it may touch a subject's resource.
 *
 * <p>The shape that matters is RFC 8693 delegation: the agent presents a token with the
 * principal's {@code sub} and an {@code act} naming itself. The alternative --
 * impersonation, {@code sub} with no {@code act} -- is indistinguishable from the
 * principal acting alone, which is exactly what an agent must not be able to do.
 *
 * <p>These tests exist because the servlet originally dropped {@code act} entirely: an
 * agent's delegated token evaluated as though Alice had asked directly, and no policy
 * could have bounded the agent because the PDP never learned one was involved.
 */
class DelegationTest {

    private static final String ALICE = "alice";
    private static final String AGENT = "urn:agent:acme-concierge:v2";
    private static final String OPERATOR = "acme-budgeting";

    private static GrantView grant() {
        Map<String, Object> consent = new LinkedHashMap<>();
        consent.put("type", "account_information");
        consent.put("actions", List.of("read_balance"));
        consent.put("locations", List.of("111"));
        return new GrantView("grant-123", ALICE, OPERATOR,
                List.of("accounts.read", GrantEvaluator.SCOPE_EVALUATE),
                System.currentTimeMillis() + 86_400_000L, List.of(consent));
    }

    /** A token as PingFederate would mint it, with an optional act chain. */
    private static TokenClaims tokenWithAct(Object act) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", ALICE);
        payload.put("client_id", OPERATOR);
        payload.put("agid", "grant-123");
        payload.put("scope", "accounts.read " + GrantEvaluator.SCOPE_EVALUATE);
        if (act != null) {
            payload.put("act", act);
        }
        return TokenClaims.from(payload);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> actorContextOf(TokenClaims token) throws Exception {
        Map<String, Object> req = GrantEvaluator.buildDecisionRequest(
                grant(), token, "account", "111", "read_balance", null, null);
        Map<String, Object> ctx = (Map<String, Object>) req.get("context");
        return (Map<String, Object>) ctx.get("actor");
    }

    // ---- reading the act chain (RFC 8693 section 4.1) ----

    @Test
    void readsTheAgentFromADelegatedToken() {
        TokenClaims t = tokenWithAct(Map.of("sub", AGENT));

        assertTrue(t.isDelegated());
        assertEquals(AGENT, t.getActor());
        assertEquals(ALICE, t.getSubject(), "the principal is still the subject");
        assertEquals(OPERATOR, t.getClientId(), "the client is the agent operator, not the agent");
    }

    @Test
    void readsANestedChainCurrentActorFirst() {
        // act: {sub: A2, act: {sub: A1}} -- A2 is acting now, A1 is the prior actor.
        TokenClaims t = tokenWithAct(Map.of("sub", "agent-2", "act", Map.of("sub", "agent-1")));

        assertEquals(List.of("agent-2", "agent-1"), t.getActorChain());
        assertEquals("agent-2", t.getActor(), "the outermost act is the current actor");
    }

    @Test
    void aDirectTokenHasNoActor() {
        TokenClaims t = tokenWithAct(null);

        assertFalse(t.isDelegated());
        assertNull(t.getActor());
        assertTrue(t.getActorChain().isEmpty());
    }

    @Test
    void aCyclicActChainTerminates() {
        // The chain comes off an attacker-influenced token; it must not loop forever.
        Map<String, Object> act = new LinkedHashMap<>();
        act.put("sub", "agent-loop");
        act.put("act", act);

        List<String> chain = TokenClaims.actorChain(act);
        assertEquals(TokenClaims.MAX_ACTOR_CHAIN, chain.size(), "walking stops at the depth cap");
    }

    @Test
    void anActWithoutASubIsNotAnActor() {
        assertTrue(TokenClaims.actorChain(Map.of("nonsense", "x")).isEmpty());
        assertTrue(TokenClaims.actorChain("not-an-object").isEmpty());
        assertTrue(TokenClaims.actorChain(null).isEmpty());
    }

    // ---- what the PDP is told ----

    @Test
    void theAgentIsNamedToThePdp() throws Exception {
        // The regression that matters: without this the PDP sees an agent's call as
        // Alice's own, and cannot bound the agent by its registration at all.
        Map<String, Object> actor = actorContextOf(tokenWithAct(Map.of("sub", AGENT)));

        assertEquals(true, actor.get("delegated"));
        assertEquals(AGENT, actor.get("id"));
        assertEquals(OPERATOR, actor.get("operator"));
        assertEquals(List.of(AGENT), actor.get("chain"));
    }

    @Test
    void aDirectCallIsMarkedUndelegated() throws Exception {
        // The PDP must be able to tell "no agent" from "agent we failed to read".
        Map<String, Object> actor = actorContextOf(tokenWithAct(null));

        assertEquals(false, actor.get("delegated"));
        assertNull(actor.get("id"));
        assertEquals(OPERATOR, actor.get("operator"), "the operator is known either way");
    }

    @Test
    void theFullChainReachesThePdp() throws Exception {
        // Audit and policy both need every hop, not just the nearest one.
        Map<String, Object> actor = actorContextOf(
                tokenWithAct(Map.of("sub", "agent-2", "act", Map.of("sub", "agent-1"))));

        assertEquals(List.of("agent-2", "agent-1"), actor.get("chain"));
        assertEquals("agent-2", actor.get("id"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void theSubjectRemainsThePrincipalNotTheAgent() throws Exception {
        Map<String, Object> req = GrantEvaluator.buildDecisionRequest(
                grant(), tokenWithAct(Map.of("sub", AGENT)),
                "account", "111", "read_balance", null, null);

        Map<String, Object> subject = (Map<String, Object>) req.get("subject");
        assertEquals(ALICE, subject.get("id"),
                "an agent has no standing of its own here; it exercises Alice's authority");
    }

    @Test
    void anAgentCannotForgeAnActorViaTheRequestBody() throws Exception {
        // The actor comes from the signed token. A caller-supplied one must not survive,
        // or any client could claim to be any agent.
        Map<String, Object> hostile = new LinkedHashMap<>();
        hostile.put("actor", Map.of("id", "urn:agent:trusted-thing", "delegated", true));

        Map<String, Object> req = GrantEvaluator.buildDecisionRequest(
                grant(), tokenWithAct(null), "account", "111", "read_balance", null, hostile);

        @SuppressWarnings("unchecked")
        Map<String, Object> ctx = (Map<String, Object>) req.get("context");
        @SuppressWarnings("unchecked")
        Map<String, Object> actor = (Map<String, Object>) ctx.get("actor");

        assertEquals(false, actor.get("delegated"), "the token said no agent; the body cannot say otherwise");
        assertNull(actor.get("id"));
    }

    @Test
    void delegationDoesNotWidenTheGrant() throws Exception {
        // An agent's token is still bound by the grant it names. Delegation changes who
        // is asking, never what was consented.
        var e = org.junit.jupiter.api.Assertions.assertThrows(
                GrantEvaluator.RefusedException.class,
                () -> GrantEvaluator.buildDecisionRequest(
                        grant(),
                        // An agent acting for someone who is not the grant's subject.
                        new TokenClaims("mallory", OPERATOR, "grant-123",
                                List.of(GrantEvaluator.SCOPE_EVALUATE), List.of(AGENT)),
                        "account", "111", "read_balance", null, null));

        assertEquals(GrantEvaluator.Refusal.NOT_YOUR_GRANT, e.refusal,
                "an agent cannot reach a grant by delegating from the wrong principal");
    }
}
