package au.com.idpartners.gm.servlet;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The resource-search request: "which resources of this type may this subject act on?".
 *
 * <p>The point of these tests is that a search is not a looser question than an evaluation.
 * It goes through the same scope check, the same expiry refusal and the same subject
 * inference — the ONLY difference is that the resource carries no id, because the set of ids
 * is the answer. If a search could ever be a way to ask something an evaluation would refuse,
 * that is a privilege-escalation path, so each shared guard is asserted here too.
 */
class SearchRequestTest {

    private static final String SUB = "alice";

    private static GrantView grant(String subject, List<String> scopes, Long expires) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "account_information");
        detail.put("actions", List.of("read_balance"));
        return new GrantView("grant-123", subject, "acme-budgeting", scopes, expires,
                List.of(detail));
    }

    private static GrantView validGrant() {
        return grant(SUB, List.of("accounts.read", GrantEvaluator.SCOPE_EVALUATE),
                System.currentTimeMillis() + 86_400_000L);
    }

    private static TokenClaims token(String subject, String... scopes) {
        return new TokenClaims(subject, "acme-budgeting", "grant-123", List.of(scopes));
    }

    private static TokenClaims validToken() {
        return token(SUB, "accounts.read", GrantEvaluator.SCOPE_EVALUATE);
    }

    private static Map<String, Object> search(GrantView g, TokenClaims t, String resourceType)
            throws GrantEvaluator.RefusedException {
        return GrantEvaluator.buildSearchRequest(g, t, resourceType, "search_accounts", null);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> sub(Map<String, Object> request, String key) {
        return (Map<String, Object>) request.get(key);
    }

    // ------------------------------------------------------------------
    // shape
    // ------------------------------------------------------------------

    @Test
    void theResourceCarriesATypeAndNoId() throws Exception {
        Map<String, Object> request = search(validGrant(), validToken(), "account");
        Map<String, Object> resource = sub(request, "resource");

        assertEquals("account", resource.get("type"));
        assertFalse(resource.containsKey("id"), "the id set is the ANSWER, not an input");
    }

    @Test
    void theSubjectIsTheGrantsSubjectNotTheCallers() throws Exception {
        // The caller supplies no subject at all; it comes off the grant. This is the
        // property that stops a client asking what someone else holds.
        Map<String, Object> request = search(validGrant(), validToken(), "account");
        assertEquals(SUB, sub(request, "subject").get("id"));
        assertEquals("user", sub(request, "subject").get("type"));
    }

    @Test
    void theActionIsCarriedThrough() throws Exception {
        Map<String, Object> request = search(validGrant(), validToken(), "account");
        assertEquals("search_accounts", sub(request, "action").get("name"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void theGrantAndActorEnrichmentMatchesAnEvaluation() throws Exception {
        // Same enrichment as evaluate: the PDP must be able to decide against this specific
        // consent, and must be able to see that an agent is asking.
        Map<String, Object> request = search(validGrant(), validToken(), "account");
        Map<String, Object> context = sub(request, "context");

        Map<String, Object> oauth = (Map<String, Object>) context.get("oauth");
        assertEquals("acme-budgeting", oauth.get("client_id"));
        assertEquals("grant-123", oauth.get("grant_id"));
        assertEquals(List.of("accounts.read", GrantEvaluator.SCOPE_EVALUATE), context.get("scopes"));
        assertTrue(context.containsKey("authorization_details"));

        Map<String, Object> actor = (Map<String, Object>) context.get("actor");
        assertEquals("acme-budgeting", actor.get("operator"));
        assertEquals(false, actor.get("delegated"));
    }

    @Test
    void callerContextIsMergedWhenSupplied() throws Exception {
        Map<String, Object> request = GrantEvaluator.buildSearchRequest(
                validGrant(), validToken(), "account", "search_accounts",
                Map.of("channel", "ai-agent"));
        assertEquals("ai-agent", sub(request, "context").get("channel"));
    }

    // ------------------------------------------------------------------
    // the guards a search must NOT be able to dodge
    // ------------------------------------------------------------------

    @Test
    void aTokenWithoutTheEvaluateScopeIsRefused() {
        TokenClaims noScope = token(SUB, "accounts.read");
        GrantEvaluator.RefusedException e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> search(validGrant(), noScope, "account"));
        assertEquals("insufficient_scope", e.refusal.code);
    }

    @Test
    void anExpiredGrantIsRefused() {
        GrantView expired = grant(SUB, List.of(GrantEvaluator.SCOPE_EVALUATE),
                System.currentTimeMillis() - 1_000L);
        GrantEvaluator.RefusedException e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> search(expired, validToken(), "account"));
        assertEquals("grant_expired", e.refusal.code);
    }

    @Test
    void aGrantBelongingToAnotherSubjectIsRefused() {
        // The token says bob; the grant says alice. Nobody may search across that line.
        TokenClaims bob = token("bob", "accounts.read", GrantEvaluator.SCOPE_EVALUATE);
        assertThrows(GrantEvaluator.RefusedException.class,
                () -> search(validGrant(), bob, "account"));
    }

    @Test
    void aMissingResourceTypeIsRefused() {
        GrantEvaluator.RefusedException e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> search(validGrant(), validToken(), null));
        assertEquals("missing_resource", e.refusal.code);

        assertThrows(GrantEvaluator.RefusedException.class,
                () -> search(validGrant(), validToken(), "   "));
    }

    @Test
    void aGrantNamingNoSubjectIsRefused() {
        // Null and blank are distinct paths and both must refuse: a grant with no subject
        // would otherwise produce a PDP question about the empty-string user.
        GrantView nullSubject = grant(null, List.of(GrantEvaluator.SCOPE_EVALUATE),
                System.currentTimeMillis() + 86_400_000L);
        GrantEvaluator.RefusedException e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> search(nullSubject, token(null, GrantEvaluator.SCOPE_EVALUATE), "account"));
        assertEquals("invalid_grant", e.refusal.code);

        GrantView blankSubject = grant("   ", List.of(GrantEvaluator.SCOPE_EVALUATE),
                System.currentTimeMillis() + 86_400_000L);
        GrantEvaluator.RefusedException e2 = assertThrows(GrantEvaluator.RefusedException.class,
                () -> search(blankSubject, token("   ", GrantEvaluator.SCOPE_EVALUATE), "account"));
        assertEquals("invalid_grant", e2.refusal.code);
    }

    // ------------------------------------------------------------------
    // evaluate still demands an id (the search relaxation must not leak into it)
    // ------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void actionPropertiesAppearOnlyWhenNonEmpty() throws Exception {
        // An empty map must not put an empty "properties" object on the wire — a policy
        // reading action.properties.amount should see "absent", not "present but empty".
        Map<String, Object> withEmpty = GrantEvaluator.buildDecisionRequest(validGrant(),
                validToken(), "account", "CHK-1001", "read_balance", Map.of(), null);
        assertFalse(((Map<String, Object>) withEmpty.get("action")).containsKey("properties"));

        Map<String, Object> withProps = GrantEvaluator.buildDecisionRequest(validGrant(),
                validToken(), "account", "CHK-1001", "initiate_payment",
                Map.of("amount", 500), null);
        Map<String, Object> action = (Map<String, Object>) withProps.get("action");
        assertEquals(500, ((Map<String, Object>) action.get("properties")).get("amount"));
    }

    @Test
    void anEvaluationStillRequiresAResourceId() {
        GrantEvaluator.RefusedException e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> GrantEvaluator.buildDecisionRequest(validGrant(), validToken(),
                        "account", null, "read_balance", null, null));
        assertEquals("missing_resource", e.refusal.code);

        assertThrows(GrantEvaluator.RefusedException.class,
                () -> GrantEvaluator.buildDecisionRequest(validGrant(), validToken(),
                        "account", "  ", "read_balance", null, null));
    }
}
