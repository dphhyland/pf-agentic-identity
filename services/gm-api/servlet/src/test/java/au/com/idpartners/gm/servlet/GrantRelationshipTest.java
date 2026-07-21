package au.com.idpartners.gm.servlet;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A grant is a relationship between the client, this authorization server, and the
 * subject. These tests pin that model, because getting it wrong breaks in two directions
 * at once.
 *
 * <p>Checking only the subject leg lets any client holding a token for Alice interrogate
 * a <em>different</em> client's grant with her. Requiring the subject on the token
 * excludes every client that is not mid-session with a user — which is most of an Open
 * Banking ecosystem, where a TPP holds a long-lived consent and asks about it with a
 * client_credentials token.
 *
 * <p>The resolution: the <b>client leg authorises</b> the question; the <b>subject is
 * read off the grant</b> (section 8.4.1). An agent, when present, is an extra vector over
 * that relationship, never a party to it.
 */
class GrantRelationshipTest {

    private static final String TPP = "acme-budgeting";
    private static final String OTHER_TPP = "rival-app";
    private static final String ALICE = "alice";

    private static GrantView grantOf(String clientId, String subject) {
        Map<String, Object> consent = new LinkedHashMap<>();
        consent.put("type", "account_information");
        consent.put("actions", List.of("read_balance"));
        consent.put("locations", List.of("111"));
        return new GrantView("grant-123", subject, clientId,
                List.of("accounts.read", GrantEvaluator.SCOPE_EVALUATE),
                System.currentTimeMillis() + 86_400_000L, List.of(consent));
    }

    private static Map<String, Object> evaluate(GrantView grant, TokenClaims token)
            throws GrantEvaluator.RefusedException {
        return GrantEvaluator.buildDecisionRequest(
                grant, token, "account", "111", "read_balance", null, null);
    }

    // ---- the three token shapes this endpoint must serve ----

    /**
     * Open Banking / Open Data: a TPP holding a long-lived consent asks whether it still
     * covers an account, with no user present and no user token — typically before
     * bothering to spend its refresh token.
     *
     * <p>A client_credentials token carries <b>no sub at all</b>. This is the case the
     * endpoint originally could not serve.
     */
    @Test
    @SuppressWarnings("unchecked")
    void aClientCredentialsTokenCanEvaluateItsOwnGrant() throws Exception {
        TokenClaims clientOnly = new TokenClaims(
                null, TPP, null, List.of(GrantEvaluator.SCOPE_EVALUATE));

        Map<String, Object> req = evaluate(grantOf(TPP, ALICE), clientOnly);

        assertNotNull(req);
        Map<String, Object> subject = (Map<String, Object>) req.get("subject");
        assertEquals(ALICE, subject.get("id"),
                "the subject comes off the grant; the token never carried one");
    }

    /** The user-present case: an authorization-code token names the subject too. */
    @Test
    @SuppressWarnings("unchecked")
    void anAuthorizationCodeTokenEvaluatesItsOwnGrant() throws Exception {
        TokenClaims userToken = new TokenClaims(
                ALICE, TPP, "grant-123", List.of("accounts.read", GrantEvaluator.SCOPE_EVALUATE));

        Map<String, Object> req = evaluate(grantOf(TPP, ALICE), userToken);

        Map<String, Object> subject = (Map<String, Object>) req.get("subject");
        assertEquals(ALICE, subject.get("id"));
    }

    /** The agentic case: an extra vector over the same relationship, not a new party. */
    @Test
    @SuppressWarnings("unchecked")
    void anAgentsDelegatedTokenEvaluatesTheClientsGrant() throws Exception {
        TokenClaims delegated = new TokenClaims(
                ALICE, TPP, "grant-123",
                List.of("accounts.read", GrantEvaluator.SCOPE_EVALUATE),
                List.of("urn:agent:concierge:v2"));

        Map<String, Object> req = evaluate(grantOf(TPP, ALICE), delegated);

        Map<String, Object> ctx = (Map<String, Object>) req.get("context");
        Map<String, Object> actor = (Map<String, Object>) ctx.get("actor");
        assertEquals("urn:agent:concierge:v2", actor.get("id"));
        assertEquals(TPP, actor.get("operator"), "the agent's operator is still the grant's client");

        Map<String, Object> subject = (Map<String, Object>) req.get("subject");
        assertEquals(ALICE, subject.get("id"), "the grant relationship is unchanged by the agent");
    }

    // ---- the client leg is what authorises the question ----

    /**
     * The hole that checking only the subject leaves open: a rival TPP with its own
     * perfectly valid token for Alice must not be able to read Acme's consent with her.
     */
    @Test
    void anotherClientCannotEvaluateThisClientsGrant() {
        TokenClaims rivalsToken = new TokenClaims(
                ALICE, OTHER_TPP, "grant-123",
                List.of("accounts.read", GrantEvaluator.SCOPE_EVALUATE));

        var e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> evaluate(grantOf(TPP, ALICE), rivalsToken));

        assertEquals(GrantEvaluator.Refusal.NOT_YOUR_GRANT, e.refusal);
        assertEquals(TPP + ", token was issued to " + OTHER_TPP,
                e.getMessage().substring(e.getMessage().indexOf(TPP)),
                "the refusal names the client leg, not the subject");
    }

    @Test
    void anotherClientCannotEvaluateWithAClientCredentialsTokenEither() {
        TokenClaims rivalMachine = new TokenClaims(
                null, OTHER_TPP, null, List.of(GrantEvaluator.SCOPE_EVALUATE));

        var e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> evaluate(grantOf(TPP, ALICE), rivalMachine));
        assertEquals(GrantEvaluator.Refusal.NOT_YOUR_GRANT, e.refusal);
    }

    // ---- the subject leg still holds when the token asserts one ----

    @Test
    void aTokenSubjectThatContradictsTheGrantIsRefused() {
        // Right client, wrong user: the client has conflated two of its own grants.
        TokenClaims wrongUser = new TokenClaims(
                "bob", TPP, "grant-123", List.of(GrantEvaluator.SCOPE_EVALUATE));

        var e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> evaluate(grantOf(TPP, ALICE), wrongUser));
        assertEquals(GrantEvaluator.Refusal.NOT_YOUR_GRANT, e.refusal);
    }

    @Test
    void aGrantNamingNoSubjectIsRefused() {
        // Nothing to decide about, and it must not silently become a decision about null.
        TokenClaims clientOnly = new TokenClaims(null, TPP, null, List.of(GrantEvaluator.SCOPE_EVALUATE));

        var e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> evaluate(grantOf(TPP, null), clientOnly));
        assertEquals(GrantEvaluator.Refusal.NO_SUBJECT, e.refusal);
    }

    @Test
    void aGrantNamingNoClientIsRefused() {
        TokenClaims clientOnly = new TokenClaims(null, TPP, null, List.of(GrantEvaluator.SCOPE_EVALUATE));

        var e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> evaluate(grantOf(null, ALICE), clientOnly));
        assertEquals(GrantEvaluator.Refusal.NOT_YOUR_GRANT, e.refusal,
                "a grant with no client leg cannot be matched to any caller");
    }
}
