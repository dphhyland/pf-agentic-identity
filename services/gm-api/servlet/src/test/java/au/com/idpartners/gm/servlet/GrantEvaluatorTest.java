package au.com.idpartners.gm.servlet;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GrantEvaluatorTest {

    private static final String SUB = "alice";

    private static GrantView grant(String subject, List<String> scopes, Long expires,
                                   List<Map<String, Object>> details) {
        return new GrantView("grant-123", subject, "acme-budgeting", scopes, expires, details);
    }

    private static List<Map<String, Object>> consent() {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("type", "account_information");
        d.put("actions", List.of("read_balance"));
        d.put("locations", List.of("111", "222"));
        return List.of(d);
    }

    private static GrantView validGrant() {
        return grant(SUB, List.of("accounts.read", "grant_management_evaluate"),
                System.currentTimeMillis() + 86_400_000L, consent());
    }

    private static TokenClaims token(String subject, String... scopes) {
        return new TokenClaims(subject, "acme-budgeting", "grant-123", List.of(scopes));
    }

    private static TokenClaims validToken() {
        return token(SUB, "accounts.read", GrantEvaluator.SCOPE_EVALUATE);
    }

    private static Map<String, Object> build(GrantView g, TokenClaims t)
            throws GrantEvaluator.RefusedException {
        return GrantEvaluator.buildDecisionRequest(
                g, t, "account", "111", "read_balance", null, null);
    }

    // ---- the AuthZEN request the PDP will decide ----

    @Test
    @SuppressWarnings("unchecked")
    void buildsTheDecisionRequestFromTheGrant() throws Exception {
        Map<String, Object> req = build(validGrant(), validToken());

        Map<String, Object> subject = (Map<String, Object>) req.get("subject");
        assertEquals("user", subject.get("type"));
        assertEquals(SUB, subject.get("id"), "the subject comes from the grant, not the request");

        assertEquals("read_balance", ((Map<String, Object>) req.get("action")).get("name"));
        assertEquals("account", ((Map<String, Object>) req.get("resource")).get("type"));
        assertEquals("111", ((Map<String, Object>) req.get("resource")).get("id"));

        Map<String, Object> ctx = (Map<String, Object>) req.get("context");
        assertEquals(List.of("accounts.read", "grant_management_evaluate"), ctx.get("scopes"));

        Map<String, Object> oauth = (Map<String, Object>) ctx.get("oauth");
        assertEquals("acme-budgeting", oauth.get("client_id"));
        assertEquals("grant-123", oauth.get("grant_id"));

        // The consent must reach the PDP intact. In-process it is already typed, which
        // is the whole advantage over unpicking it from a grant attribute.
        List<Map<String, Object>> details = (List<Map<String, Object>>) ctx.get("authorization_details");
        assertEquals(1, details.size());
        assertEquals("account_information", details.get(0).get("type"));
        assertEquals(List.of("111", "222"), details.get(0).get("locations"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void passesActionPropertiesThrough() throws Exception {
        Map<String, Object> req = GrantEvaluator.buildDecisionRequest(
                validGrant(), validToken(), "payment", "pmt-1", "initiate_payment",
                Map.of("amount", 500), null);

        Map<String, Object> action = (Map<String, Object>) req.get("action");
        assertEquals(Map.of("amount", 500), action.get("properties"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void callerContextDoesNotOverrideGrantConstraints() throws Exception {
        // A client must not be able to widen its own consent by passing scopes or
        // authorization_details in the request context.
        Map<String, Object> hostile = new LinkedHashMap<>();
        hostile.put("scopes", List.of("payments.write"));
        hostile.put("authorization_details", List.of(Map.of("type", "payment_initiation")));

        Map<String, Object> req = GrantEvaluator.buildDecisionRequest(
                validGrant(), validToken(), "account", "111", "read_balance", null, hostile);

        Map<String, Object> ctx = (Map<String, Object>) req.get("context");
        assertEquals(List.of("accounts.read", "grant_management_evaluate"), ctx.get("scopes"),
                "the grant's scopes must win over anything the caller supplied");
        List<Map<String, Object>> details = (List<Map<String, Object>>) ctx.get("authorization_details");
        assertEquals("account_information", details.get(0).get("type"),
                "the grant's consent must win over anything the caller supplied");
    }

    // ---- what the AS refuses before the PDP is consulted (section 8.4.2) ----

    @Test
    void refusesATokenWithoutTheEvaluateScope() {
        var e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> build(validGrant(), token(SUB, "accounts.read")));
        assertEquals(GrantEvaluator.Refusal.MISSING_SCOPE, e.refusal);
    }

    @Test
    void refusesAnUnknownGrant() {
        var e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> build(null, validToken()));
        assertEquals(GrantEvaluator.Refusal.GRANT_NOT_FOUND, e.refusal);
    }

    @Test
    void refusesSomeoneElsesGrant() {
        // The check that stops a client asking about another user's consent.
        var e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> build(validGrant(), token("mallory", "accounts.read", GrantEvaluator.SCOPE_EVALUATE)));
        assertEquals(GrantEvaluator.Refusal.NOT_YOUR_GRANT, e.refusal);
    }

    @Test
    void refusesAnExpiredGrant() {
        GrantView expired = grant(SUB, List.of("accounts.read", "grant_management_evaluate"),
                System.currentTimeMillis() - 1000L, consent());
        var e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> build(expired, validToken()));
        assertEquals(GrantEvaluator.Refusal.GRANT_EXPIRED, e.refusal);
    }

    @Test
    void refusesARequestNamingNoResource() {
        var e = assertThrows(GrantEvaluator.RefusedException.class,
                () -> GrantEvaluator.buildDecisionRequest(
                        validGrant(), validToken(), null, "111", "read_balance", null, null));
        assertEquals(GrantEvaluator.Refusal.MISSING_RESOURCE, e.refusal);
        assertEquals(422, e.refusal.status, "section 6.7.4");
    }

    @Test
    void aGrantWithNoExpiryDoesNotExpire() throws Exception {
        GrantView g = grant(SUB, List.of("accounts.read", "grant_management_evaluate"), null, consent());
        assertFalse(build(g, validToken()).isEmpty());
    }

    @Test
    void aGrantWithoutConsentSendsNoDetails() throws Exception {
        GrantView g = grant(SUB, List.of("accounts.read", "grant_management_evaluate"), null, null);
        @SuppressWarnings("unchecked")
        Map<String, Object> ctx = (Map<String, Object>) build(g, validToken()).get("context");
        assertTrue(((List<?>) ctx.get("authorization_details")).isEmpty(),
                "scope-only grants are legitimate");
    }

    @Test
    void expiryIsInclusiveOfNow() {
        long now = System.currentTimeMillis();
        assertFalse(grant(SUB, List.of(), now + 1, null).isExpired(now));
        assertTrue(grant(SUB, List.of(), now - 1, null).isExpired(now));
        assertFalse(grant(SUB, List.of(), null, null).isExpired(now), "no expiry means no expiry");
        assertFalse(grant(SUB, List.of(), 0L, null).isExpired(now), "zero means unset");
    }
}
