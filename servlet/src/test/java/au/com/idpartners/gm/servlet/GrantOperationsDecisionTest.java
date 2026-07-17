package au.com.idpartners.gm.servlet;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The retryable split is the whole value of the reason vocabulary, and the MCP surface
 * turns it into guidance a model acts on. Getting it wrong sends users through pointless
 * consent flows, or worse, tells a model to give up on a problem the user could fix.
 *
 * <p>A user can consent again to a consent problem. Nobody can consent to access they do
 * not have -- so an entitlement denial, a missing grant, or a wrong-client refusal must
 * not invite a retry.
 */
class GrantOperationsDecisionTest {

    private static GrantOperations.Decision denied(String reasonId) {
        return new GrantOperations.Decision(false, reasonId, "", true);
    }

    @Test
    void consentProblemsAreRetryable() {
        for (String r : new String[]{
                "resource_not_consented", "action_not_consented", "missing_scope",
                "no_consent_for_resource_type", "amount_exceeds_consented_limit"}) {
            assertTrue(denied(r).retryable(), r + " is fixable by consenting again");
        }
    }

    @Test
    void entitlementProblemsAreNotRetryable() {
        assertFalse(denied("subject_not_entitled").retryable(),
                "the user does not hold it; consent cannot conjure it");
        assertFalse(denied("entitlement_lacks_right").retryable(),
                "the user's own rights stop short");
    }

    @Test
    void aMissingOrForeignGrantIsNotRetryable() {
        assertFalse(denied("grant_not_found").retryable(), "the grant is gone");
        assertFalse(denied("grant_expired").retryable(), "the grant lapsed");
        assertFalse(denied(GrantEvaluator.Refusal.NOT_YOUR_GRANT.code).retryable(),
                "wrong grant id; consenting does not change whose grant it is");
    }

    @Test
    void aPermitIsNeverRetryable() {
        assertFalse(new GrantOperations.Decision(true, "consent_covers_request", "", true).retryable());
    }

    @Test
    void anUnknownReasonDefaultsToRetryable() {
        // A reason id this build does not recognise is more safely treated as a consent
        // problem the user might fix than as a dead end -- the failure mode is a wasted
        // prompt, not a lost recovery path.
        assertTrue(denied("some_future_reason").retryable());
    }
}
