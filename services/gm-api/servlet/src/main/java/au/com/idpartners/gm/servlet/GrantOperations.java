package au.com.idpartners.gm.servlet;

import com.pingidentity.access.AccessGrantManagerAccessor;
import com.pingidentity.sdk.accessgrant.AccessGrantManager;

import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The Grant Management operations, independent of how they are asked for.
 *
 * <p>Two transports sit on this: {@link GrantsServlet} speaks the spec's REST shape, and
 * {@link McpServlet} speaks JSON-RPC to an AI agent. They must not diverge. Every rule
 * that decides whether a caller may act on a grant lives here and in
 * {@link GrantEvaluator}, so adding a transport cannot accidentally add a way around
 * them.
 *
 * <p>That matters more than tidiness. The MCP surface is reachable by an agent; if it
 * carried its own copy of the authorisation logic, the two copies would drift and the
 * looser one would become the way in.
 */
final class GrantOperations {

    private static final Logger LOG = Logger.getLogger(GrantOperations.class.getName());

    private final PfTokenVerifier verifier;
    private final PdpClient pdp;

    GrantOperations(PfTokenVerifier verifier, PdpClient pdp) {
        this.verifier = verifier;
        this.pdp = pdp;
    }

    PdpClient pdp() {
        return pdp;
    }

    /** The grant store could not be read. Distinct from the grant not existing. */
    static class GrantStoreException extends Exception {
        GrantStoreException(Throwable cause) {
            super(cause);
        }
    }

    /** The decision service could not be reached, so there is no answer. Not a denial. */
    static class UnavailableException extends Exception {
        UnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * The answer to "does this consent still permit this".
     *
     * @param permitted the decision
     * @param reasonId  the stable identifier a caller branches on
     * @param message   the reason, safe to show a human
     * @param fromPdp   false when the AS refused before the PDP was consulted
     */
    record Decision(boolean permitted, String reasonId, String message, boolean fromPdp) {

        /**
         * Whether re-consenting could change this answer.
         *
         * <p>It cannot when the subject does not hold the access: nobody can consent to
         * what they do not have. This is the single most useful thing a caller can know,
         * and the reason the ids are stable.
         */
        boolean retryable() {
            if (permitted) {
                return false;
            }
            return !GrantEvaluator.Refusal.NOT_YOUR_GRANT.code.equals(reasonId)
                    && !"subject_not_entitled".equals(reasonId)
                    && !"entitlement_lacks_right".equals(reasonId)
                    && !"grant_not_found".equals(reasonId)
                    && !"grant_expired".equals(reasonId);
        }
    }

    TokenClaims verify(String bearerToken) throws PfTokenVerifier.InvalidTokenException {
        return verifier.verify(bearerToken);
    }

    /**
     * Reads the grant in-process.
     *
     * <p>Returns null for a grant that does not exist, and throws when the store itself
     * could not be read. Those are different answers and must not share a signal: "no
     * such grant" is a decision, "I could not look" is an outage, and reporting the
     * second as the first tells a client its consent is gone when it is not.
     *
     * <p>The attributes are fetched lazily, only when the grant carries no native
     * consent -- otherwise every request would pay for a second store read.
     */
    GrantView lookup(String grantId) throws GrantStoreException {
        try {
            AccessGrantManager manager = AccessGrantManagerAccessor.getAccessGrantManager();
            return GrantView.from(manager.getByGuid(grantId), () -> {
                try {
                    return manager.getGrantAttributes(grantId);
                } catch (Exception e) {
                    LOG.log(Level.WARNING, "could not read grant attributes for " + grantId, e);
                    return null;
                }
            });
        } catch (Exception e) {
            throw new GrantStoreException(e);
        }
    }

    /** The grant's scopes and consent, per section 6.2. Requires grant_management_query. */
    Map<String, Object> describe(GrantView grant, TokenClaims token)
            throws GrantEvaluator.RefusedException {
        GrantEvaluator.authorise(grant, token, GrantEvaluator.SCOPE_QUERY);
        return GrantEvaluator.describe(grant);
    }

    /**
     * Ends the grant, per section 6.3. Requires grant_management_revoke.
     *
     * <p>Not exposed on the MCP surface: revocation is irreversible, and ending a user's
     * consent is not a decision an agent should reach through a tool call.
     */
    void revoke(GrantView grant, TokenClaims token)
            throws GrantEvaluator.RefusedException, UnavailableException {
        GrantEvaluator.authorise(grant, token, GrantEvaluator.SCOPE_REVOKE);
        try {
            AccessGrantManagerAccessor.getAccessGrantManager().revokeGrant(grant.guid());
        } catch (Exception e) {
            throw new UnavailableException("the grant could not be revoked", e);
        }
    }

    /**
     * Asks whether the grant still permits the action, per section 6.7.
     *
     * <p>An AS-side refusal comes back as a Decision, not an exception: "you may not"
     * is an answer. Only an unreachable PDP throws, because that is the absence of one.
     */
    Decision evaluate(GrantView grant, TokenClaims token, String resourceType, String resourceId,
                      String actionName, Map<String, Object> actionProps,
                      Map<String, Object> callerContext) throws UnavailableException {

        Map<String, Object> request;
        try {
            request = GrantEvaluator.buildDecisionRequest(
                    grant, token, resourceType, resourceId, actionName, actionProps, callerContext);
        } catch (GrantEvaluator.RefusedException e) {
            // Section 8.4.2: refused by the AS before the PDP was consulted.
            LOG.info("refused: " + e.refusal.code + ": " + e.getMessage());
            return new Decision(false, e.refusal.code, e.refusal.userMessage, false);
        }

        Map<String, Object> decision;
        try {
            decision = pdp.evaluate(request);
        } catch (PdpClient.PdpUnavailableException e) {
            throw new UnavailableException("the policy decision service is unavailable", e);
        }
        if (decision == null) {
            // A 200 whose body is the literal `null` decodes to null rather than
            // throwing. A PDP we cannot understand is an outage, not a denial.
            throw new UnavailableException("the policy decision service returned a null document", null);
        }

        boolean permitted = Boolean.TRUE.equals(decision.get("decision"));
        List<Map<String, Object>> reasons = userReasonsOf(decision);
        String id = reasons.isEmpty() ? "" : String.valueOf(reasons.get(0).get("id"));
        String message = reasons.isEmpty() ? "" : String.valueOf(reasons.get(0).get("message"));
        return new Decision(permitted, id, message, true);
    }

    /**
     * Asks which resources of a type the grant permits acting on — the AuthZEN resource
     * search. Returns the permitted ids, in order, or an empty list when the subject holds
     * none.
     *
     * <p>Same shape of contract as {@link #evaluate}: an AS-side refusal is an answer (an
     * empty set with the refusal logged), but an unreachable PDP throws. "I could not ask"
     * must never render as "you hold nothing" — the caller would tell the user something
     * false and act on it.
     */
    List<String> search(GrantView grant, TokenClaims token, String resourceType,
                        String actionName, Map<String, Object> callerContext)
            throws UnavailableException, GrantEvaluator.RefusedException {

        Map<String, Object> request =
                GrantEvaluator.buildSearchRequest(grant, token, resourceType, actionName, callerContext);

        Map<String, Object> response;
        try {
            response = pdp.search(request);
        } catch (PdpClient.PdpUnavailableException e) {
            throw new UnavailableException("the policy decision service is unavailable", e);
        }
        if (response == null) {
            throw new UnavailableException("the policy decision service returned a null document", null);
        }

        List<String> ids = new java.util.ArrayList<>();
        Object results = response.get("results");
        if (results instanceof List<?> list) {
            for (Object entry : list) {
                Object id = asMap(entry).get("id");
                if (id != null && !String.valueOf(id).isBlank()) {
                    ids.add(String.valueOf(id));
                }
            }
        }
        return ids;
    }

    /**
     * The user-facing half of the PDP's reasons, and only that half.
     *
     * <p>AuthZEN's reason_admin may name internal policy detail; section 8.4.3 says it
     * must not reach the client. Dropping it here is structural, not a filter that can
     * be forgotten downstream -- and it matters more on the MCP surface, where the text
     * goes into a model's context and from there potentially to a user.
     */
    static List<Map<String, Object>> userReasonsOf(Map<String, Object> decision) {
        Map<String, Object> context = asMap(decision.get("context"));
        if (context.isEmpty()) {
            return List.of();
        }
        Map<String, Object> reasonUser = asMap(context.get("reason_user"));
        if (reasonUser.isEmpty()) {
            return List.of();
        }
        Object message = reasonUser.containsKey("en")
                ? reasonUser.get("en")
                : reasonUser.values().iterator().next();

        Map<String, Object> reason = new java.util.LinkedHashMap<>();
        if (context.get("id") != null) {
            reason.put("id", context.get("id"));
        }
        reason.put("message", message == null ? "" : message.toString());
        return List.of(reason);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : Map.of();
    }
}
