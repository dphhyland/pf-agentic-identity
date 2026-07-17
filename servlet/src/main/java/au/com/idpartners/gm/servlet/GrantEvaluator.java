package au.com.idpartners.gm.servlet;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Decides a Grant Evaluation API request, given a grant and a validated token.
 *
 * <p>This is the part of section 8.4.2 the authorization server owns: check the grant is
 * real, belongs to this client, and has not lapsed, before anything is asked of the PDP.
 * An expired or revoked grant carries no authority, so no policy question about it is
 * worth asking.
 *
 * <p>The model is the ordinary OAuth one, and it is worth being exact about: a grant is a
 * relationship between the <b>client</b>, this <b>authorization server</b>, and the
 * <b>subject</b>. Nothing here changes that. Asking about a grant is authorised by the
 * client leg; the subject is read off the grant. An agent, when there is one, is an extra
 * authorisation vector layered over that relationship -- it never becomes a party to it.
 *
 * <p>Which is why this serves more than agents. The same endpoint answers a TPP holding a
 * long-lived Open Banking consent, asking with a client_credentials token whether that
 * consent still covers an account before it bothers to refresh.
 *
 * <p>Everything downstream of that -- whether the consent actually covers this request,
 * and whether the subject still holds the access -- is the PDP's. This class only
 * assembles the question.
 *
 * <p>Takes a {@link GrantView} rather than PingFederate's AccessGrant, so the decision
 * logic is ordinary code that runs outside the server. All the PF-specific reading lives
 * in GrantView.from().
 */
public final class GrantEvaluator {

    /**
     * The scopes the spec gives each Grant Management operation. Each operation requires
     * exactly its own: a client that may ask "is this still allowed?" has no business
     * also being able to read or revoke the grant.
     */
    public static final String SCOPE_QUERY = "grant_management_query";
    public static final String SCOPE_REVOKE = "grant_management_revoke";
    public static final String SCOPE_EVALUATE = "grant_management_evaluate";

    private GrantEvaluator() {
    }

    /** Why a request was refused by the AS, before the PDP was consulted. */
    public enum Refusal {
        MISSING_SCOPE(403, "insufficient_scope", "This client may not evaluate grants."),
        GRANT_NOT_FOUND(404, "grant_not_found", "No such grant."),
        NOT_YOUR_GRANT(403, "unauthorized", "This grant belongs to someone else."),
        GRANT_EXPIRED(403, "grant_expired", "This consent has expired."),
        MISSING_RESOURCE(422, "missing_resource", "No resource was named in the request."),
        NO_SUBJECT(403, "invalid_grant", "This grant names no subject.");

        public final int status;
        public final String code;
        public final String userMessage;

        Refusal(int status, String code, String userMessage) {
            this.status = status;
            this.code = code;
            this.userMessage = userMessage;
        }
    }

    /** Thrown when the AS refuses before the PDP is reached. */
    public static class RefusedException extends Exception {
        public final Refusal refusal;

        RefusedException(Refusal refusal, String detail) {
            super(detail);
            this.refusal = refusal;
        }
    }

    /**
     * Checks this caller may touch this grant at all, for any Grant Management operation.
     *
     * <p>The rule is the grant's own shape: a grant is a relationship between the client,
     * this authorization server, and the subject. The <b>client leg authorises</b> — a
     * client may act on its own grants and only its own. The <b>subject is read off the
     * grant</b> (section 8.4.1), never taken from the token or the request body.
     *
     * <p>Query, revoke and evaluate all pass through here. They differ only in the scope
     * they require, per section 6.7.1 and the base spec: each operation needs exactly its
     * own, so a client permitted to ask whether access still holds cannot thereby read or
     * revoke the grant.
     *
     * @param grant         the grant named by the request, or null if there is none
     * @param token         the validated bearer token's claims
     * @param requiredScope the scope this operation demands
     */
    public static void authorise(GrantView grant, TokenClaims token, String requiredScope)
            throws RefusedException {

        if (!token.hasScope(requiredScope)) {
            throw new RefusedException(Refusal.MISSING_SCOPE,
                    "token carries " + token.getScopes() + ", needs " + requiredScope);
        }
        if (grant == null) {
            throw new RefusedException(Refusal.GRANT_NOT_FOUND, "no grant with that id");
        }

        // The client leg. This is the check that matters, and it is deliberately not the
        // subject check: verifying only that the token's sub matches the grant's would
        // let any client holding a token for Alice reach a *different* client's grant
        // with her.
        if (grant.clientId() == null || !grant.clientId().equals(token.getClientId())) {
            throw new RefusedException(Refusal.NOT_YOUR_GRANT,
                    "grant belongs to client " + grant.clientId()
                            + ", token was issued to " + token.getClientId());
        }

        // The subject comes from the grant, which is what lets this serve more than a
        // user-present flow. A TPP holding a long-lived consent asks with a
        // client_credentials token carrying no sub at all; the subject is still perfectly
        // well known, because the grant names it. Requiring it on the token would exclude
        // every Open Data client that is not mid-session with a user.
        String grantSubject = grant.subject();
        if (grantSubject == null || grantSubject.isBlank()) {
            throw new RefusedException(Refusal.NO_SUBJECT,
                    "grant " + grant.guid() + " names no subject");
        }

        // When the token does carry a subject -- an authorization-code token, or an
        // agent's delegated one -- it must be the grant's. Defence in depth: it catches a
        // client conflating its own grants, and it is the leg that would matter if the
        // client check above were ever relaxed.
        if (token.getSubject() != null && !token.getSubject().equals(grantSubject)) {
            throw new RefusedException(Refusal.NOT_YOUR_GRANT,
                    "grant is for subject " + grantSubject + ", token subject is " + token.getSubject());
        }
    }

    /**
     * The grant as section 6.2 describes it, for a query response.
     *
     * <p>The spec's response also carries a {@code claims} array. PingFederate's
     * AccessGrant models no claims, so there is nothing to populate it from and the field
     * is omitted rather than invented.
     */
    public static Map<String, Object> describe(GrantView grant) {
        Map<String, Object> out = new LinkedHashMap<>();

        // The spec renders each scope as an object, so that a scope may name the
        // resources it applies to. PF holds a flat scope string, so each becomes a bare
        // {"scope": "..."} with no resource.
        List<Map<String, Object>> scopes = new ArrayList<>();
        for (String s : grant.scopes()) {
            scopes.add(Map.of("scope", s));
        }
        out.put("scopes", scopes);

        if (!grant.authorizationDetails().isEmpty()) {
            out.put("authorization_details", grant.authorizationDetails());
        }
        return out;
    }

    /**
     * Checks the grant may be evaluated by this caller, and builds the AuthZEN request.
     *
     * @param grant       the grant named by the request, or null if there is none
     * @param token       the validated bearer token's claims
     * @param resourceType the resource type being asked about
     * @param resourceId   the specific resource
     * @param actionName   the action being attempted
     * @param actionProps  action properties, e.g. an amount
     * @param callerContext extra context supplied by the client
     */
    public static Map<String, Object> buildDecisionRequest(
            GrantView grant,
            TokenClaims token,
            String resourceType,
            String resourceId,
            String actionName,
            Map<String, Object> actionProps,
            Map<String, Object> callerContext) throws RefusedException {

        authorise(grant, token, SCOPE_EVALUATE);

        if (resourceType == null || resourceType.isBlank()) {
            throw new RefusedException(Refusal.MISSING_RESOURCE, "resource.type is required");
        }

        // Section 8.4.2: an expired grant carries no authority. Refuse here rather than
        // ask the PDP a question whose premise is already false.
        //
        // Only evaluate cares. Querying an expired grant is exactly how a client learns
        // it has expired, and revoking one is harmless.
        if (grant.isExpired(System.currentTimeMillis())) {
            throw new RefusedException(Refusal.GRANT_EXPIRED, "grant expired at " + grant.expires());
        }

        String grantSubject = grant.subject();

        // The subject is the principal whose authority is being exercised, even when an
        // agent is the one calling. The agent is a qualifier on that authority, not a
        // replacement for it -- an agent has no standing to read Alice's account except
        // through Alice.
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("type", "user");
        subject.put("id", grantSubject);

        Map<String, Object> action = new LinkedHashMap<>();
        action.put("name", actionName);
        if (actionProps != null && !actionProps.isEmpty()) {
            action.put("properties", actionProps);
        }

        Map<String, Object> resource = new LinkedHashMap<>();
        resource.put("type", resourceType);
        resource.put("id", resourceId);

        // The grant's constraints become the AuthZEN context. This is what lets a
        // general-purpose PDP decide against this specific consent.
        Map<String, Object> oauth = new LinkedHashMap<>();
        oauth.put("client_id", grant.clientId());
        oauth.put("grant_id", grant.guid());

        Map<String, Object> context = new LinkedHashMap<>();
        if (callerContext != null) {
            context.putAll(callerContext);
        }
        context.put("oauth", oauth);
        context.put("scopes", grant.scopes());
        context.put("authorization_details", grant.authorizationDetails());

        // Who is actually calling.
        //
        // Without this the PDP cannot tell "Alice asked" from "an agent asked on Alice's
        // behalf" -- the two are identical once act is dropped, which is impersonation in
        // everything but name. Naming the actor is what lets policy apply a third bound:
        // the agent's own authority, from its registration and attestation. Effective
        // access is then
        //
        //     grant  ∩  subject entitlement  ∩  agent authority
        //
        // and an agent can never widen what Alice granted, only be narrowed against it.
        //
        // Nothing is decided here. The actor is surfaced; the PDP judges it.
        Map<String, Object> actor = new LinkedHashMap<>();
        actor.put("delegated", token.isDelegated());
        // The agent operator is the registered client, present either way. It is who is
        // accountable for the agent, and is not the agent.
        actor.put("operator", token.getClientId());
        if (token.isDelegated()) {
            actor.put("id", token.getActor());
            actor.put("chain", token.getActorChain());
        }
        context.put("actor", actor);

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("subject", subject);
        request.put("action", action);
        request.put("resource", resource);
        request.put("context", context);
        return request;
    }
}
