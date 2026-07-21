package au.com.idpartners.gm.servlet;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The claims of a validated access token, in the shape this API cares about.
 *
 * <p>Three identities can appear in one token, and conflating them is the central
 * failure mode of agentic access:
 *
 * <ul>
 *   <li><b>The principal</b> ({@code sub}) — whose authority is being exercised. Alice.
 *   <li><b>The actor</b> ({@code act.sub}) — the agent actually performing the call.
 *   <li><b>The agent operator</b> ({@code client_id}) — the legal entity responsible for
 *       the agent, and the registered OAuth client. Not the agent.
 * </ul>
 *
 * <p>A token with {@code sub: alice} and no {@code act} is <em>impersonation</em>: it is
 * indistinguishable from one Alice obtained herself, and any agent behind it is invisible.
 * A token with {@code sub: alice, act: {sub: agent}} is <em>delegation</em>: the agent is
 * named, so policy and audit can see it. Delegation is the only shape worth evaluating
 * for an agent, and reading {@code act} is what makes the difference visible here.
 */
public final class TokenClaims {

    /**
     * How deep an act chain may nest before we stop walking.
     *
     * <p>The chain comes off an attacker-influenced token. A cyclic or absurdly deep
     * structure must not become an infinite loop inside a request, and no legitimate
     * delegation chain is anywhere near this long.
     */
    static final int MAX_ACTOR_CHAIN = 10;

    private final String subject;
    private final String clientId;
    private final String grantId;
    private final List<String> scopes;
    private final List<String> actorChain;

    public TokenClaims(String subject, String clientId, String grantId, List<String> scopes) {
        this(subject, clientId, grantId, scopes, List.of());
    }

    public TokenClaims(String subject, String clientId, String grantId,
                       List<String> scopes, List<String> actorChain) {
        this.subject = subject;
        this.clientId = clientId;
        this.grantId = grantId;
        this.scopes = scopes == null ? List.of() : List.copyOf(scopes);
        this.actorChain = actorChain == null ? List.of() : List.copyOf(actorChain);
    }

    /**
     * Reads the claims this API needs out of a JWT payload.
     *
     * <p>{@code agid} is PingFederate's access-grant GUID claim — the id of the grant the
     * token was issued against. It is what lets a client name its own grant without being
     * told the id out of band, and is configured on the access token manager as
     * "Access Grant GUID Claim Name".
     */
    public static TokenClaims from(Map<String, Object> payload) {
        return new TokenClaims(
                asString(payload.get("sub")),
                asString(payload.get("client_id")),
                asString(payload.get("agid")),
                splitScopes(payload.get("scope")),
                actorChain(payload.get("act")));
    }

    /** The principal: whose authority is being exercised. */
    public String getSubject() {
        return subject;
    }

    /**
     * The agent operator: the registered OAuth client. This is the legal entity
     * responsible for the agent, not the agent itself.
     */
    public String getClientId() {
        return clientId;
    }

    /** The grant this token was issued against, or null. */
    public String getGrantId() {
        return grantId;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }

    /**
     * The actor chain, current actor first, then each prior actor.
     *
     * <p>Per RFC 8693 §4.1 the outermost {@code act} is the current actor and nested
     * {@code act} claims are prior actors, so for
     * {@code act: {sub: A2, act: {sub: A1}}} this returns {@code [A2, A1]}: A2 is
     * acting now, having received the authority via A1.
     *
     * <p>Empty for a token the principal obtained directly.
     */
    public List<String> getActorChain() {
        return actorChain;
    }

    /** The agent making this call, or null if the principal is acting directly. */
    public String getActor() {
        return actorChain.isEmpty() ? null : actorChain.get(0);
    }

    /** Whether an agent is acting on the principal's behalf. */
    public boolean isDelegated() {
        return !actorChain.isEmpty();
    }

    /**
     * Walks the nested {@code act} claim into a flat chain.
     *
     * <p>Anything that is not a well-formed chain yields what was read so far rather than
     * an error: a malformed {@code act} must not be silently treated as "no agent", which
     * would turn a delegated call into one that looks like the principal acting alone.
     * What is read is handed to the PDP, which decides what to make of it.
     */
    static List<String> actorChain(Object act) {
        List<String> chain = new ArrayList<>();
        Object node = act;
        for (int depth = 0; depth < MAX_ACTOR_CHAIN && node instanceof Map<?, ?> map; depth++) {
            Object sub = map.get("sub");
            if (sub != null && !sub.toString().isBlank()) {
                chain.add(sub.toString());
            }
            node = map.get("act");
        }
        return chain;
    }

    /** OAuth renders scope as one space-separated string; tolerate a list too. */
    static List<String> splitScopes(Object scope) {
        if (scope instanceof String s) {
            List<String> out = new ArrayList<>();
            for (String part : s.trim().split("\\s+")) {
                if (!part.isEmpty()) {
                    out.add(part);
                }
            }
            return out;
        }
        if (scope instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object o : list) {
                if (o != null) {
                    out.add(o.toString());
                }
            }
            return out;
        }
        return Collections.emptyList();
    }

    private static String asString(Object o) {
        return o == null ? null : o.toString();
    }
}
