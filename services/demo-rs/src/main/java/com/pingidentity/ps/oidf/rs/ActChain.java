/*
 * The RFC 8693 act claim: who is acting, on whose behalf.
 */
package com.pingidentity.ps.oidf.rs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Parses the RFC 8693 {@code act} claim into an ordered actor chain.
 *
 * <p>Two rules from the RFC are enforced here rather than left to callers, because getting either
 * wrong is a security bug rather than a formatting one:
 *
 * <ol>
 *   <li><strong>{@code act} is a JSON object, not a string.</strong> RFC 8693 §4.1 defines it as a
 *       claim whose value is a JSON object, optionally nested. The legacy string form this platform
 *       once emitted is still parsed, so an older token keeps working, but it is reported as
 *       {@link Parsed#legacyStringForm()} so a deployment can see it is running on a deviation.</li>
 *   <li><strong>Only the outermost actor may be authorised on.</strong> RFC 8693 §4.1: the nested
 *       actors describe prior delegation and are informational — <em>"the most recent actor is the
 *       outermost"</em>, and inner entries record history, not present authority. Authorising on a
 *       nested actor means granting a party that has already handed the token on. {@link #currentActor}
 *       is therefore the only accessor that returns a single value; the rest of the chain is available
 *       only as a list, deliberately awkward to mistake for an authorisation input.</li>
 * </ol>
 *
 * <p>For this platform the shape is: {@code sub} is the human, and {@code act.sub} is the opaque agent
 * instance identifier. A resource server can risk-assess on that identifier and can learn nothing else
 * from it without the instance registry.
 */
public final class ActChain {

    private static final ObjectMapper JSON = new ObjectMapper();

    private ActChain() {
    }

    /**
     * Reads the {@code act} claim from a set of token claims.
     *
     * @param claims the decoded token claims
     * @return the parsed chain; {@link Parsed#isEmpty()} when the token carries no {@code act}
     */
    public static Parsed parse(Map<String, Object> claims) {
        Object act = claims == null ? null : claims.get("act");
        if (act == null) {
            return new Parsed(List.of(), false, false);
        }
        if (act instanceof Map) {
            return new Parsed(flatten(JSON.valueToTree(act)), false, false);
        }
        if (act instanceof String text) {
            // The legacy form: a JSON object serialised into a string claim. Parsed so older tokens
            // keep working, flagged so the deviation is visible rather than permanent.
            try {
                JsonNode node = JSON.readTree(text);
                if (!node.isObject()) {
                    return new Parsed(List.of(), true, true);
                }
                return new Parsed(flatten(node), true, false);
            } catch (Exception e) {
                return new Parsed(List.of(), true, true);
            }
        }
        return new Parsed(List.of(), false, true);
    }

    /** Flattens nested {@code act} objects, outermost (most recent) first. */
    private static List<Actor> flatten(JsonNode node) {
        List<Actor> actors = new ArrayList<>();
        JsonNode current = node;
        // Bounded: a hostile token could otherwise nest until the parser runs out of stack.
        for (int depth = 0; current != null && current.isObject() && depth < 16; depth++) {
            String subject = current.path("sub").asText(null);
            String issuer = current.path("iss").asText(null);
            if (subject != null || issuer != null) {
                actors.add(new Actor(subject, issuer));
            }
            current = current.get("act");
        }
        return List.copyOf(actors);
    }

    /** One entry in the chain. */
    public record Actor(String subject, String issuer) {
    }

    /** The parsed chain, plus what was wrong with how it arrived. */
    public record Parsed(List<Actor> actors, boolean legacyStringForm, boolean malformed) {

        public boolean isEmpty() {
            return this.actors.isEmpty();
        }

        /**
         * The actor presenting the token — the only one that may be authorised on.
         *
         * <p>Empty when the token is not delegated at all, which a caller must treat as "no agent is
         * acting here" rather than as "any agent may".
         */
        public Optional<Actor> currentActor() {
            return this.actors.isEmpty() ? Optional.empty() : Optional.of(this.actors.get(0));
        }

        /**
         * Everything before the current actor, most recent first. Informational only: RFC 8693 is
         * explicit that prior actors record history, and authorising on one would grant a party that
         * has already passed the token along.
         */
        public List<Actor> priorActors() {
            return this.actors.size() <= 1 ? List.of() : List.copyOf(this.actors.subList(1, this.actors.size()));
        }

        /** How many hops the token has taken. */
        public int depth() {
            return this.actors.size();
        }
    }
}
