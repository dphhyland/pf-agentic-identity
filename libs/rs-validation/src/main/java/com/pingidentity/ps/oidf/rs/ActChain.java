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
 * wrong is a security bug rather than a formatting one. RFC 8693 §4.1, quoted from the RFC:
 *
 * <ol>
 *   <li><strong>{@code act} is a JSON object, not a string.</strong> "The "act" claim value is a JSON
 *       object, and members in the JSON object are claims that identify the actor." The legacy string
 *       form this platform once emitted is still parsed, and reported as {@link Parsed#legacyStringForm()};
 *       {@link DelegatedTokenValidator} refuses it unless a development deployment has switched it on.</li>
 *   <li><strong>Only the outermost actor may be authorised on.</strong> "The outermost "act" claim
 *       represents the current actor while nested "act" claims represent prior actors." And: "For the
 *       purpose of applying access control policy, the consumer of a token MUST only consider the token's
 *       top-level claims and the party identified as the current actor by the "act" claim. Prior actors
 *       identified by any nested "act" claims are informational only and are not to be considered in
 *       access control decisions." {@link Parsed#currentActor} is therefore the only accessor that returns
 *       a single value; the rest of the chain is available only as a list, deliberately awkward to mistake
 *       for an authorisation input.</li>
 * </ol>
 *
 * <p>{@link Parsed#malformed()} is set for anything else that is not that shape: an {@code act} that is
 * neither an object nor a string, a level that names no actor (no string {@code sub} or {@code iss}), a
 * nested {@code act} that is not an object, a {@code sub} or {@code iss} that is not a string, and a chain
 * deeper than {@link #MAX_CHAIN_DEPTH}. {@link DelegatedTokenValidator} refuses a malformed chain.
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
            return flatten(JSON.valueToTree(act), false);
        }
        if (act instanceof String text) {
            // The legacy form: a JSON object serialised into a string claim. Parsed so the deviation can be
            // reported; DelegatedTokenValidator refuses it unless development has switched it on.
            JsonNode node;
            try {
                node = JSON.readTree(text);
            } catch (Exception e) {
                return new Parsed(List.of(), true, true);
            }
            return node.isObject() ? flatten(node, true) : new Parsed(List.of(), true, true);
        }
        return new Parsed(List.of(), false, true);
    }

    /**
     * How deep an act chain may nest before flattening stops.
     *
     * <p>Bounded because no legitimate delegation chain is anywhere near this long, and a chain that goes
     * deeper is reported as malformed, so {@link DelegatedTokenValidator} refuses it rather than reading
     * part of it.
     *
     * <p>Kept equal to {@code TokenClaims.MAX_ACTOR_CHAIN} in {@code services/gm-api} — two independent
     * resource servers reading one RFC 8693 claim should not disagree about where a chain stops. These
     * modules share no dependency, so the constants cannot be shared; if you change one, change both.
     */
    static final int MAX_CHAIN_DEPTH = 10;

    /**
     * Flattens nested {@code act} objects, outermost (most recent) first. Malformed when a level names no
     * actor, carries a {@code sub} or {@code iss} that is not a string, nests an {@code act} that is not an
     * object, or goes deeper than {@link #MAX_CHAIN_DEPTH}; the actors read up to that point are still
     * reported.
     */
    private static Parsed flatten(JsonNode node, boolean legacy) {
        List<Actor> actors = new ArrayList<>();
        JsonNode current = node;
        boolean malformed = false;
        while (current != null) {
            if (!current.isObject() || actors.size() == MAX_CHAIN_DEPTH) {
                malformed = true;
                break;
            }
            JsonNode subject = current.get("sub");
            JsonNode issuer = current.get("iss");
            if (subject != null && !subject.isTextual() || issuer != null && !issuer.isTextual()
                    || subject == null && issuer == null) {
                malformed = true;
                break;
            }
            actors.add(new Actor(subject == null ? null : subject.asText(), issuer == null ? null : issuer.asText()));
            current = current.get("act");
        }
        return new Parsed(List.copyOf(actors), legacy, malformed);
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
