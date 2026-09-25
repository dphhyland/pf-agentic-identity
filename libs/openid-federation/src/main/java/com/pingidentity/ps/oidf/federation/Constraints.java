/*
 * OpenID Federation trust chain constraints.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The {@code constraints} claim of one Subordinate Statement (OpenID Federation 1.0 §6.2), parsed and
 * checked. Every Subordinate Statement's constraints apply independently, and "if any of the constraints
 * checks fails, the Trust Chain MUST be considered invalid" (§6.2).
 *
 * <ul>
 *   <li>{@code max_path_length} (§6.2.1): the most Intermediates allowed between the Entity setting it and
 *       the Trust Chain subject. For the Subordinate Statement at chain index {@code k} (ES[1] is the one
 *       about the subject), there are {@code k - 1} of them.</li>
 *   <li>{@code naming_constraints} (§6.2.2): RFC 5280 domain name constraints on the host of every Entity
 *       below the setter - the subject of its statement and everything under it. {@code .example.com}
 *       matches any host with at least one more label; {@code host.example.com} matches that host only;
 *       an excluded match fails "regardless of the information appearing in the permitted list".</li>
 *   <li>{@code allowed_entity_types} (§6.2.3): Entity Types not listed are removed from the subject's
 *       metadata - after its superior's metadata is applied and before policy. {@code federation_entity}
 *       is always kept and "MUST NOT be included in the constraint".</li>
 * </ul>
 *
 * <p>Where the text leaves room, this reads it closed: {@code permitted: []} permits nothing (RFC 5280 gives
 * a permitted subtree list at least one entry, so an empty one cannot mean "anything"), and an IP-literal
 * host matches only an identical constraint, never a {@code .suffix}. Unknown constraint parameters are
 * ignored, as §6.2 requires.
 */
public final class Constraints {
    static final String FEDERATION_ENTITY = "federation_entity";
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    private static final Pattern DNS_NAME = Pattern.compile("\\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*");

    private final Long maxPathLength;
    private final List<String> permitted;
    private final List<String> excluded;
    private final Set<String> allowedEntityTypes;

    private Constraints(Long maxPathLength, List<String> permitted, List<String> excluded, Set<String> allowedEntityTypes) {
        this.maxPathLength = maxPathLength;
        this.permitted = permitted;
        this.excluded = excluded;
        this.allowedEntityTypes = allowedEntityTypes;
    }

    /**
     * Checks {@code raw} is a {@code constraints} claim this entity could publish (§6.2) - for an operator's setting,
     * refused at start-up rather than in every statement a superior would then reject.
     *
     * @throws IllegalArgumentException naming what is wrong
     */
    public static void requireValid(Object raw) {
        parse(raw);
    }

    /**
     * @param raw the {@code constraints} claim value, or {@code null} when absent
     * @throws IllegalArgumentException naming what is not syntactically correct (§3.2 "Verify that its value
     *                                  is syntactically correct, as specified in Section 6.2")
     */
    static Constraints parse(Object raw) {
        if (raw == null) {
            return new Constraints(null, null, null, null);
        }
        if (!(raw instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("constraints is not a JSON object");
        }
        Long maxPathLength = null;
        if (map.containsKey("max_path_length")) {
            Object value = map.get("max_path_length");
            if (!(value instanceof Number n) || n.doubleValue() != Math.rint(n.doubleValue()) || n.doubleValue() < 0) {
                throw new IllegalArgumentException("max_path_length must be an integer of zero or more");
            }
            maxPathLength = n.longValue();
        }
        List<String> permitted = null;
        List<String> excluded = null;
        if (map.containsKey("naming_constraints")) {
            if (!(map.get("naming_constraints") instanceof Map<?, ?> naming)) {
                throw new IllegalArgumentException("naming_constraints is not a JSON object");
            }
            permitted = names(naming, "permitted");
            excluded = names(naming, "excluded");
        }
        Set<String> allowed = null;
        if (map.containsKey("allowed_entity_types")) {
            if (!(map.get("allowed_entity_types") instanceof List<?> types)) {
                throw new IllegalArgumentException("allowed_entity_types is not an array");
            }
            allowed = new LinkedHashSet<>();
            for (Object type : types) {
                if (!(type instanceof String s) || s.isBlank()) {
                    throw new IllegalArgumentException("allowed_entity_types holds something other than an Entity Type Identifier");
                }
                if (FEDERATION_ENTITY.equals(s)) {
                    throw new IllegalArgumentException("allowed_entity_types lists federation_entity, which is always allowed and"
                            + " MUST NOT be included (§6.2.3)");
                }
                allowed.add(s);
            }
        }
        return new Constraints(maxPathLength, permitted, excluded, allowed);
    }

    private static List<String> names(Map<?, ?> naming, String member) {
        if (!naming.containsKey(member)) {
            return null;
        }
        if (!(naming.get(member) instanceof List<?> values)) {
            throw new IllegalArgumentException("naming_constraints." + member + " is not an array");
        }
        List<String> out = new ArrayList<>();
        for (Object value : values) {
            if (!(value instanceof String s) || !DNS_NAME.matcher(s.toLowerCase(Locale.ROOT)).matches()) {
                throw new IllegalArgumentException("naming_constraints." + member + " holds " + (value instanceof String ? "'"
                        + value + "'" : "a non-string") + ", which is not a domain name constraint (a host, or .domain)");
            }
            out.add(s.toLowerCase(Locale.ROOT));
        }
        return List.copyOf(out);
    }

    boolean isEmpty() {
        return this.maxPathLength == null && this.permitted == null && this.excluded == null && this.allowedEntityTypes == null;
    }

    /**
     * §6.2.1 for the Subordinate Statement at chain index {@code statementIndex} (1 = the statement about the
     * subject).
     *
     * @return a description of the failure, or {@code null} when it holds
     */
    String checkPathLength(int statementIndex) {
        long intermediates = statementIndex - 1L;
        if (this.maxPathLength != null && intermediates > this.maxPathLength) {
            return "max_path_length is " + this.maxPathLength + " but " + intermediates
                    + " Intermediate(s) stand between the Entity that set it and the Trust Chain subject";
        }
        return null;
    }

    /**
     * §6.2.2 for every Entity Identifier below the setter.
     *
     * @return a description of the first failure, or {@code null} when every name is within the constraints
     */
    String checkNames(List<String> entityIds) {
        if (this.permitted == null && this.excluded == null) {
            return null;
        }
        for (String id : entityIds) {
            String host = EntityId.host(id);
            if (this.excluded != null) {
                for (String constraint : this.excluded) {
                    if (matches(host, constraint)) {
                        return id + " is in the excluded name subtree " + constraint;
                    }
                }
            }
            if (this.permitted != null) {
                boolean found = false;
                for (String constraint : this.permitted) {
                    found |= matches(host, constraint);
                }
                if (!found) {
                    return id + " is outside every permitted name subtree " + this.permitted;
                }
            }
        }
        return null;
    }

    static boolean matches(String host, String constraint) {
        if (constraint.startsWith(".")) {
            return !isIpLiteral(host) && host.endsWith(constraint);
        }
        return host.equals(constraint);
    }

    private static boolean isIpLiteral(String host) {
        return host.startsWith("[") || IPV4.matcher(host).matches();
    }

    /** The Entity Types this constraint allows, or {@code null} when it sets none. */
    Set<String> allowedEntityTypes() {
        return this.allowedEntityTypes;
    }

    /**
     * §6.2.3: the metadata without the Entity Types {@code allowed} does not list, {@code federation_entity}
     * always kept. {@code removed} receives what was taken out.
     */
    static Map<String, Object> filterEntityTypes(Map<String, Object> metadata, Set<String> allowed, Set<String> removed) {
        if (allowed == null) {
            return metadata;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : metadata.entrySet()) {
            if (FEDERATION_ENTITY.equals(entry.getKey()) || allowed.contains(entry.getKey())) {
                out.put(entry.getKey(), entry.getValue());
            } else {
                removed.add(entry.getKey());
            }
        }
        return out;
    }
}
