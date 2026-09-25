/*
 * Which federation endpoints take client authentication.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import org.jose4j.json.JsonUtil;

/**
 * Client authentication at this entity's federation endpoints (OpenID Federation 1.0 §8.8): none by default, and per
 * endpoint what a federation chose - {@code optional} or {@code required}. What each endpoint takes is published as its
 * {@code <endpoint>_auth_methods} (§8.8.1), with {@code endpoint_auth_signing_alg_values_supported} beside them.
 */
public final class EndpointAuthPolicy {
    /** Whether an endpoint takes client authentication. */
    public enum Mode { NONE, OPTIONAL, REQUIRED }

    /** The §5.1.1 federation endpoints, by their metadata names. */
    public static final List<String> ENDPOINTS = List.of("federation_fetch_endpoint", "federation_list_endpoint",
            "federation_resolve_endpoint", "federation_trust_mark_status_endpoint", "federation_trust_mark_list_endpoint",
            "federation_trust_mark_endpoint", "federation_historical_keys_endpoint");
    /** The one method §8.8 defines. */
    public static final String PRIVATE_KEY_JWT = "private_key_jwt";
    /** What a Federation Entity Key can sign with: asymmetric JWS algorithms, never {@code none} (§5.1.1). */
    static final Set<String> ASYMMETRIC_ALGORITHMS = Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
            "ES512", "EdDSA");

    private static final EndpointAuthPolicy NONE = new EndpointAuthPolicy(Map.of(), List.of());

    private final Map<String, Mode> modes;
    private final List<String> signingAlgorithms;

    private EndpointAuthPolicy(Map<String, Mode> modes, List<String> signingAlgorithms) {
        this.modes = Map.copyOf(modes);
        this.signingAlgorithms = List.copyOf(signingAlgorithms);
    }

    /** No client authentication anywhere: §8.8's default. */
    public static EndpointAuthPolicy none() {
        return NONE;
    }

    /**
     * {@code {"federation_fetch_endpoint": "required", "federation_resolve_endpoint": "optional"}}: an endpoint not named
     * takes none. Blank is none everywhere.
     *
     * @param signingAlgorithms what a client may sign with - asymmetric algorithms only
     * @throws IllegalArgumentException for an endpoint §5.1.1 doesn't define, a mode that isn't one, an algorithm that
     *                                  isn't asymmetric, or no algorithm at all for an endpoint that takes authentication
     */
    public static EndpointAuthPolicy parse(String json, List<String> signingAlgorithms) {
        if (json == null || json.isBlank()) {
            return NONE;
        }
        Map<String, Object> raw;
        try {
            raw = JsonUtil.parseJson(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("not a JSON object of endpoint names and none, optional or required");
        }
        Map<String, Mode> modes = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : raw.entrySet()) {
            if (!ENDPOINTS.contains(entry.getKey())) {
                throw new IllegalArgumentException(entry.getKey() + " is not a federation endpoint (OpenID Federation 1.0 §5.1.1)");
            }
            modes.put(entry.getKey(), mode(entry.getValue()));
        }
        EndpointAuthPolicy policy = new EndpointAuthPolicy(modes, asymmetric(signingAlgorithms));
        if (policy.anyEnabled() && signingAlgorithms.isEmpty()) {
            throw new IllegalArgumentException("no signing algorithm is accepted, so no client could authenticate");
        }
        return policy;
    }

    /**
     * {@code algorithms}, each one a JWS algorithm a Federation Entity Key signs with: asymmetric, never {@code none}.
     *
     * @throws IllegalArgumentException naming the first that isn't
     */
    public static List<String> asymmetric(List<String> algorithms) {
        for (String alg : Objects.requireNonNull(algorithms, "algorithms")) {
            if (!ASYMMETRIC_ALGORITHMS.contains(alg)) {
                throw new IllegalArgumentException("a Federation Entity Key signs with one of " + new TreeSet<>(ASYMMETRIC_ALGORITHMS)
                        + ", not " + alg + " (OpenID Federation 1.0 §5.1.1, §8.8)");
            }
        }
        return List.copyOf(algorithms);
    }

    private static Mode mode(Object value) {
        for (Mode mode : Mode.values()) {
            if (mode.name().equalsIgnoreCase(String.valueOf(value))) {
                return mode;
            }
        }
        throw new IllegalArgumentException(value + " is not none, optional or required");
    }

    public Mode mode(String endpoint) {
        return this.modes.getOrDefault(endpoint, Mode.NONE);
    }

    /** Whether any endpoint takes client authentication. */
    public boolean anyEnabled() {
        return this.modes.values().stream().anyMatch(mode -> mode != Mode.NONE);
    }

    /**
     * §8.8.1: what {@code endpoint} publishes as its {@code _auth_methods} - {@code ["private_key_jwt"]} when required,
     * with {@code "none"} too when optional. Null when it takes none, which is what an absent parameter means.
     */
    public List<String> authMethods(String endpoint) {
        return switch (this.mode(endpoint)) {
            case NONE -> null;
            case OPTIONAL -> List.of("none", PRIVATE_KEY_JWT);
            case REQUIRED -> List.of(PRIVATE_KEY_JWT);
        };
    }

    public List<String> signingAlgorithms() {
        return this.signingAlgorithms;
    }
}
