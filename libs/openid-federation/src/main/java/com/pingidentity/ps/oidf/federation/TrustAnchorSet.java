/*
 * The Trust Anchors a deployment validates chains against.
 */
package com.pingidentity.ps.oidf.federation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * An ordered, immutable set of {@link TrustAnchor}s, each with its own pinned keys.
 *
 * <p>OpenID Federation 1.0 lets an entity belong to several federations, and a relying party to trust
 * several Trust Anchors (§4, §10.1 "ignoring the authority hints that end in an unknown Trust Anchor";
 * §10.3 choosing one of the valid chains). Keys are always looked up for the anchor a statement claims
 * to be issued by, so two anchors never verify each other's statements.
 *
 * <p>Order is preference: when a caller names no anchor, validation tries them in configuration order.
 * {@link #select} applies a caller's own preference (the resolve endpoint's repeatable
 * {@code trust_anchor} parameter) and never widens the set: an anchor the deployment does not trust
 * cannot be requested into it.
 */
public final class TrustAnchorSet {
    private final List<TrustAnchor> anchors;

    private TrustAnchorSet(List<TrustAnchor> anchors) {
        this.anchors = List.copyOf(anchors);
    }

    public static TrustAnchorSet empty() {
        return new TrustAnchorSet(List.of());
    }

    /**
     * @throws IllegalArgumentException when two anchors share an entity identifier (after trailing-slash
     *                                  normalisation)
     */
    public static TrustAnchorSet of(List<TrustAnchor> anchors) {
        List<TrustAnchor> ordered = new ArrayList<>();
        for (TrustAnchor anchor : Objects.requireNonNull(anchors, "anchors")) {
            Objects.requireNonNull(anchor, "anchor");
            for (TrustAnchor existing : ordered) {
                if (EntityId.same(existing.entityId(), anchor.entityId())) {
                    throw new IllegalArgumentException("Trust anchor " + anchor.entityId() + " is configured twice");
                }
            }
            ordered.add(anchor);
        }
        return new TrustAnchorSet(ordered);
    }

    public static TrustAnchorSet of(TrustAnchor... anchors) {
        return of(List.of(anchors));
    }

    /**
     * Parses {@code {"<anchor entity id>": <JWK Set>, ...}}; member order is preference order.
     *
     * @throws IllegalArgumentException when the document is not a JSON object of JWK Sets, or any set is
     *                                  not a usable public key set (see {@link TrustAnchor#of})
     */
    public static TrustAnchorSet parseJson(String json) {
        if (json == null || json.isBlank()) {
            throw new IllegalArgumentException("Trust anchor set is empty: expected {\"<anchor entity id>\": {\"keys\":[...]}, ...}");
        }
        Map<String, Object> parsed;
        try {
            parsed = new ObjectMapper().readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException("Trust anchor set is not a JSON object of JWK Sets");
        }
        List<TrustAnchor> anchors = new ArrayList<>();
        for (Map.Entry<String, Object> entry : parsed.entrySet()) {
            if (!(entry.getValue() instanceof Map)) {
                throw new IllegalArgumentException("Trust anchor " + entry.getKey() + " is not mapped to a JWK Set");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> jwks = (Map<String, Object>) entry.getValue();
            anchors.add(TrustAnchor.of(entry.getKey(), jwks));
        }
        return of(anchors);
    }

    /** True when {@code json} looks like a map of anchors rather than a single JWK Set ({@code {"keys": ...}}). */
    public static boolean looksLikeAnchorMap(String json) {
        if (json == null || json.isBlank()) {
            return false;
        }
        try {
            Map<String, Object> parsed = new ObjectMapper().readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {});
            return !parsed.containsKey("keys");
        } catch (Exception e) {
            return false;
        }
    }

    /** This set with {@code anchor} added, or replacing the anchor with the same entity identifier in place. */
    public TrustAnchorSet plus(TrustAnchor anchor) {
        Objects.requireNonNull(anchor, "anchor");
        List<TrustAnchor> next = new ArrayList<>(this.anchors);
        for (int i = 0; i < next.size(); i++) {
            if (EntityId.same(next.get(i).entityId(), anchor.entityId())) {
                next.set(i, anchor);
                return new TrustAnchorSet(next);
            }
        }
        next.add(anchor);
        return new TrustAnchorSet(next);
    }

    /** The anchor this set holds for {@code entityId}, compared with {@link EntityId#same}. */
    public Optional<TrustAnchor> find(String entityId) {
        for (TrustAnchor anchor : this.anchors) {
            if (EntityId.same(anchor.entityId(), entityId)) {
                return Optional.of(anchor);
            }
        }
        return Optional.empty();
    }

    public boolean contains(String entityId) {
        return this.find(entityId).isPresent();
    }

    public boolean isEmpty() {
        return this.anchors.isEmpty();
    }

    public int size() {
        return this.anchors.size();
    }

    /** The anchors, in preference order. */
    public List<TrustAnchor> anchors() {
        return this.anchors;
    }

    public List<String> entityIds() {
        List<String> ids = new ArrayList<>(this.anchors.size());
        for (TrustAnchor anchor : this.anchors) {
            ids.add(anchor.entityId());
        }
        return List.copyOf(ids);
    }

    /**
     * The anchors to try for a request that names some: {@code requested} ∩ this set, in the caller's
     * order. An empty or absent request means every anchor, in configuration order.
     *
     * @throws FederationException {@link FederationError#INVALID_TRUST_ANCHOR} when the caller named anchors
     *                             and none of them is trusted here
     */
    public List<TrustAnchor> select(List<String> requested) {
        if (requested == null || requested.isEmpty()) {
            return this.anchors;
        }
        List<TrustAnchor> selected = new ArrayList<>();
        for (String id : requested) {
            this.find(id).filter(a -> !selected.contains(a)).ifPresent(selected::add);
        }
        if (selected.isEmpty()) {
            throw new FederationException(FederationError.INVALID_TRUST_ANCHOR,
                    "none of the requested trust anchors is trusted here");
        }
        return List.copyOf(selected);
    }

    @Override
    public String toString() {
        return "TrustAnchorSet" + this.entityIds();
    }
}
