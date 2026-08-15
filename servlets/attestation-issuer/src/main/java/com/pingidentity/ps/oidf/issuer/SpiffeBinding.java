/*
 * A single SPIFFE-ID → client binding entry (the one-to-many instance registration).
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.List;
import java.util.Map;

/**
 * One entry of a client's {@code attestation_instances} list — an <em>instance archetype</em>: a pattern
 * over the proven instance subject, permitting any instance that matches it to obtain an attestation as
 * an instance of the client, with optional per-archetype {@code entitlement} (an RFC 9396
 * {@code authorization_details} ceiling for a matching instance) and {@code metadata} (attributes carried
 * into the issued attestation's {@code workload.attributes}, for later per-instance enforcement). A bare
 * {@code spiffe_id} entry means "allowed, no extra claims".
 *
 * <p>The pattern is the subject string itself: a literal value (e.g.
 * {@code spiffe://example.org/agents/agent-1}) matches only that exact instance, exactly as before this
 * class supported patterns at all; a value ending in {@code *} (e.g.
 * {@code spiffe://example.org/agents/*}) matches any instance subject sharing that prefix — an
 * <em>archetype</em> covering a whole class of instances (e.g. every replica of an autoscaled workload)
 * under one ceiling, rather than requiring one literal entry per instance.
 */
public final class SpiffeBinding {
    private final String spiffeId;
    private final List<Map<String, Object>> entitlement;
    private final Map<String, Object> metadata;

    public SpiffeBinding(String spiffeId, List<Map<String, Object>> entitlement, Map<String, Object> metadata) {
        this.spiffeId = spiffeId;
        this.entitlement = entitlement == null ? List.of() : List.copyOf(entitlement);
        this.metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
    }

    public String spiffeId() {
        return this.spiffeId;
    }

    /**
     * The instance subject this entry binds — the SPIFFE ID for a SPIFFE workload, or the wallet instance
     * id for a wallet binding. The format-neutral alias for {@link #spiffeId()}; matched against
     * {@link InstanceIdentity#subject()}.
     */
    public String subject() {
        return this.spiffeId;
    }

    /** This instance's RFC 9396 entitlement ceiling; empty if the entry defers to the client-level ceiling. */
    public List<Map<String, Object>> entitlement() {
        return this.entitlement;
    }

    /** Attester-asserted per-instance attributes, surfaced as {@code workload.attributes}; empty if none. */
    public Map<String, Object> metadata() {
        return this.metadata;
    }

    /**
     * Whether this archetype's pattern matches {@code candidateSubject}: exactly, if the pattern carries
     * no trailing {@code *}; by prefix, if it does.
     */
    public boolean matches(String candidateSubject) {
        if (candidateSubject == null || this.spiffeId == null) {
            return false;
        }
        if (this.spiffeId.endsWith("*")) {
            return candidateSubject.startsWith(this.spiffeId.substring(0, this.spiffeId.length() - 1));
        }
        return this.spiffeId.equals(candidateSubject);
    }

    /**
     * How specific this archetype's pattern is, for resolving an instance subject that matches more than
     * one archetype in the same client's bindings: an exact match always outranks any prefix match
     * (a wildcard covering an entire fleet must never shadow an instance's own, more specific entry), and
     * among prefix matches, the longer (more specific) prefix wins.
     */
    int specificity() {
        if (this.spiffeId == null) {
            return -1;
        }
        return this.spiffeId.endsWith("*") ? this.spiffeId.length() - 1 : Integer.MAX_VALUE;
    }
}
