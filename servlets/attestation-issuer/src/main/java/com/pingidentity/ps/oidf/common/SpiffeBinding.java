/*
 * A single SPIFFE-ID → client binding entry (the one-to-many instance registration).
 */
package com.pingidentity.ps.oidf.common;

import java.util.List;
import java.util.Map;

/**
 * One entry of a client's {@code attestation_instances} list: a SPIFFE ID permitted to obtain an
 * attestation as an instance of the client, with optional per-instance {@code entitlement} (an RFC 9396
 * {@code authorization_details} ceiling for this instance) and {@code metadata} (attributes carried into
 * the issued attestation's {@code workload.attributes}, for later per-instance enforcement). A bare
 * {@code spiffe_id} entry means "allowed, no extra claims".
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

    /** This instance's RFC 9396 entitlement ceiling; empty if the entry defers to the client-level ceiling. */
    public List<Map<String, Object>> entitlement() {
        return this.entitlement;
    }

    /** Attester-asserted per-instance attributes, surfaced as {@code workload.attributes}; empty if none. */
    public Map<String, Object> metadata() {
        return this.metadata;
    }
}
