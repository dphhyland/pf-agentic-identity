/*
 * The result of resolving a caller-asserted (unverified) discriminator against an evidenced instance.
 */
package com.pingidentity.ps.oidf.common;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What an {@link AssertedContextResolver} produces: additional context about a caller-supplied
 * discriminator (e.g. an Entra Agent ID {@code oid}) that the attester never cryptographically verifies,
 * layered on top of an already-{@link InstanceAttestationValidator}-verified {@link InstanceIdentity}.
 *
 * <p>{@code claims} are surfaced under the minted attestation's {@code workload.attributes.asserted} —
 * deliberately never merged into the top-level {@code workload} fields that represent proven facts, so a
 * relying party can tell "PF verified this" from "the platform asserted this" at a glance. {@code ceiling}
 * is an RFC 9396 {@code authorization_details} list that can only ever <em>narrow</em> the evidenced
 * instance's own ceiling — see {@link AttestationIssuanceServlet}'s use, which intersects rather than
 * unions.
 */
public final class AssertedContext {
    private final Map<String, Object> claims;
    private final List<Map<String, Object>> ceiling;

    public AssertedContext(Map<String, Object> claims, List<Map<String, Object>> ceiling) {
        this.claims = claims == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(claims));
        this.ceiling = ceiling == null ? List.of() : List.copyOf(ceiling);
    }

    /** Unverified, caller-asserted attributes — land under {@code workload.attributes.asserted}. */
    public Map<String, Object> claims() {
        return this.claims;
    }

    /** The asserted entitlement ceiling; intersected with (never unioned into) the evidenced ceiling. */
    public List<Map<String, Object>> ceiling() {
        return this.ceiling;
    }
}
