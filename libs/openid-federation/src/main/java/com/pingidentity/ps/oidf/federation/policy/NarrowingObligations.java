/*
 * What a permit comes with.
 */
package com.pingidentity.ps.oidf.federation.policy;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The obligations a permit carries, all of them narrowing: the scopes, grant types and response types the client may
 * keep (null: no limit), the longest the registration may live in seconds (null: no limit), and Trust Mark types the
 * entity must hold, verified, for the registration to go ahead.
 *
 * <p>A policy decision point can refuse, or narrow what the federation allows; it can never widen it. Every set here is
 * intersected with what the registration would otherwise be, and the registration's end only ever brought forward.
 */
public record NarrowingObligations(Set<String> scopes, Set<String> grantTypes, Set<String> responseTypes, Long maxTtlSeconds,
                                   Set<String> requiredTrustMarks) {
    public static final NarrowingObligations NONE = new NarrowingObligations(null, null, null, null, Set.of());

    public NarrowingObligations {
        scopes = scopes == null ? null : Set.copyOf(scopes);
        grantTypes = grantTypes == null ? null : Set.copyOf(grantTypes);
        responseTypes = responseTypes == null ? null : Set.copyOf(responseTypes);
        if (maxTtlSeconds != null && maxTtlSeconds < 0) {
            throw new IllegalArgumentException("a registration cannot live for less than no time");
        }
        requiredTrustMarks = requiredTrustMarks == null ? Set.of() : Set.copyOf(requiredTrustMarks);
    }

    /** Whether it narrows nothing. */
    public boolean isEmpty() {
        return this.equals(NONE);
    }

    /** Both sets of obligations at once: each set intersected, the shorter life, the marks of both. */
    public NarrowingObligations and(NarrowingObligations other) {
        Set<String> marks = new LinkedHashSet<>(this.requiredTrustMarks);
        marks.addAll(other.requiredTrustMarks);
        return new NarrowingObligations(intersect(this.scopes, other.scopes), intersect(this.grantTypes, other.grantTypes),
                intersect(this.responseTypes, other.responseTypes), min(this.maxTtlSeconds, other.maxTtlSeconds), marks);
    }

    /** {@code draft} narrowed: only what it has and the obligations allow, ending no later than they allow. */
    public ClientDraft applyTo(ClientDraft draft, long now) {
        long expiresAt = this.maxTtlSeconds == null ? draft.expiresAt() : Math.min(draft.expiresAt(), now + this.maxTtlSeconds);
        return new ClientDraft(keep(draft.scopes(), this.scopes), Set.copyOf(keep(List.copyOf(draft.grantTypes()), this.grantTypes)),
                keep(draft.responseTypes(), this.responseTypes), expiresAt);
    }

    private static List<String> keep(List<String> values, Set<String> allowed) {
        return allowed == null ? values : values.stream().filter(allowed::contains).toList();
    }

    private static Set<String> intersect(Set<String> a, Set<String> b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        Set<String> both = new LinkedHashSet<>(a);
        both.retainAll(b);
        return both;
    }

    private static Long min(Long a, Long b) {
        return a == null ? b : b == null ? a : Long.valueOf(Math.min(a, b));
    }
}
