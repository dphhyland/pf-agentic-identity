/*
 * What a constrained field the candidate leaves out means to authorize().
 */
package com.pingidentity.ps.oidf.rar.model;

/**
 * How {@link RarModels#authorize} treats a field the ceiling constrains and the candidate omits.
 *
 * <p>{@link #INHERIT} is the token endpoint's reading: silence on a field is a request for the whole
 * of what the ceiling allows there, so the grant carries the ceiling's value for it - never more than
 * the ceiling, never a detail that names no constraint where the ceiling named one. {@link #STRICT} is
 * the reading of a comparison that cannot rewrite the candidate (a refresh's {@code isEqualOrSubset}):
 * the omission is a mismatch and the request is refused.
 */
public enum Omission {
    /** Fill the omitted field from the ceiling, then require containment. */
    INHERIT,
    /** Require containment of the candidate as sent. */
    STRICT
}
