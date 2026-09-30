/*
 * Cloud evidence policies for the tests: development with nothing pinned, and production with each type pinned.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.Map;
import java.util.Set;

final class CloudPolicies {
    private CloudPolicies() {
    }

    /**
     * Development with no pin and no list: a client's own {@code attestation_evidence_issuer} is its pin, and a client
     * without one takes the provider's published issuer - what the validators' tests before 0.6.0 exercised.
     */
    static CloudTokenValidator.Policy development() {
        return CloudTokenValidator.Policy.of(Map.of(), CloudTokenValidator.Policy.DEFAULT_MAX_LIFETIME_SECONDS,
                null, null, null, null, false, false);
    }

    /** Production with {@code issuers} pinned per type and no list. */
    static CloudTokenValidator.Policy production(Map<String, Set<String>> issuers) {
        return CloudTokenValidator.Policy.of(issuers, CloudTokenValidator.Policy.DEFAULT_MAX_LIFETIME_SECONDS,
                null, null, null, null, false, true);
    }
}
