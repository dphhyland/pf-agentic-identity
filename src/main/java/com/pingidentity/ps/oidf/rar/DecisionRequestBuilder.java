/*
 * Strategy for turning an authorization_details entry into a governance-engine decision request.
 */
package com.pingidentity.ps.oidf.rar;

import java.util.Map;

/**
 * Builds the {@link DecisionRequest} for one RFC 9396 {@code authorization_details} entry. Pluggable so the
 * native governance-engine shape (the default {@link GovernanceEngineRequestBuilder}) can be swapped for an
 * AuthZEN {@code /access/v1/evaluation} builder later without touching the client or the processor.
 */
public interface DecisionRequestBuilder {

    /**
     * @param type             the {@code authorization_details} type
     * @param detail           the requested detail's fields
     * @param subject          attester-vouched context (never {@code null}; may be {@link AttestationSubject#empty()})
     * @param fallbackClientId the OAuth client id to use as the subject when the attestation context has none
     */
    DecisionRequest build(String type, Map<String, Object> detail, AttestationSubject subject, String fallbackClientId);
}
