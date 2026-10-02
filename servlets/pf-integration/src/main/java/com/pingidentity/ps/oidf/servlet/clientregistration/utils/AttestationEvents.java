/*
 * The attestation decisions the filter, the criterion and the start-up scan record.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import com.pingidentity.ps.oidf.platform.events.Events;

/**
 * The events of attestation-based client authentication (plan item O-2, the programme's decision 7): each decision of
 * the token-endpoint filter and of the OGNL criterion is {@code attestation.client.verified} or
 * {@code attestation.client.refused} (catalogued in openid-federation's {@code federation} catalogue), and a client
 * whose {@code attestation_*} properties are refused is {@code attestation.policy.invalid} (pf-integration's
 * {@code attestation} catalogue). Each names the client as its subject; none carries a property's value. Platform's
 * {@link Events} counts every one in {@code oidf_events_total}.
 */
public final class AttestationEvents {
    static final String FEDERATION = "federation";
    static final String ATTESTATION = "attestation";
    public static final String VERIFIED = "attestation.client.verified";
    public static final String REFUSED = "attestation.client.refused";
    public static final String POLICY_INVALID = "attestation.policy.invalid";

    /** Where a decision was made: the {@code endpoint} field. */
    public static final String FILTER = "token_endpoint_filter";
    public static final String CRITERION = "issuance_criterion";
    public static final String SCAN = "startup_scan";

    private AttestationEvents() {
    }

    /** {@code clientId}'s attestation, from {@code attester}, verified at {@code endpoint}. */
    public static void verified(String endpoint, String clientId, String attester) {
        Events.event(FEDERATION, VERIFIED).subject(clientId).partner(attester).role("ATTESTER").audit()
                .field("endpoint", endpoint).emit();
    }

    /** {@code clientId} refused at {@code endpoint} with the OAuth error {@code error}. */
    public static void refused(String endpoint, String clientId, String error) {
        Events.event(FEDERATION, REFUSED).failure(error).subject(clientId).audit()
                .field("endpoint", endpoint).emit();
    }

    /** {@code e}'s client refused for its property, found at {@code endpoint}; the value is never recorded. */
    public static void policyInvalid(String endpoint, AttestationPolicyException e) {
        Events.event(ATTESTATION, POLICY_INVALID).failure(e.problem()).subject(e.clientId()).audit()
                .field("property", e.property()).field("endpoint", endpoint).emit();
    }
}
