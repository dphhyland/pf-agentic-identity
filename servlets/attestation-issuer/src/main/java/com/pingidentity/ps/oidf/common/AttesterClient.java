/*
 * One attestation-enabled client the attester serves: its id paired with its parsed config.
 */
package com.pingidentity.ps.oidf.common;

/**
 * A single client the attester can mint for: the {@code client_id} the minted attestation's {@code sub}
 * will carry, paired with its {@link AttestationIssuanceConfig}. The workload never names a client — the
 * attester enumerates these and reverse-maps the workload's <em>evidence identity</em> (SPIFFE ID) onto
 * one of them. Which client an identity belongs to is the attester's knowledge alone.
 */
public final class AttesterClient {
    private final String clientId;
    private final AttestationIssuanceConfig config;

    public AttesterClient(String clientId, AttestationIssuanceConfig config) {
        this.clientId = clientId;
        this.config = config;
    }

    public String clientId() {
        return this.clientId;
    }

    public AttestationIssuanceConfig config() {
        return this.config;
    }
}
