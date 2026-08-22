package com.pingidentity.ps.oidf.harness;

import org.junit.jupiter.api.Test;

/**
 * Runs the in-process issuance self-verify under surefire, the same way
 * {@link AttestationFlowHarnessSmokeTest} pins {@code selfverify}: a real SVID + instance proof mints an
 * attestation via the module's public building blocks, and it must round-trip through
 * {@code ClientAttestationVerifier}; an unauthorised SPIFFE ID and a wrong-key proof must both be
 * refused. {@link AttestationIssuanceHarness#run()} throws {@link AssertionError} on the first failure,
 * so a clean run is simply "no exception".
 */
class AttestationIssuanceHarnessSmokeTest {

    @Test
    void selfVerifyPassesEveryCheck() throws Exception {
        AttestationIssuanceHarness.run();
    }
}
