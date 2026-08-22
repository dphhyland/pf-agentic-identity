package com.pingidentity.ps.oidf.harness;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Runs the in-process SSF self-verify under surefire, the same way
 * {@link AttestationFlowHarnessSmokeTest} pins {@code selfverify}: a real {@code SetMinter} mints a
 * CAEP session-revoked SET and the harness verifies its own signature and claims back.
 */
class SsfSelfVerifySmokeTest {

    @Test
    void selfVerifyPassesEveryCheck() throws Exception {
        assertEquals(0, SsfSelfVerify.selfVerify(), "SSF selfverify reported failures - see stdout");
    }
}
