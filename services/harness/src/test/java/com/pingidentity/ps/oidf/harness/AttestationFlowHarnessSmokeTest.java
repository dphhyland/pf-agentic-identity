package com.pingidentity.ps.oidf.harness;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Runs the in-process {@code selfverify} walk under surefire. The harness reaches the verifier by
 * reflection on class names, so a package or constructor change would otherwise surface only when
 * someone runs the CLI by hand; this pins it to the build instead.
 */
class AttestationFlowHarnessSmokeTest {

    @Test
    void selfVerifyPassesEveryCheck() throws Exception {
        assertEquals(0, AttestationFlowHarness.selfVerify(), "selfverify reported failures - see stdout");
    }
}
