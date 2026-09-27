package com.pingidentity.ps.oidf.harness;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.pingidentity.ps.oidf.clientattestation.servlet.ClientAttestationChallengeServlet;
import jakarta.servlet.annotation.WebServlet;
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

    /**
     * {@code live} presents its challenge at the token endpoint, so it must come from the authorization server's
     * endpoint - the path that servlet is mapped at - and not the attester's, whose challenges the token endpoint
     * refuses.
     */
    @Test
    void liveFetchesItsChallengeWhereTheAuthorizationServersEndpointIsMapped() {
        assertEquals(ClientAttestationChallengeServlet.class.getAnnotation(WebServlet.class).urlPatterns()[0],
                AttestationFlowHarness.AS_CHALLENGE_PATH);
    }
}
