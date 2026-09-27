/*
 * PF_AUTHORITY_INSECURE_TLS through InsecureTls: any chain, but still the host dialled.
 */
package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HostedEntityRegistrarInsecureTlsTest {

    private static final String CREATED = "{\"entityId\":\"https://authority.example/agents/a1\"}";

    @TempDir
    static Path dir;
    private static SelfSignedTlsServer rightName;
    private static SelfSignedTlsServer wrongName;

    @BeforeAll
    static void start() throws Exception {
        rightName = new SelfSignedTlsServer(dir, "localhost", 201, CREATED);
        wrongName = new SelfSignedTlsServer(dir, "wrong.example", 201, CREATED);
    }

    @AfterAll
    static void stop() {
        rightName.close();
        wrongName.close();
    }

    private static String register(SelfSignedTlsServer server, boolean insecureTls) throws EnrolmentException {
        return new HostedEntityRegistrar.PingFederate("https://authority.example", server.url(""), "admin-token", insecureTls)
                .register("a1", Map.of("kty", "EC"), Map.of(), null, null);
    }

    @Test
    void theSwitchAcceptsASelfSignedCertificateForTheHostDialled() throws Exception {
        assertEquals("https://authority.example/agents/a1", register(rightName, true));
    }

    @Test
    void theSwitchStillRefusesACertificateForAnotherName() {
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> register(wrongName, true));
        assertTrue(SelfSignedTlsServer.isWrongName(e), String.valueOf(e));
    }

    @Test
    void withoutTheSwitchTheChainIsChecked() {
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> register(rightName, false));
        assertFalse(SelfSignedTlsServer.isWrongName(e), String.valueOf(e));
        assertEquals("PF_AUTHORITY_INSECURE_TLS", HostedEntityRegistrar.PingFederate.INSECURE_TLS);
    }
}
