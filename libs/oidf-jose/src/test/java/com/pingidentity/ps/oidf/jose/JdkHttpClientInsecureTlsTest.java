/*
 * OIDF_FEDERATION_IGNORE_SSL_ERRORS through InsecureTls: any chain, but still the host dialled.
 */
package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JdkHttpClientInsecureTlsTest {

    @TempDir
    static Path dir;
    private static SelfSignedTlsServer rightName;
    private static SelfSignedTlsServer wrongName;

    @BeforeAll
    static void start() throws Exception {
        rightName = new SelfSignedTlsServer(dir, "localhost", 200, "{}");
        wrongName = new SelfSignedTlsServer(dir, "wrong.example", 200, "{}");
    }

    @AfterAll
    static void stop() {
        rightName.close();
        wrongName.close();
    }

    @Test
    void ignoringSslErrorsAcceptsASelfSignedCertificateForTheHostDialled() throws Exception {
        assertEquals("{}", new JdkHttpClient(true, OutboundUrlPolicy.permissive()).get(rightName.url("/"), "application/json"));
        assertEquals(Set.of("OIDF_FEDERATION_IGNORE_SSL_ERRORS"),
                SelfSignedTlsServer.settingsRecordedBy(() -> new JdkHttpClient(true, OutboundUrlPolicy.permissive())));
    }

    @Test
    void ignoringSslErrorsStillRefusesACertificateForAnotherName() {
        Exception e = assertThrows(Exception.class,
                () -> new JdkHttpClient(true, OutboundUrlPolicy.permissive()).get(wrongName.url("/"), "application/json"));
        assertTrue(SelfSignedTlsServer.isWrongName(e), String.valueOf(e));
    }

    @Test
    void withoutTheSwitchTheChainIsChecked() {
        Exception e = assertThrows(Exception.class,
                () -> new JdkHttpClient(false, OutboundUrlPolicy.permissive()).get(rightName.url("/"), "application/json"));
        assertFalse(SelfSignedTlsServer.isWrongName(e), String.valueOf(e));
        assertEquals("OIDF_FEDERATION_IGNORE_SSL_ERRORS", JdkHttpClient.IGNORE_SSL_SETTING);
    }
}
