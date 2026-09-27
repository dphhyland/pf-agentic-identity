/*
 * The plugin's "Skip TLS verification (dev only)" through InsecureTls: any chain, but still the host dialled.
 */
package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JdkHttpTransportInsecureTlsTest {

    @TempDir
    static Path dir;
    private static SelfSignedTlsServer rightName;
    private static SelfSignedTlsServer wrongName;

    @BeforeAll
    static void start() throws Exception {
        rightName = new SelfSignedTlsServer(dir, "localhost", 200, "{\"decision\":\"PERMIT\"}");
        wrongName = new SelfSignedTlsServer(dir, "wrong.example", 200, "{\"decision\":\"PERMIT\"}");
    }

    @AfterAll
    static void stop() {
        rightName.close();
        wrongName.close();
    }

    @Test
    void theSwitchAcceptsASelfSignedCertificateForTheHostDialled() throws Exception {
        assertEquals(200, new JdkHttpTransport(true, 5000).post(rightName.url("/"), "{}", Map.of()).status());
    }

    @Test
    void theSwitchStillRefusesACertificateForAnotherNameAndThatIsARefusalNotAnOutage() {
        IOException e = assertThrows(IOException.class, () -> new JdkHttpTransport(true, 5000).post(wrongName.url("/"), "{}", Map.of()));
        assertTrue(SelfSignedTlsServer.isWrongName(e), String.valueOf(e));
        assertFalse(e instanceof PdpUnavailableException, "something answered that could not prove it was the PDP");
    }

    @Test
    void withoutTheSwitchTheChainIsChecked() {
        IOException e = assertThrows(IOException.class, () -> new JdkHttpTransport(false, 5000).post(rightName.url("/"), "{}", Map.of()));
        assertFalse(SelfSignedTlsServer.isWrongName(e), String.valueOf(e));
        assertEquals("Skip TLS verification (dev only)", JdkHttpTransport.INSECURE_TLS_SETTING);
    }
}
