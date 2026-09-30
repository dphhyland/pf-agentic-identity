/*
 * OIDF_HARNESS_INSECURE_TLS through InsecureTls: any chain, but still the host dialled, until main turns the JDK's
 * host name check off for the run - which it does only with the switch on (F-0162).
 */
package com.pingidentity.ps.oidf.harness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Set;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AttestationFlowHarnessInsecureTlsTest {

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

    private static int get(HttpClient client, SelfSignedTlsServer server) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(server.url("/"))).build(), HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    @Test
    void theSwitchAcceptsASelfSignedCertificateForTheHostDialled() throws Exception {
        assertEquals(200, get(AttestationFlowHarness.httpClient(true), rightName));
        assertEquals(Set.of("OIDF_HARNESS_INSECURE_TLS"), SelfSignedTlsServer.settingsRecordedBy(() -> AttestationFlowHarness.httpClient(true)));
    }

    @Test
    void theSwitchStillRefusesACertificateForAnotherName() {
        // In this JVM the JDK flag is unset; the harness's main sets it only with the switch on, which is what lets a
        // run reach a local PF whose certificate names another host (F-0162).
        Exception e = assertThrows(Exception.class, () -> get(AttestationFlowHarness.httpClient(true), wrongName));
        assertTrue(SelfSignedTlsServer.isWrongName(e), String.valueOf(e));
    }

    @Test
    void withoutTheSwitchTheChainIsChecked() {
        Exception e = assertThrows(Exception.class, () -> get(AttestationFlowHarness.httpClient(false), rightName));
        assertFalse(SelfSignedTlsServer.isWrongName(e), String.valueOf(e));
        assertEquals("OIDF_HARNESS_INSECURE_TLS", AttestationFlowHarness.INSECURE_TLS);
    }

    @Test
    void theSwitchIsReadStrictly() {
        assertTrue(AttestationFlowHarness.insecureTls(k -> " TRUE "));
        assertFalse(AttestationFlowHarness.insecureTls(k -> "false"));
        assertFalse(AttestationFlowHarness.insecureTls(k -> null));
        assertFalse(AttestationFlowHarness.insecureTls(k -> " "));
        SettingRefused refused = assertThrows(SettingRefused.class, () -> AttestationFlowHarness.insecureTls(k -> "yes"));
        assertTrue(refused.getMessage().contains("OIDF_HARNESS_INSECURE_TLS"), refused.getMessage());
    }

    @Test
    void theJvmHostNameFlagIsSetOnlyWithTheSwitch() {
        String property = InsecureTls.JDK_HOSTNAME_VERIFICATION_PROPERTY;
        String before = System.getProperty(property);
        try {
            System.clearProperty(property);
            AttestationFlowHarness.relaxHostnameCheck(false);
            assertEquals(null, System.getProperty(property), "a run without the switch leaves the host name check on");
            AttestationFlowHarness.relaxHostnameCheck(true);
            assertEquals("true", System.getProperty(property), "a run with it turns the check off");
        } finally {
            if (before == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, before);
            }
        }
    }
}
