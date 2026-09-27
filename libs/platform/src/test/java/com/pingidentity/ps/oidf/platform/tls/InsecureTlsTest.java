/*
 * What InsecureTls's trust-all does and does not turn off, against real self-signed servers.
 */
package com.pingidentity.ps.oidf.platform.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class InsecureTlsTest {

    @TempDir
    static Path dir;
    private static SelfSignedHttpsServer wrongName;
    private static SelfSignedHttpsServer rightName;

    @BeforeAll
    static void startServers() throws Exception {
        wrongName = new SelfSignedHttpsServer(dir, "wrong.example");
        rightName = new SelfSignedHttpsServer(dir, "localhost");
    }

    @AfterAll
    static void stopServers() {
        wrongName.close();
        rightName.close();
    }

    @BeforeEach
    void forget() {
        InsecureTls.reset();
    }

    private static int get(HttpClient client, String url) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).build(), HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    private static HttpClient trustAll() {
        return InsecureTls.trustAnyCertificate(HttpClient.newBuilder(), "TEST_INSECURE_TLS", true).build();
    }

    @Test
    void trustAllAcceptsASelfSignedCertificateForTheHostDialled() throws Exception {
        assertEquals(200, get(trustAll(), rightName.url()));
    }

    @Test
    void trustAllStillRefusesACertificateForAnotherName() {
        IOException e = assertThrows(IOException.class, () -> get(trustAll(), wrongName.url()));
        assertTrue(e instanceof SSLHandshakeException || e.getCause() instanceof SSLHandshakeException, String.valueOf(e));
        assertTrue(String.valueOf(e.getMessage()).contains("localhost"), e.getMessage());
    }

    @Test
    void offLeavesTheBuilderAloneAndTheChainChecked() throws Exception {
        HttpClient.Builder builder = HttpClient.newBuilder();
        assertSame(builder, InsecureTls.trustAnyCertificate(builder, "TEST_INSECURE_TLS", false));
        HttpClient client = builder.build();
        assertSame(SSLContext.getDefault(), client.sslContext());
        IOException e = assertThrows(IOException.class, () -> get(client, rightName.url()));
        assertTrue(String.valueOf(e.getMessage()).contains("PKIX") || String.valueOf(e.getCause()).contains("PKIX"), String.valueOf(e));
        assertEquals(List.of(), InsecureTls.uses(), "an unused switch is not recorded");
    }

    @Test
    void theContextIsAPlainTrustManagerSoJsseChecksTheName() throws Exception {
        // JSSE wraps a plain X509TrustManager and checks the endpoint identity after it; an extended one it trusts
        // as it is. The class is what keeps the host name checked.
        assertTrue(X509TrustManager.class.isAssignableFrom(InsecureTls.TrustEveryCertificate.class));
        assertFalse(X509ExtendedTrustManager.class.isAssignableFrom(InsecureTls.TrustEveryCertificate.class));
        InsecureTls.TrustEveryCertificate trust = new InsecureTls.TrustEveryCertificate();
        trust.checkClientTrusted(null, "EC");
        trust.checkServerTrusted(null, "EC");
        assertEquals(0, trust.getAcceptedIssuers().length);
    }

    @Test
    void anSslSocketWithTheSameContextChecksNoName() throws Exception {
        // What a site that took the context to an SSLSocket (or HttpsURLConnection's socket layer) without setting
        // the endpoint identification algorithm would get: no name check at all. InsecureTls hands the context
        // only to HttpClient for this reason.
        SSLContext context = trustAll().sslContext();
        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket("localhost", wrongName.port())) {
            socket.startHandshake();
            assertEquals("TLSv1.3", socket.getSession().getProtocol());
        }
    }

    @Test
    void theJvmWideFlagTurnsTheNameCheckOffForTrustAllButNotTheChainCheck() throws Exception {
        assertEquals("status 200", probe(wrongName.url(), true), "trust-all with the flag: no check at all (F-0035)");
        String defaultContext = probe(wrongName.url(), false);
        assertTrue(defaultContext.contains("unable to find valid certification path"), "the default context still checks the chain: "
                + defaultContext);
        String withoutFlag = probeWithoutFlag(wrongName.url(), true);
        assertTrue(withoutFlag.contains("No subject alternative DNS name matching localhost"), "and without the flag, the name: " + withoutFlag);
    }

    private static String probe(String url, boolean trustAll) throws Exception {
        return run(url, trustAll, true);
    }

    private static String probeWithoutFlag(String url, boolean trustAll) throws Exception {
        return run(url, trustAll, false);
    }

    private static String run(String url, boolean trustAll, boolean flag) throws Exception {
        String classpath = Path.of(InsecureTls.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                + File.pathSeparator
                + Path.of(InsecureTlsProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        List<String> command = new java.util.ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString()));
        if (flag) {
            command.add("-D" + InsecureTls.JDK_HOSTNAME_VERIFICATION_PROPERTY + "=true");
        }
        command.addAll(List.of("-cp", classpath, InsecureTlsProbe.class.getName(), url, String.valueOf(trustAll)));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "the probe did not finish");
        String last = out.strip();
        return last.substring(last.lastIndexOf('\n') + 1);
    }

    @Test
    void eachSettingWarnsOnceAndIsRecordedForTheStartUpAudit() {
        assertTrue(InsecureTls.record("A", InsecureTls.Kind.TRUST_ALL_CERTIFICATES, "a"));
        assertFalse(InsecureTls.record("A", InsecureTls.Kind.TRUST_ALL_CERTIFICATES, "a"), "one WARN per setting name");
        assertTrue(InsecureTls.record("A", InsecureTls.Kind.JDK_HOSTNAME_VERIFICATION_OFF, "a"), "a different kind is a different use");
        trustAll();
        trustAll();
        List<InsecureTls.Use> uses = InsecureTls.uses();
        assertEquals(3, uses.size(), String.valueOf(uses));
        assertEquals(1, uses.stream().filter(u -> u.setting().equals("TEST_INSECURE_TLS")).count());
        assertTrue(uses.stream().anyMatch(u -> u.setting().equals("TEST_INSECURE_TLS") && u.kind() == InsecureTls.Kind.TRUST_ALL_CERTIFICATES));
        assertTrue(!uses.get(0).first().isAfter(uses.get(2).first()), "oldest first");
    }

    @Test
    void usesAreOrderedByTimeThenSettingThenKind() {
        java.time.Instant t = java.time.Instant.parse("2026-09-28T00:00:00Z");
        List<InsecureTls.Use> sorted = new java.util.ArrayList<>(List.of(
                new InsecureTls.Use("B", InsecureTls.Kind.TRUST_ALL_CERTIFICATES, t),
                new InsecureTls.Use("A", InsecureTls.Kind.JDK_HOSTNAME_VERIFICATION_OFF, t),
                new InsecureTls.Use("A", InsecureTls.Kind.TRUST_ALL_CERTIFICATES, t)));
        sorted.sort(InsecureTls.ORDER);
        assertEquals(List.of("A TRUST_ALL_CERTIFICATES", "A JDK_HOSTNAME_VERIFICATION_OFF", "B TRUST_ALL_CERTIFICATES"),
                sorted.stream().map(u -> u.setting() + " " + u.kind()).toList());
    }

    @Test
    void aUseMustNameItsSetting() {
        for (String setting : new String[] {null, "", " "}) {
            assertThrows(IllegalArgumentException.class, () -> InsecureTls.trustAnyCertificate(HttpClient.newBuilder(), setting, true));
            assertThrows(IllegalArgumentException.class, () -> InsecureTls.disableJdkHostnameVerification(setting, true));
        }
        assertThrows(NullPointerException.class, () -> InsecureTls.trustAnyCertificate(null, "S", true));
        IllegalStateException none = assertThrows(IllegalStateException.class,
                () -> InsecureTls.trustAnyCertificate(HttpClient.newBuilder(), "S", true, "NO-SUCH-PROTOCOL"));
        assertEquals("could not build the trust-all TLS context S asked for", none.getMessage());
    }

    @Test
    void theJdkFlagIsSetOnlyWhenAskedAndReadAsTheJdkReadsIt() {
        String before = System.getProperty(InsecureTls.JDK_HOSTNAME_VERIFICATION_PROPERTY);
        try {
            System.clearProperty(InsecureTls.JDK_HOSTNAME_VERIFICATION_PROPERTY);
            InsecureTls.disableJdkHostnameVerification("HARNESS", false);
            assertFalse(InsecureTls.jdkHostnameVerificationDisabled());
            assertEquals(List.of(), InsecureTls.uses());
            InsecureTls.disableJdkHostnameVerification("HARNESS", true);
            assertTrue(InsecureTls.jdkHostnameVerificationDisabled());
            assertEquals(InsecureTls.Kind.JDK_HOSTNAME_VERIFICATION_OFF, InsecureTls.uses().get(0).kind());
        } finally {
            if (before == null) {
                System.clearProperty(InsecureTls.JDK_HOSTNAME_VERIFICATION_PROPERTY);
            } else {
                System.setProperty(InsecureTls.JDK_HOSTNAME_VERIFICATION_PROPERTY, before);
            }
        }
        assertFalse(InsecureTls.disabledByValue(null));
        assertTrue(InsecureTls.disabledByValue(""), "set and empty disables, as in the JDK");
        assertTrue(InsecureTls.disabledByValue("TRUE"));
        assertFalse(InsecureTls.disabledByValue("yes"));
        assertFalse(InsecureTls.disabledByValue("false"));
    }
}
