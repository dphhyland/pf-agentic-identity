package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Each "PDP TLS trust" mode against a CA made for this run: a PDP whose certificate that CA signed for
 * {@code localhost} answers, one it signed for {@code wrong.example} - reached as {@code localhost} - is refused in
 * every mode, the development-only trust-all included, and that refusal is never "unreachable". A PDP no trusted CA
 * signed for is refused too.
 */
class PdpTlsTest {

    private static final Map<String, String> JSON = Map.of("Content-Type", "application/json");
    private static StubPdp.Ca ca;
    private static StubPdp right;
    private static StubPdp wrong;

    @BeforeAll
    static void start() throws Exception {
        ca = StubPdp.Ca.get();
        right = StubPdp.tls(ca.server("localhost"), StubPdp.json(200, "{\"decision\":true}"));
        wrong = StubPdp.tls(ca.server("wrong"), StubPdp.json(200, "{\"decision\":true}"));
    }

    @AfterAll
    static void stop() throws IOException {
        right.close();
        wrong.close();
    }

    private static int post(PdpTls tls, StubPdp pdp) throws IOException {
        return new PdpTransport(tls, 5_000, false).post(pdp.httpsUrl("localhost", "/access/v1/evaluation"), "{}", JSON).status();
    }

    private static void refusedForTheName(PdpTls tls) {
        IOException e = assertThrows(IOException.class, () -> post(tls, wrong), tls.toString());
        assertFalse(e instanceof PdpUnavailableException, "a PDP that could not prove its name is not an outage: " + e);
        assertEquals(OutboundHttpException.Reason.TLS, ((OutboundHttpException) e).reason(), e.toString());
    }

    private static void refusedForTheChain(PdpTls tls) {
        IOException e = assertThrows(IOException.class, () -> post(tls, right), tls.toString());
        assertFalse(e instanceof PdpUnavailableException, e.toString());
        assertEquals(OutboundHttpException.Reason.TLS, ((OutboundHttpException) e).reason(), e.toString());
    }

    @Test
    void pinnedTrustsExactlyThePastedCaAndChecksTheName() throws Exception {
        PdpTls pinned = PdpTls.pinned(ca.caPem);
        assertEquals(PdpTls.PINNED_CA, pinned.mode());
        assertEquals(200, post(pinned, right));
        refusedForTheName(pinned);
    }

    @Test
    void pingFederatesCasAreUsedAndReadAgainWhenTheyChange() throws Exception {
        AtomicReference<Set<TrustAnchor>> anchors = new AtomicReference<>(Set.of(new TrustAnchor(ca.ca, null)));
        AtomicInteger reads = new AtomicInteger();
        PdpTls pingFederate = PdpTls.pingFederate(() -> {
            reads.incrementAndGet();
            return anchors.get() == null ? null : new HashSet<>(anchors.get());
        });
        assertEquals(PdpTls.PINGFEDERATE_TRUSTED_CAS, pingFederate.mode());
        assertEquals(200, post(pingFederate, right));
        refusedForTheName(pingFederate);
        TlsTrust first = pingFederate.current();
        assertSame(first, pingFederate.current(), "the same anchors (PingFederate hands the same objects) reuse the trust");
        assertTrue(reads.get() >= 4, "read on every call");

        // A reload in PingFederate: new anchor objects, here without the test CA. The trust is rebuilt and refuses.
        anchors.set(Set.of(new TrustAnchor(someOtherCa(), null)));
        assertNotSame(first, pingFederate.current());
        refusedForTheChain(pingFederate);
        anchors.set(null);
        assertThrows(IOException.class, pingFederate::current, "a set that goes missing is nothing to trust, not the last one");
    }

    @Test
    void pingFederateWithNothingToTrustOrThatCannotBeReadRefuses() {
        PdpTls empty = PdpTls.pingFederate(Set::of);
        IOException none = assertThrows(IOException.class, () -> post(empty, right));
        assertFalse(none instanceof PdpUnavailableException);
        assertTrue(none.getMessage().contains("no certificate"), none.getMessage());
        PdpTls nameOnly = PdpTls.pingFederate(() -> {
            Set<TrustAnchor> set = new HashSet<>();
            set.add(new TrustAnchor(ca.ca.getSubjectX500Principal(), ca.ca.getPublicKey(), null));
            set.add(null);
            return set;
        });
        assertThrows(IOException.class, nameOnly::current, "an anchor with no certificate cannot be put in a trust store");
        PdpTls nullSet = PdpTls.pingFederate(() -> null);
        assertThrows(IOException.class, nullSet::current);
        PdpTls broken = PdpTls.pingFederate(() -> {
            throw new NoClassDefFoundError("com/pingidentity/sdk/internal/services/ServiceFactory");
        });
        IOException unreadable = assertThrows(IOException.class, broken::current);
        assertTrue(unreadable.getMessage().contains("could not be read"), unreadable.getMessage());
        PdpTls throwing = PdpTls.pingFederate(() -> {
            throw new IllegalStateException("no service");
        });
        assertThrows(IOException.class, throwing::current);
    }

    /** The JVM's default trust, stood in for by a default SSLContext that trusts the test CA, for the length of the test. */
    @Test
    void jvmDefaultUsesTheJvmsTrustAndChecksTheName() throws Exception {
        SSLContext saved = SSLContext.getDefault();
        try {
            refusedForTheChain(PdpTls.jvmDefault());
            SSLContext.setDefault(ca.clientTrustingCa());
            PdpTls jvm = PdpTls.jvmDefault();
            assertEquals(PdpTls.JVM_DEFAULT, jvm.mode());
            assertEquals(200, post(jvm, right));
            refusedForTheName(jvm);
        } finally {
            SSLContext.setDefault(saved);
        }
    }

    /** Development's "Skip TLS verification": any chain, and still the name. It is platform's one trust-all, recorded. */
    @Test
    void theDevelopmentSwitchTrustsAnyChainButNotAnotherName() throws Exception {
        PdpTls insecure = PdpTls.insecure(PdpTransport.INSECURE_TLS_SETTING);
        assertEquals(200, post(insecure, right));
        refusedForTheName(insecure);
        assertEquals(Set.of("Skip TLS verification (dev only)"),
                SelfSignedTlsServer.settingsRecordedBy((Callable<Object>) () -> PdpTls.insecure(PdpTransport.INSECURE_TLS_SETTING)));
    }

    @Test
    void theModeFieldAcceptsTheThreeNamesAndNothingElse() {
        assertEquals(PdpTls.JVM_DEFAULT, PdpTls.modeOf(null));
        assertEquals(PdpTls.JVM_DEFAULT, PdpTls.modeOf(" "));
        assertEquals(PdpTls.PINNED_CA, PdpTls.modeOf(" Pinned-CA "));
        assertEquals(PdpTls.PINGFEDERATE_TRUSTED_CAS, PdpTls.modeOf("pingfederate-trusted-cas"));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> PdpTls.modeOf("insecure"));
        assertTrue(e.getMessage().contains("insecure"), e.getMessage());
        assertEquals(List.of("jvm-default", "pingfederate-trusted-cas", "pinned-ca"), PdpTls.MODES);
    }

    @Test
    void thePinnedFieldMustHoldACertificate() throws Exception {
        assertThrows(CertificateException.class, () -> PdpTls.certificatesOf(null));
        assertThrows(CertificateException.class, () -> PdpTls.certificatesOf("  "));
        assertThrows(CertificateException.class, () -> PdpTls.certificatesOf("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----"));
        assertThrows(CertificateException.class, () -> PdpTls.certificatesOf("not a certificate at all"));
        assertThrows(CertificateException.class, () -> PdpTls.certificatesOf(
                "-----BEGIN PKCS7-----\nMAsGCSqGSIb3DQEHAqA=\n-----END PKCS7-----"), "a malformed PKCS#7 is refused, however the JDK fails on it");
        CertificateException npe = assertThrows(CertificateException.class, () -> PdpTls.certificatesOf("x", in -> {
            throw new NullPointerException("the parser's own");
        }));
        assertTrue(npe.getMessage().contains("the parser's own"), "an unchecked failure of the JDK's parser is a refusal too");
        assertEquals(2, PdpTls.certificatesOf(ca.caPem + "\n" + ca.caPem).size());
        assertEquals("PdpTls[pinned-ca]", PdpTls.pinned(ca.caPem).toString());
    }

    private static java.security.cert.X509Certificate someOtherCa() throws Exception {
        // Any CA that did not sign the test servers' keys: the JDK's own cacerts has plenty.
        javax.net.ssl.TrustManagerFactory factory =
                javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        factory.init((java.security.KeyStore) null);
        return ((javax.net.ssl.X509TrustManager) factory.getTrustManagers()[0]).getAcceptedIssuers()[0];
    }
}
