/*
 * OpenBao's transit calls through platform's OutboundHttp: each ends at its deadline however the vault stalls, reads
 * no more than the cap, checks the vault's certificate names its host, and reaches only the vault it was configured at.
 */
package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class OpenBaoTransportTest {

    private static final Duration SHORT = Duration.ofMillis(600);
    private static final String KEY = "attestation-es256";

    /** The transit key metadata a vault answers {@code GET /v1/transit/keys/<key>} with. */
    private static String metadata() throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(key.getPublicKey().getEncoded()) + "\n-----END PUBLIC KEY-----\n";
        return JsonUtil.toJson(Map.of("data", Map.of("type", "ecdsa-p256", "latest_version", 1,
                "keys", Map.of("1", Map.of("public_key", pem)))));
    }

    /** Runs {@code call}, which must fail about {@code deadline} in, naming one of {@code reasons}. */
    private static IllegalStateException failsAt(Duration deadline, Executable call, OutboundHttpException.Reason... reasons) {
        long started = System.nanoTime();
        IllegalStateException e = assertThrows(IllegalStateException.class, call);
        long elapsedMs = (System.nanoTime() - started) / 1_000_000;
        assertTrue(elapsedMs >= deadline.toMillis() - 50 && elapsedMs < deadline.toMillis() + 1_500,
                "gave up after " + elapsedMs + " ms against a " + deadline.toMillis() + " ms deadline");
        OutboundHttpException cause = assertInstanceOf(OutboundHttpException.class, e.getCause());
        assertTrue(List.of(reasons).contains(cause.reason()), e.getMessage());
        assertTrue(e.getMessage().contains(": " + cause.reason() + ": "), "the reason is in the message: " + e.getMessage());
        return e;
    }

    @Test
    void theDeadlinesAreTwoAndAHalfSecondsWithOneToConnect() {
        assertEquals(Duration.ofSeconds(1), OpenBaoTransitSigner.CONNECT_TIMEOUT);
        assertEquals(Duration.ofMillis(2500), OpenBaoTransitSigner.TOTAL_TIMEOUT);
    }

    @Test
    void aVaultThatNeverAnswersIsGivenUpOnAtTwoAndAHalfSeconds() throws Exception {
        try (OutboundPeer vault = OutboundPeer.stalling()) {
            failsAt(OpenBaoTransitSigner.TOTAL_TIMEOUT, () -> new OpenBaoTransitSigner(vault.url(""), "t", KEY),
                    OutboundHttpException.Reason.HEADER_TIMEOUT, OutboundHttpException.Reason.DEADLINE);
            assertEquals("closed", vault.closed());
        }
    }

    @Test
    void aVaultThatDribblesIsGivenUpOnAtTwoAndAHalfSeconds() throws Exception {
        try (OutboundPeer vault = OutboundPeer.dribbling(200)) {
            failsAt(OpenBaoTransitSigner.TOTAL_TIMEOUT, () -> new OpenBaoTransitSigner(vault.url(""), "t", KEY),
                    OutboundHttpException.Reason.DEADLINE);
            assertEquals("closed", vault.closed());
        }
    }

    /** A signature is bounded too: the key read answers, then the sign call stalls. */
    @Test
    void aSignatureTheVaultStallsOnEndsAtItsDeadline() throws Exception {
        String metadata = metadata();
        try (OutboundPeer vault = OutboundPeer.of(null, peer -> (n, request, out, socket) -> {
            if (n == 1) {
                OutboundPeer.write(out, 200, "", metadata);
            } else {
                peer.stallBeforeHead().answer(n, request, out, socket);
            }
        })) {
            OpenBaoTransitSigner signer = new OpenBaoTransitSigner(vault.url("/"), "t", KEY, TlsTrust.jvmDefault(), SHORT,
                    SHORT);
            assertEquals("ES256", signer.algorithm());
            OutboundPeer.Recorded keys = vault.requests.poll(1, TimeUnit.SECONDS);
            assertEquals("GET /v1/transit/keys/" + KEY + " HTTP/1.1", keys.requestLine());
            assertEquals("t", keys.header("X-Vault-Token"));
            failsAt(SHORT, () -> signer.sign(new byte[] {1, 2, 3}), OutboundHttpException.Reason.HEADER_TIMEOUT,
                    OutboundHttpException.Reason.DEADLINE);
            OutboundPeer.Recorded sign = vault.requests.poll(1, TimeUnit.SECONDS);
            assertEquals("POST /v1/transit/sign/" + KEY + " HTTP/1.1", sign.requestLine());
            assertEquals("application/json", sign.header("Content-Type"));
            assertTrue(sign.body().contains("\"key_version\":1"), sign.body());
        }
    }

    @Test
    void anAnswerOverTheCapIsRefused() throws Exception {
        try (OutboundPeer vault = OutboundPeer.plain(OutboundPeer.oversize(200, 300 * 1024))) {
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> new OpenBaoTransitSigner(vault.url(""), "t", KEY));
            assertEquals(OutboundHttpException.Reason.BODY_TOO_LARGE, ((OutboundHttpException) e.getCause()).reason());
        }
    }

    @Test
    void aRefusalIsItsStatus() throws Exception {
        try (OutboundPeer vault = OutboundPeer.plain(OutboundPeer.answer(403, "{\"errors\":[\"permission denied\"]}"))) {
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> new OpenBaoTransitSigner(vault.url(""), "t", KEY));
            assertEquals("OpenBao returned HTTP 403 for /v1/transit/keys/" + KEY, e.getMessage());
        }
    }

    /**
     * The configured address is exempt from the scheme and address rules because the operator named it; a key name
     * that climbs out of it is not, so an internal http vault is reached and a {@code ..} key name is refused.
     */
    @Test
    void onlyTheConfiguredVaultIsExempt() throws Exception {
        try (OutboundPeer vault = OutboundPeer.plain(OutboundPeer.answer(200, metadata()))) {
            assertNotNull(new OpenBaoTransitSigner(vault.url(""), "t", KEY).keyId(), "http on loopback, as configured");
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> new OpenBaoTransitSigner(vault.url(""), "t", "../../sys/raw"));
            assertEquals(OutboundHttpException.Reason.REFUSED_URL, ((OutboundHttpException) e.getCause()).reason());
            assertEquals(1, vault.requests.size(), "the refused path was never sent");
        }
    }

    /**
     * TLS: a vault whose certificate a CA made for this run signed, trusted by that CA alone, answers; one whose
     * certificate names another host is refused in the handshake.
     */
    @Test
    void theVaultsCertificateMustNameItsHost() throws Exception {
        OutboundPeer.TestCa ca = OutboundPeer.TestCa.get();
        TlsTrust trust = TlsTrust.caCertificates(List.of(ca.ca));
        String metadata = metadata();
        try (OutboundPeer right = OutboundPeer.tls(ca.server("localhost"), OutboundPeer.answer(200, metadata));
             OutboundPeer wrong = OutboundPeer.tls(ca.server("other.test"), OutboundPeer.answer(200, metadata))) {
            assertNotNull(new OpenBaoTransitSigner(right.url(""), "t", KEY, trust, SHORT, Duration.ofSeconds(5)).keyId());
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> new OpenBaoTransitSigner(wrong.url(""), "t", KEY, trust, SHORT, Duration.ofSeconds(5)));
            assertEquals(OutboundHttpException.Reason.TLS, ((OutboundHttpException) e.getCause()).reason(), e.getMessage());
            IllegalStateException untrusted = assertThrows(IllegalStateException.class,
                    () -> new OpenBaoTransitSigner(right.url(""), "t", KEY));
            assertEquals(OutboundHttpException.Reason.TLS, ((OutboundHttpException) untrusted.getCause()).reason(),
                    "the JVM's store does not hold the test CA");
        }
    }
}
