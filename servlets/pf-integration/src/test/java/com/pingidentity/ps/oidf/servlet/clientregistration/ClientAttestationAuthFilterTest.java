package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The token-endpoint filter that turns a verified Client Attestation into the credential PF understands.
 *
 * <p>Signing keys are PER CLIENT. What {@code init} checks is whether bridge signing is configured at
 * all: a deployment that registers clients for attestation authentication with none configured is one
 * where this filter passes everything through and those clients are authenticated by nothing. That is
 * the load-bearing case, and it must refuse to start rather than degrade quietly.
 *
 * <p>A single client missing a key is a different thing — a 401 for that client, not a boot failure for
 * everyone — and is asserted separately.
 */
class ClientAttestationAuthFilterTest {

    private static final String BACKING_PROP = "oidf.bridge.signer.backing";
    private static final String KEYS_PROP = "oidf.bridge.signing.keys";
    private static final String LEGACY_KEY_PROP = "oidf.bridge.private.jwk";
    private static final String LEGACY_PREV_KEY_PROP = "oidf.bridge.previous.public.jwk";
    private static final String REQUIRE_PROP = "oidf.attestation.require.bridge.key";

    @AfterEach
    void clearProps() throws Exception {
        System.clearProperty(BACKING_PROP);
        System.clearProperty(KEYS_PROP);
        System.clearProperty(LEGACY_KEY_PROP);
        System.clearProperty(LEGACY_PREV_KEY_PROP);
        System.clearProperty(REQUIRE_PROP);
        resetSingletons();
    }

    /** Both holders memoise; a test that changes the environment has to clear them. */
    private static void resetSingletons() throws Exception {
        java.lang.reflect.Field instance = FederationRuntimeConfig.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
        java.lang.reflect.Method reset = BridgeSigners.class.getDeclaredMethod("resetForTest");
        reset.setAccessible(true);
        reset.invoke(null);
    }

    private static String privateJwkJson(String kid) throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId(kid);
        return key.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
    }

    /** A config-backed key map naming exactly the clients given. */
    private static void configureKeysFor(Path dir, String... clientIds) throws Exception {
        StringBuilder json = new StringBuilder("{");
        for (int i = 0; i < clientIds.length; i++) {
            json.append(i > 0 ? "," : "")
                .append('"').append(clientIds[i]).append("\":{\"jwk\":")
                .append(privateJwkJson("k" + i)).append('}');
        }
        json.append('}');
        Path file = dir.resolve("bridge-keys.json");
        Files.writeString(file, json.toString());
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, file.toString());
        resetSingletons();
    }

    private static HttpServletRequest requestWithoutAttestation() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader(any())).thenReturn(null);
        return req;
    }

    // ---- init: is bridge signing configured at all? ------------------------------------------------

    @Test
    void refusesToStartWhenNoBridgeSigningIsConfiguredAndItIsRequired() throws Exception {
        resetSingletons();

        ServletException e = assertThrows(ServletException.class,
                () -> new ClientAttestationAuthFilter().init(null));

        assertTrue(e.getMessage().contains(BridgeSigners.BACKING_ENV), e.getMessage());
        assertTrue(e.getMessage().contains(FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV),
                "the failure must name the opt-out, or an operator cannot act on it: " + e.getMessage());
    }

    @Test
    void startsWithoutBridgeSigningOnlyWhenExplicitlyOptedOut() throws Exception {
        System.setProperty(REQUIRE_PROP, "false");
        resetSingletons();

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
    }

    @Test
    void startsWhenBridgeSigningIsConfigured(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1");

        assertDoesNotThrow(() -> new ClientAttestationAuthFilter().init(null));
    }

    /**
     * The superseded single-key variable must not be silently ignored. A security setting that looks
     * configured and does nothing is worse than one that is absent.
     */
    @Test
    void refusesToStartWhenTheSupersededSingleKeyVariableIsStillSet(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1");
        System.setProperty(LEGACY_KEY_PROP, privateJwkJson("old-deployment-key"));
        resetSingletons();

        ServletException e = assertThrows(ServletException.class,
                () -> new ClientAttestationAuthFilter().init(null));

        assertTrue(e.getMessage().contains(FederationRuntimeConfig.BRIDGE_KEY_ENV),
                "must name the variable that is now inert: " + e.getMessage());
        assertTrue(e.getMessage().contains(BridgeSigners.KEYS_ENV),
                "must say where the key should move to: " + e.getMessage());
    }

    /**
     * The rotation-overlap variable is superseded too, and was easier to miss than its sibling: it kept
     * a SUPERSEDED deployment-wide public key in every client's JWKS while clients picked up the new
     * one. There is no deployment-wide key any more, and {@code withBridgeKeys} - the only thing that
     * ever read it - is deleted. An operator part-way through a rotation would otherwise set it and
     * believe an overlap was in place while nothing read it at all.
     */
    @Test
    void refusesToStartWhenTheSupersededRotationOverlapKeyIsStillSet(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1");
        System.setProperty(LEGACY_PREV_KEY_PROP, privateJwkJson("outgoing-deployment-key"));
        resetSingletons();

        ServletException e = assertThrows(ServletException.class,
                () -> new ClientAttestationAuthFilter().init(null));

        assertTrue(e.getMessage().contains(FederationRuntimeConfig.BRIDGE_PREVIOUS_PUBLIC_KEY_ENV),
                "must name the variable that is now inert: " + e.getMessage());
        assertTrue(e.getMessage().contains(KEYS_PROP.replace("oidf.bridge.signing.keys", BridgeSigners.KEYS_ENV))
                        || e.getMessage().contains(BridgeSigners.KEYS_ENV),
                "must say what rotating a client looks like now: " + e.getMessage());
    }

    // ---- per-client resolution ---------------------------------------------------------------------

    @Test
    void eachClientGetsItsOwnSigner(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1", "https://rp.example.com/agent-2");

        JwsSigner one = BridgeSigners.forClient("https://rp.example.com/agent-1").orElseThrow();
        JwsSigner two = BridgeSigners.forClient("https://rp.example.com/agent-2").orElseThrow();

        assertTrue(!one.keyId().equals(two.keyId()),
                "distinct clients must not share a signing key - that was the whole defect");
    }

    @Test
    void aClientWithNoKeyResolvesToNothingRatherThanBorrowingAnothers(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1");

        assertTrue(BridgeSigners.forClient("https://rp.example.com/agent-unknown").isEmpty());
    }

    /** The backing is an assertion about the deployment, enforced so a demo key cannot ride into prod. */
    @Test
    void aVaultDeploymentRefusesAnInlineKey(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("keys.json");
        Files.writeString(file, "{\"https://rp.example.com/a\":{\"jwk\":" + privateJwkJson("inline") + "}}");
        System.setProperty(BACKING_PROP, "vault");
        System.setProperty(KEYS_PROP, file.toString());
        resetSingletons();

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> BridgeSigners.forClient("https://rp.example.com/a"));
        assertTrue(e.getMessage().contains("vault"), e.getMessage());
    }

    @Test
    void aKeyWithBothFormsIsRefused(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("keys.json");
        Files.writeString(file, "{\"https://rp.example.com/a\":{\"key_ref\":\"k\",\"jwk\":"
                + privateJwkJson("inline") + "}}");
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, file.toString());
        resetSingletons();

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> BridgeSigners.forClient("https://rp.example.com/a"));
        assertTrue(e.getMessage().contains("exactly one"), e.getMessage());
    }

    @Test
    void anUnreadableKeyMapIsADeploymentErrorNotAnEmptyResult() throws Exception {
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, "/nonexistent/bridge-keys.json");
        resetSingletons();

        assertThrows(IllegalStateException.class,
                () -> BridgeSigners.forClient("https://rp.example.com/a"),
                "falling through to 'no key' would silently disable attestation auth");
    }

    // ---- pass-through -------------------------------------------------------------------------------

    @Test
    void aRequestWithNoAttestationHeaderIsForwardedUntouched(@TempDir Path dir) throws Exception {
        configureKeysFor(dir, "https://rp.example.com/agent-1");
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter();
        filter.init(null);
        HttpServletRequest req = requestWithoutAttestation();
        javax.servlet.http.HttpServletResponse resp = mock(javax.servlet.http.HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        // The ORIGINAL request, not a BridgeAuthRequest wrapper: with no attestation the filter must not
        // substitute a credential, or it would widen access rather than translate one.
        verify(chain).doFilter(req, resp);
    }
}
