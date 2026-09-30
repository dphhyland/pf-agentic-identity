package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.CompactJws;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.platform.component.ComponentRegistry;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The start-up check of every client's bridge signing key (plan item H-JOSE-2, F-0112): a key that cannot sign is a
 * {@code DEGRADED} part of {@code ATTESTATION_AUTH} naming the client, found when the filter starts rather than by the
 * client's first bridged request - which until 0.6.0 answered 500 after the attestation had verified.
 */
class BridgeSignersCheckTest {

    private static final String BACKING_PROP = "oidf.bridge.signer.backing";
    private static final String KEYS_PROP = "oidf.bridge.signing.keys";

    @TempDir
    Path dir;

    @AfterEach
    void clear() {
        System.clearProperty(BACKING_PROP);
        System.clearProperty(KEYS_PROP);
        FederationRuntimeConfig.resetForTests();
        BridgeSigners.resetForTest();
    }

    private static ComponentParts.Part part() {
        return new ComponentParts(new ComponentRegistry(), Clock.systemUTC()).begin("ATTESTATION_AUTH", BridgeSigners.CHECK_PART);
    }

    private void configure(Map<String, Object> entries) throws Exception {
        Path keys = this.dir.resolve("bridge-keys.json");
        Files.writeString(keys, JsonUtil.toJson(entries));
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, keys.toString());
        FederationRuntimeConfig.resetForTests();
        BridgeSigners.resetForTest();
    }

    private static Map<String, Object> jwk(PublicJsonWebKey key, String alg) {
        Map<String, Object> params = new LinkedHashMap<>(key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
        if (alg != null) {
            params.put("alg", alg);
        }
        return Map.of("jwk", params);
    }

    @Test
    @Requirement({"RFC7518 §3.3", "RFC7518 §3.4", "RFC7518 §3.5"})
    void aKeyThatCannotSignIsNamedByItsClientAtStartAndNeverByItsKey() throws Exception {
        PublicJsonWebKey small = RsaJwkGenerator.generateJwk(1024);
        Map<String, Object> entries = new LinkedHashMap<>();
        entries.put("es256-client", jwk(EcJwkGenerator.generateJwk(EllipticCurves.P256), null));
        entries.put("short-rsa-client", jwk(small, "RS256"));
        entries.put("wrong-curve-client", jwk(EcJwkGenerator.generateJwk(EllipticCurves.P256), "ES384"));
        entries.put("ps256-client", jwk(RsaJwkGenerator.generateJwk(2048), "PS256"));
        configure(entries);
        ComponentParts.Part part = part();

        List<String> bad = BridgeSigners.checkOnce(part);

        assertEquals(List.of("short-rsa-client", "wrong-curve-client"), bad);
        assertEquals(ComponentState.DEGRADED, part.status().state());
        String detail = part.status().reason();
        assertTrue(detail.contains("short-rsa-client") && detail.contains("wrong-curve-client"), detail);
        assertFalse(detail.contains("es256-client") || detail.contains("ps256-client"), detail);
        assertFalse(detail.contains(String.valueOf(((Map<?, ?>) jwk(small, null).get("jwk")).get("n"))), "never the key: " + detail);
        assertEquals(bad, BridgeSigners.checkOnce(part), "a second run finds the same clients");
    }

    @Test
    @Requirement("RFC7518 §3.5")
    void aPs256BridgeKeySignsAnAssertionAVerifierAccepts() throws Exception {
        configure(Map.of("ps256-client", jwk(RsaJwkGenerator.generateJwk(2048), "PS256")));
        ComponentParts.Part part = part();

        assertEquals(List.of(), BridgeSigners.checkOnce(part));
        assertEquals(ComponentState.READY, part.status().state());

        JwsSigner signer = BridgeSigners.forClient("ps256-client").orElseThrow();
        assertEquals("PS256", signer.algorithm());
        String assertion = CompactJws.sign("JWT", "{\"iss\":\"ps256-client\"}", signer);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(assertion);
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, "PS256"));
        jws.setKey(((PublicJsonWebKey) JsonWebKey.Factory.newJwk(signer.publicJwk())).getPublicKey());
        assertTrue(jws.verifySignature());
    }

    @Test
    void withNoBridgeSigningConfiguredThereIsNothingToCheck() {
        ComponentParts.Part part = part();

        assertEquals(List.of(), BridgeSigners.checkOnce(part));
        assertEquals(ComponentState.READY, part.status().state());
    }

    @Test
    void aKeyMapThatCannotBeReadIsDegradedAndSaysSo() throws Exception {
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, this.dir.resolve("absent.json").toString());
        FederationRuntimeConfig.resetForTests();
        ComponentParts.Part part = part();

        assertNull(BridgeSigners.checkOnce(part));
        assertEquals(ComponentState.DEGRADED, part.status().state());
        assertTrue(part.status().reason().contains("could not be read"), part.status().reason());
    }

    @Test
    void theDetailNamesAsManyClientsAsFitAndCountsTheRest() {
        List<String> many = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            many.add("https://client-" + i + ".example.com");
        }
        String detail = BridgeSigners.checkDetail(many);
        assertTrue(detail.length() <= ComponentRegistry.MAX_REASON, detail);
        assertTrue(detail.startsWith("40 client(s)"), detail);
        assertTrue(detail.endsWith(" more"), detail);

        assertTrue(BridgeSigners.checkDetail(List.of("a")).endsWith(": a"));
        String huge = "https://" + "x".repeat(400) + ".example.com";
        assertTrue(BridgeSigners.checkDetail(List.of(huge)).endsWith("1 not named here"));
    }

    @Test
    void theCheckStartsOnceInThisCopy() throws Exception {
        configure(Map.of("es256-client", jwk(EcJwkGenerator.generateJwk(EllipticCurves.P256), null)));

        BridgeSigners.startCheck();
        var first = com.pingidentity.ps.oidf.platform.exec.ManagedExecutors.live(BridgeSigners.CHECK_JOB).orElseThrow();
        BridgeSigners.startCheck();

        assertTrue(first == com.pingidentity.ps.oidf.platform.exec.ManagedExecutors.live(BridgeSigners.CHECK_JOB).orElseThrow(),
                "a second start while the first runs does nothing");
        BridgeSigners.resetForTest();
        assertTrue(first.isClosed(), "a reset stops it");
    }
}
