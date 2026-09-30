/*
 * The hosted entities' vault, read through its hosted-entity-signing entries (plan item ST-5).
 */
package com.pingidentity.ps.oidf.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * OpenBao's address and token for hosted entities come from the same two entries the attestation issuer reads: the
 * system property, then the environment variable, then the superseded names, and a superseded name that disagrees is
 * refused - where the reader before 0.6.0 took the first one set and never noticed the disagreement.
 */
class RegistryHostedEntitySignerSettingsTest {

    private static final HostedEntity SIGNED = new HostedEntity("https://authority.example/federation/agents/a1",
            HostingMode.AUTHORITY_SIGNED, "k1", Map.of("oauth_client", Map.of()), Map.of(), EntityStatus.ACTIVE, false, null,
            java.time.Instant.now(), null);

    private static RegistryHostedEntitySigner read(Map<String, String> env, Map<String, String> props) {
        return RegistryHostedEntitySigner.from(Sources.of(env::get, props::get, null));
    }

    @Test
    void neitherSetLeavesAnAuthoritySignedEntityWithoutASigner() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> read(Map.of(), Map.of()).signerFor(SIGNED));
        assertTrue(e.getMessage().contains("no OpenBao address/token"), e.getMessage());
        RegistryHostedEntitySigner.fromEnvironment();
    }

    @Test
    void aSupersededNameIsReadAndOneThatDisagreesIsRefused() {
        // Read under the superseded names: the signer is built; an unreachable vault fails the signer, not the read.
        RegistryHostedEntitySigner signer = read(Map.of("OPENBAO_ADDR", "http://127.0.0.1:1", "BAO_TOKEN", "t"), Map.of());
        assertThrows(IllegalStateException.class, () -> signer.signerFor(SIGNED));

        SettingRefused conflict = assertThrows(SettingRefused.class,
                () -> read(Map.of("OIDF_OPENBAO_URL", "https://bao.example", "VAULT_ADDR", "https://other.example"), Map.of()));
        assertEquals(RegistryHostedEntitySigner.URL, conflict.setting());
        assertTrue(conflict.getMessage().contains("VAULT_ADDR"), conflict.getMessage());
        read(Map.of("OIDF_OPENBAO_URL", "https://env.example"), Map.of("oidf.openbao.url", "https://property.example"));
    }
}
