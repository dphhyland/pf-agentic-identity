package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttestationMetadataConfigTest {
    private static final String CHALLENGE = "https://as.example.com/federation/attestation-challenge";

    @BeforeEach
    @AfterEach
    void forget() {
        AttestationMetadataConfig.resetForTests();
    }

    @Test
    void defaultsAdvertiseOnlyThePlainJwtFormat() {
        AttestationMetadataConfig defaults = AttestationMetadataConfig.defaults();
        assertEquals(java.util.List.of("jwt"), defaults.clientAttestationFormatsSupported());
        assertTrue(defaults.tokenEndpointAuthMethodsSupported().contains("attest_jwt_client_auth"));
        assertTrue(defaults.tokenEndpointAuthMethodsSupported().contains("attest_jwt_client_auth_dpop"));
    }

    @Test
    void defaultsAdvertiseBothPopMethods() {
        AttestationMetadataConfig defaults = AttestationMetadataConfig.defaults();
        assertEquals(java.util.List.of("attestation_pop_jwt", "dpop_combined"),
                defaults.clientAttestationPopMethodsSupported());
    }

    /** PingFederate 13.1.3's own list, as its discovery documents served it on the rig (2026-10-01). */
    private static Map<String, Object> pingFederateDocument() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", "https://as.example.com");
        doc.put("token_endpoint_auth_methods_supported",
                List.of("client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "tls_client_auth", "none"));
        doc.put("dpop_signing_alg_values_supported", List.of("RS256", "RS384", "ES256", "PS256"));
        doc.put("prompt_values_supported", List.of("none", "login"));
        return doc;
    }

    /**
     * ABCA-10 §8's methods appended to the document's own, its algorithm members and §6.1's challenge_endpoint added, and
     * every member the document had kept first, in its order, unchanged - PingFederate's DPoP list included.
     */
    @Test
    @Requirement({"ABCA-10 §6.1", "ABCA-10 §8"})
    void extendAddsTheSetAndKeepsTheDocumentsOwnMembers() {
        Map<String, Object> doc = pingFederateDocument();
        Map<String, Object> out = AttestationMetadataConfig.defaults().extend(doc, CHALLENGE);

        assertEquals(List.of("issuer", "token_endpoint_auth_methods_supported", "dpop_signing_alg_values_supported",
                "prompt_values_supported", "client_attestation_signing_alg_values_supported",
                "client_attestation_pop_signing_alg_values_supported", "client_attestation_pop_methods_supported", "challenge_endpoint"),
                List.copyOf(out.keySet()));
        assertEquals(List.of("client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "tls_client_auth", "none",
                "attest_jwt_client_auth", "attest_jwt_client_auth_dpop"), out.get("token_endpoint_auth_methods_supported"));
        assertEquals(doc.get("dpop_signing_alg_values_supported"), out.get("dpop_signing_alg_values_supported"),
                "PingFederate's own DPoP list, which its DPoP validation holds proofs to, is never replaced");
        assertEquals(List.of("RS256", "PS256", "ES256"), out.get("client_attestation_signing_alg_values_supported"));
        assertEquals(List.of("ES256", "RS256", "PS256"), out.get("client_attestation_pop_signing_alg_values_supported"));
        assertEquals(List.of("attestation_pop_jwt", "dpop_combined"), out.get("client_attestation_pop_methods_supported"));
        assertEquals(CHALLENGE, out.get("challenge_endpoint"));
        assertEquals(pingFederateDocument(), doc, "the document itself is not changed");
    }

    @Test
    void extendAppendsOnlyTheMethodsTheDocumentLacksAndKeepsAChallengeItHas() {
        Map<String, Object> doc = pingFederateDocument();
        doc.put("token_endpoint_auth_methods_supported", List.of("attest_jwt_client_auth_dpop", "private_key_jwt"));
        doc.put("challenge_endpoint", "https://as.example.com/its-own");
        Map<String, Object> out = AttestationMetadataConfig.defaults().extend(doc, CHALLENGE);

        assertEquals(List.of("attest_jwt_client_auth_dpop", "private_key_jwt", "attest_jwt_client_auth"),
                out.get("token_endpoint_auth_methods_supported"));
        assertEquals("https://as.example.com/its-own", out.get("challenge_endpoint"));
        assertEquals(out, AttestationMetadataConfig.defaults().extend(out, CHALLENGE), "extending twice adds nothing more");
    }

    /** RFC 8414 §2: "If omitted, the default is "client_secret_basic"" - so a document without a list gets the configured one. */
    @Test
    @Requirement("RFC8414 §2")
    void aDocumentWithoutAMethodListGetsTheConfiguredOne() {
        Map<String, Object> out = AttestationMetadataConfig.defaults().extend(Map.of("issuer", "https://as.example.com"), CHALLENGE);

        assertEquals(List.of("private_key_jwt", "attest_jwt_client_auth", "attest_jwt_client_auth_dpop"),
                out.get("token_endpoint_auth_methods_supported"));
        assertEquals(List.of("ES256", "RS256", "PS256"), out.get("dpop_signing_alg_values_supported"),
                "§8: dpop_signing_alg_values_supported MUST be there when DPoP combined mode is");
    }

    @Test
    void aMethodListThatIsNotStringsCannotBeExtended() {
        assertNull(AttestationMetadataConfig.defaults().extend(Map.of("token_endpoint_auth_methods_supported", "private_key_jwt"), CHALLENGE));
        assertNull(AttestationMetadataConfig.defaults().extend(Map.of("token_endpoint_auth_methods_supported", List.of("a", 1)), CHALLENGE));
    }

    @Test
    void withoutDpopCombinedModeOrPopMethodsTheirMembersAreLeftOut() {
        AttestationMetadataConfig popJwtOnly = AttestationMetadataConfigs.popJwtOnly();
        Map<String, Object> out = popJwtOnly.extend(Map.of("issuer", "https://as.example.com", "token_endpoint_auth_methods_supported",
                List.of("none")), CHALLENGE);

        assertEquals(List.of("none", "attest_jwt_client_auth"), out.get("token_endpoint_auth_methods_supported"));
        assertFalse(out.containsKey("dpop_signing_alg_values_supported"));
        assertFalse(out.containsKey("client_attestation_pop_methods_supported"), "draft-10 §8: never an empty array");
        assertEquals(CHALLENGE, out.get("challenge_endpoint"));
    }

    @Test
    void theChallengeEndpointOnlyWhenEnabledAndNamed() {
        assertFalse(AttestationMetadataConfigs.withoutChallenge().extend(pingFederateDocument(), CHALLENGE).containsKey("challenge_endpoint"));
        assertFalse(AttestationMetadataConfig.defaults().extend(pingFederateDocument(), null).containsKey("challenge_endpoint"));
    }

    /** S9b's rule for a disabled component: ATTESTATION_AUTH switched off advertises no member anywhere. */
    @Test
    void switchedOffOrWithoutAnAttestationMethodNothingIsAdded() {
        for (AttestationMetadataConfig none : List.of(AttestationMetadataConfigs.switchedOff(), AttestationMetadataConfigs.noAttestationMethod())) {
            assertFalse(none.advertised());
            assertEquals(List.of(), none.attestationMethods());
            Map<String, Object> doc = pingFederateDocument();
            Map<String, Object> out = none.extend(doc, CHALLENGE);
            assertEquals(doc, out);
            assertNotSame(doc, out);
        }
        assertEquals(List.of("private_key_jwt"), AttestationMetadataConfigs.switchedOff().tokenEndpointAuthMethodsSupported(),
                "openid_provider keeps the configured list less ABCA-10's methods");
        assertTrue(AttestationMetadataConfig.defaults().advertised());
        assertEquals(AttestationMetadataConfig.ATTESTATION_METHODS, AttestationMetadataConfig.defaults().attestationMethods());
    }

    @Test
    void theSwitchIsReadFromTheComponentsVerdict() {
        Settings settings = Settings.load(AttestationMetadataConfig.class.getClassLoader(), FederationConfiguration.CATALOGUE)
                .with(Sources.of(Map.of(), Map.of()));
        for (String value : List.of("true", "maybe")) {
            // Enabled, or a switch that cannot be read (the component fails; its members are still what is configured).
            assertTrue(AttestationMetadataConfig.from(settings, ComponentSwitches.of(Map.of(ComponentSwitches.ATTESTATION_AUTH, value)::get,
                    name -> null)).advertised(), value);
        }
        assertFalse(AttestationMetadataConfig.from(settings, ComponentSwitches.of(Map.of(ComponentSwitches.ATTESTATION_AUTH, "false")::get,
                name -> null)).advertised());
    }

    /** What the federation servlet read last is what the discovery filter publishes; before it has read anything, the catalogue's. */
    @Test
    void currentIsWhatTheServletReadLastOrTheCatalogues() {
        AttestationMetadataConfig beforeTheServlet = AttestationMetadataConfig.current();
        assertEquals(AttestationMetadataConfig.defaults().attestationMethods(), beforeTheServlet.attestationMethods());
        assertSame(beforeTheServlet, AttestationMetadataConfig.current(), "read once, then kept");

        AttestationMetadataConfig read = AttestationMetadataConfigs.withoutChallenge();
        assertSame(read, AttestationMetadataConfig.current());
        AttestationMetadataConfig.from(Settings.load(AttestationMetadataConfig.class.getClassLoader(), FederationConfiguration.CATALOGUE)
                .with(Sources.of(Map.of(), Map.of())));
        assertNotSame(read, AttestationMetadataConfig.current());
    }

    @Test
    void aRefusedValueIsTheCallersToHandle() {
        Settings refusing = Settings.load(AttestationMetadataConfig.class.getClassLoader(), FederationConfiguration.CATALOGUE)
                .with(Sources.of(Map.of(), Map.of()).withInitParams(Map.of("attestationChallengeEndpointEnabled", "sometimes")::get));
        assertThrows(SettingRefused.class, () -> AttestationMetadataConfig.from(refusing));
    }
}
