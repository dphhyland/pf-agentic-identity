/*
 * The attester's settings through their catalogues, strictly, and its in-memory state under the production profile.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.issuer.AttesterSigningKey;
import com.pingidentity.ps.oidf.issuer.EvidencePolicy;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import com.pingidentity.ps.oidf.issuer.SpireSelectorIntrospector;
import com.pingidentity.ps.oidf.issuer.WorkloadIntrospector;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Map;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Plan items ST-5 and PR-2 for the attester: every setting its servlets read goes through the attestation-issuer,
 * evidence-policy and hosted-entity-signing catalogues, strictly, and a value an entry refuses is the part's
 * {@code FAILED_CONFIG}, naming the setting; the attester's in-memory stores need the {@code in-memory-state} risk
 * under production. A test run's environment is production, with no Redis URL.
 */
@ExtendWith(InMemoryStateAccepted.class)
class AttesterSettingsTest {

    private static final List<String> PROPERTIES = List.of("oidf.wallet.provider.jwks", "oidf.entra.agent.directory",
            "oidf.attester.spire.entries.url", "oidf.openbao.url", "oidf.openbao.token", "oidf.attester.op.issuer",
            "oidf.attester.max.evidence.lifetime.seconds", "oidf.attester.require.single.audience.evidence");

    @AfterEach
    void clearProperties() {
        PROPERTIES.forEach(System::clearProperty);
    }

    private static ServletConfig config(Map<String, String> params) {
        ServletConfig config = mock(ServletConfig.class);
        params.forEach((name, value) -> when(config.getInitParameter(name)).thenReturn(value));
        return config;
    }

    private static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    /** The status a servlet answers a GET with, through the container's entry point. */
    private static int status(HttpServlet servlet) throws Exception {
        return status(servlet, "GET");
    }

    /** The status a servlet answers {@code method} with, through the container's entry point. */
    private static int status(HttpServlet servlet, String method) throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn(method);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new ServletOutputStream() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener listener) {
            }

            @Override
            public void write(int b) {
                body.write(b);
            }
        });
        when(response.getWriter()).thenReturn(new java.io.PrintWriter(body, true));
        servlet.service((jakarta.servlet.ServletRequest) request, (jakarta.servlet.ServletResponse) response);
        org.mockito.ArgumentCaptor<Integer> status = org.mockito.ArgumentCaptor.forClass(Integer.class);
        verify(response).setStatus(status.capture());
        return status.getValue();
    }

    /** The attester's settings under development, from the init-params given. */
    private static Settings development(Map<String, String> initParams) {
        return Settings.of(AttestationIssuanceServlet.SETTINGS).with(Sources.of(
                Map.of(DeploymentProfile.SETTING, "development")::get, name -> null, initParams::get));
    }

    // ---- in-memory state (PR-2) --------------------------------------------------------------------------------------

    @Test
    void theAttestersInMemoryStoresAreRefusedInProductionWithoutTheRisk() throws Exception {
        AttestationSupport.acceptedRisksForTests(AcceptedRisks.none());
        new AttestationIssuanceServlet().init(config(Map.of()));
        PartStatus issuance = part("AttestationIssuanceServlet");
        assertEquals(ComponentState.REFUSED, issuance.state(), issuance.reason());
        assertTrue(issuance.reason().contains("'in-memory-state'"), issuance.reason());
        assertTrue(issuance.reason().contains("OIDF_REDIS_URL"), issuance.reason());
        assertTrue(issuance.reason().contains("evidence bindings (oidf:cas:*)"), issuance.reason());

        // Every other part of the component is refused with it, and its surfaces answer 503.
        ClientAttestationServiceMetadataServlet metadata = new ClientAttestationServiceMetadataServlet();
        metadata.init(config(Map.of()));
        assertEquals(ComponentState.REFUSED, part("ClientAttestationServiceMetadataServlet").state());
        assertEquals(503, status(metadata));
        AttesterConfigurationServlet configuration = new AttesterConfigurationServlet();
        configuration.init(config(Map.of()));
        assertEquals(503, status(configuration));
    }

    @Test
    void aReadyAttesterPassesTheGateToItsHandlers() throws Exception {
        // The risk accepted (the extension's default): each metadata servlet is READY and its gate lets a request
        // through to the handler, whose preflight answer is 204. Every part of the component starts again, so that none
        // is left REFUSED by an earlier test: a refused part closes every part of the component.
        new AttestationIssuanceServlet().init(config(Map.of()));
        new AttestationIssuanceChallengeServlet().init(config(Map.of()));
        ClientAttestationServiceMetadataServlet metadata = new ClientAttestationServiceMetadataServlet();
        metadata.init(config(Map.of()));
        AttesterConfigurationServlet configuration = new AttesterConfigurationServlet();
        configuration.init(config(Map.of()));
        assertTrue(Startup.parts().parts().stream().noneMatch(p -> p.component().equals("ATTESTATION_ISSUER")
                && p.state() != ComponentState.READY), Startup.parts().parts().toString());
        assertEquals(204, status(metadata, "OPTIONS"));
        assertEquals(204, status(configuration, "OPTIONS"));
    }

    @Test
    void developmentKeepsTheInMemoryStoresWithAWarning() throws Exception {
        AttestationSupport.acceptedRisksForTests(AcceptedRisks.none());
        ProfileRefusals.publish(ProfileAudit.Result.empty(DeploymentProfile.DEVELOPMENT));
        new AttestationIssuanceServlet().init(config(Map.of()));
        assertEquals(ComponentState.READY, part("AttestationIssuanceServlet").state());
        assertTrue(ProfileRefusals.codeRefusals().isEmpty());
    }

    // ---- the init-params and the environment, strictly (ST-5) ----------------------------------------------------------

    @Test
    void aSwitchThatIsNotTrueOrFalseFailsEachServletNamingIt() throws Exception {
        ServletConfig yes = config(Map.of("challengeRequired", "yes"));
        new AttestationIssuanceServlet().init(yes);
        assertFailed("AttestationIssuanceServlet", "challengeRequired");

        ClientAttestationServiceMetadataServlet metadata = new ClientAttestationServiceMetadataServlet();
        metadata.init(yes);
        assertFailed("ClientAttestationServiceMetadataServlet", "challengeRequired");
        assertEquals(503, status(metadata));
        metadata.init(config(Map.of("challengeEndpointEnabled", "on")));
        assertFailed("ClientAttestationServiceMetadataServlet", "challengeEndpointEnabled");

        AttesterConfigurationServlet configuration = new AttesterConfigurationServlet();
        configuration.init(yes);
        assertFailed("AttesterConfigurationServlet", "challengeRequired");
        assertEquals(503, status(configuration));
        configuration.init(config(Map.of("challengeRequired", " TRUE ")));
        assertEquals(ComponentState.READY, part("AttesterConfigurationServlet").state(), "true in any case, trimmed");
    }

    private static void assertFailed(String part, String setting) {
        PartStatus status = part(part);
        assertEquals(ComponentState.FAILED_CONFIG, status.state(), part);
        assertTrue(status.reason().contains(setting), status.reason());
    }

    @Test
    void developmentReadsALegacySwitchSpellingAsTheOldReaderDid() {
        ClientAttestationServiceMetadataServlet metadata = new ClientAttestationServiceMetadataServlet();
        metadata.start(development(Map.of("challengeRequired", "yes", "challengeEndpointEnabled", "off",
                "attestationSigningAlgValuesSupported", "ES256 PS256", "customClaimsRequired", "deployment_id, region")));
        Map<String, Object> doc = metadata.metadata("https://attester.example.com");
        assertEquals(false, doc.get("challenge_required"), "yes was false to the reader before 0.6.0, and is still");
        assertFalse(doc.containsKey("challenge_endpoint"), "off: the challenge endpoint is not advertised");
        assertEquals(List.of("ES256", "PS256"), doc.get("attestation_signing_alg_values_supported"), "split at spaces too");
        assertEquals(List.of("deployment_id", "region"), doc.get("custom_claims_required"));
    }

    @Test
    void aListOfNothingIsRefusedWhereItOnceMeantTheDefault() {
        ClientAttestationServiceMetadataServlet metadata = new ClientAttestationServiceMetadataServlet();
        SettingRefused refused = assertThrows(SettingRefused.class,
                () -> metadata.start(development(Map.of("attestationSigningAlgValuesSupported", ", ,"))));
        assertEquals("attestationSigningAlgValuesSupported", refused.setting());
    }

    @Test
    void anEnvironmentValueItsEntryRefusesFailsTheIssuanceServletAtDeploy() throws Exception {
        Map<String, String> wrong = Map.of("oidf.wallet.provider.jwks", "[1]", "oidf.entra.agent.directory", "not json",
                "oidf.attester.spire.entries.url", "ftp://spire.example/entries");
        Map<String, String> named = Map.of("oidf.wallet.provider.jwks", "OIDF_WALLET_PROVIDER_JWKS",
                "oidf.entra.agent.directory", "OIDF_ENTRA_AGENT_DIRECTORY",
                "oidf.attester.spire.entries.url", "OIDF_ATTESTER_SPIRE_ENTRIES_URL");
        for (Map.Entry<String, String> property : wrong.entrySet()) {
            System.setProperty(property.getKey(), property.getValue());
            try {
                assertDoesNotThrow(() -> new AttestationIssuanceServlet().init(config(Map.of())));
                assertFailed("AttestationIssuanceServlet", named.get(property.getKey()));
            } finally {
                System.clearProperty(property.getKey());
            }
        }
        System.setProperty("oidf.wallet.provider.jwks", "[1]");
        new ClientAttestationServiceMetadataServlet().init(config(Map.of()));
        assertFailed("ClientAttestationServiceMetadataServlet", "OIDF_WALLET_PROVIDER_JWKS");
    }

    @Test
    void anEvidencePolicyItsEntriesRefuseFailsTheIssuanceServletAtDeploy() throws Exception {
        // A lifetime of nothing, a lifetime above the production cap, and a switch that is neither true nor false: each
        // is FAILED_CONFIG at deploy, naming the variable, where before 0.6.0 each issuance answered 500.
        Map<String, String> wrong = Map.of("oidf.attester.max.evidence.lifetime.seconds", "0",
                "oidf.attester.require.single.audience.evidence", "yes");
        Map<String, String> named = Map.of("oidf.attester.max.evidence.lifetime.seconds", EvidencePolicy.MAX_LIFETIME_ENV,
                "oidf.attester.require.single.audience.evidence", EvidencePolicy.SINGLE_AUDIENCE_ENV);
        for (Map.Entry<String, String> property : wrong.entrySet()) {
            System.setProperty(property.getKey(), property.getValue());
            try {
                assertDoesNotThrow(() -> new AttestationIssuanceServlet().init(config(Map.of())));
                assertFailed("AttestationIssuanceServlet", named.get(property.getKey()));
            } finally {
                System.clearProperty(property.getKey());
            }
        }
        System.setProperty("oidf.attester.max.evidence.lifetime.seconds", "86401");
        new AttestationIssuanceServlet().init(config(Map.of()));
        assertFailed("AttestationIssuanceServlet", EvidencePolicy.MAX_LIFETIME_ENV);

        // Read at deploy and kept: the policy the first request uses is the one init read.
        System.setProperty("oidf.attester.max.evidence.lifetime.seconds", "120");
        System.setProperty("oidf.attester.require.single.audience.evidence", "TRUE");
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.init(config(Map.of()));
        assertEquals(ComponentState.READY, part("AttestationIssuanceServlet").state());
        System.clearProperty("oidf.attester.max.evidence.lifetime.seconds");
        System.clearProperty("oidf.attester.require.single.audience.evidence");
        assertEquals(120L, servlet.evidencePolicy().maxEvidenceLifetimeSeconds());
        assertTrue(servlet.evidencePolicy().requireSingleAudience());
    }

    @Test
    void theRequestPathReadsTheSameEntries() {
        assertInstanceOf(WorkloadIntrospector.none().getClass(), new AttestationIssuanceServlet().defaultWorkloadIntrospector());
        System.setProperty("oidf.attester.spire.entries.url", " https://spire.example/entries ");
        assertInstanceOf(SpireSelectorIntrospector.class, new AttestationIssuanceServlet().defaultWorkloadIntrospector());

        assertNull(AttestationIssuanceServlet.entraDirectoryResolverFromEnv());
        System.setProperty("oidf.entra.agent.directory", "{\"oid-1\":{\"display_name\":\"Agent\"}}");
        assertTrue(AttestationIssuanceServlet.entraDirectoryResolverFromEnv() != null);

        System.setProperty("oidf.wallet.provider.jwks", "{\"https://wallet.example\":1}");
        assertNull(AttestationIssuanceServlet.staticWalletValidatorFromEnv(), "no entry is a JWK Set");
    }

    @Test
    void aKeyAndAPolicyGivenBeforeInitAreKept() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        EvidencePolicy policy = new EvidencePolicy(60L, true);
        servlet.setAttesterSigningKey(new AttesterSigningKey(null, null));
        servlet.setEvidencePolicy(policy);
        servlet.init(config(Map.of()));
        assertEquals(ComponentState.READY, part("AttestationIssuanceServlet").state());
        assertSame(policy, servlet.evidencePolicy());
    }

    @Test
    void theOpenBaoAddressAndTokenAreReadThroughTheirEntries() {
        IssuanceException none = assertThrows(IssuanceException.class,
                () -> AttesterSigningKey.fromEnvironment().signerFor("attester-key", null));
        assertTrue(none.getMessage().contains("no OpenBao address/token"), none.getMessage());

        // Set, the vault is asked: nothing listens on port 1, so the signer is unavailable rather than unconfigured.
        System.setProperty("oidf.openbao.url", "http://127.0.0.1:1");
        System.setProperty("oidf.openbao.token", "s.test-token");
        IssuanceException asked = assertThrows(IssuanceException.class,
                () -> AttesterSigningKey.fromEnvironment().signerFor("attester-key", null));
        assertTrue(asked.getMessage().startsWith("OpenBao transit signer unavailable"), asked.getMessage());
        assertFalse(asked.getMessage().contains("s.test-token"), asked.getMessage());
    }

    @Test
    void theEvidencePolicyIsReadStrictlyWithTheDevelopmentEscape() {
        Map<String, String> none = Map.of();
        IllegalArgumentException production = assertThrows(IllegalArgumentException.class,
                () -> EvidencePolicy.fromEnvironment(none::get, Map.of(EvidencePolicy.SINGLE_AUDIENCE_ENV, "yes")::get));
        assertTrue(production.getMessage().contains(EvidencePolicy.SINGLE_AUDIENCE_ENV), production.getMessage());
        EvidencePolicy development = EvidencePolicy.fromEnvironment(none::get, Map.of(EvidencePolicy.SINGLE_AUDIENCE_ENV, "yes",
                DeploymentProfile.SETTING, "development")::get);
        assertFalse(development.requireSingleAudience(), "yes: false, as the legacy rule reads every such spelling");
        assertEquals(60L, EvidencePolicy.fromEnvironment(none::get, Map.of(EvidencePolicy.MAX_LIFETIME_ENV, " 60 ")::get)
                .maxEvidenceLifetimeSeconds());
        IllegalArgumentException zero = assertThrows(IllegalArgumentException.class,
                () -> EvidencePolicy.fromEnvironment(none::get, Map.of(EvidencePolicy.MAX_LIFETIME_ENV, "0")::get));
        assertTrue(zero.getMessage().contains(EvidencePolicy.MAX_LIFETIME_ENV), zero.getMessage());
    }
}
