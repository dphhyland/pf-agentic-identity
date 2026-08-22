/*
 * PfIssuanceClientResolver: the production wiring from a PingFederate Client's attestation_* extended
 * properties into an AttestationIssuanceConfig. Reads only; provisioning happens out of band.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.issuer.AttesterClient;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import com.pingidentity.ps.oidf.pf.ClientStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

class PfIssuanceClientResolverTest {

    private static final String CLIENT_ID = "https://rp.example.com/agent-1";

    private static Client clientWithProps(boolean enabled, Map<String, String> props) {
        Client client = new Client();
        client.setClientId(CLIENT_ID);
        client.setEnabled(enabled);
        Map<String, ParamValues> extended = new HashMap<>();
        for (Map.Entry<String, String> e : props.entrySet()) {
            ParamValues values = new ParamValues();
            values.setElements(List.of(e.getValue()));
            extended.put(e.getKey(), values);
        }
        client.setExtendedParams(extended);
        return client;
    }

    /** The minimum attestation_* properties fromProperties() accepts (spiffe-jwt, bundle by URL). */
    private static Map<String, String> minimalAttestationProps() {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, "https://attester.example.com");
        props.put(AttestationIssuanceConfig.P_BUNDLE_URL, "https://attester.example.com/jwks.json");
        return props;
    }

    // ---- resolve(clientId) ----------------------------------------------------------------------

    @Test
    void resolveRejectsAnUnknownClient() {
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        PfIssuanceClientResolver resolver = new PfIssuanceClientResolver(store);

        IssuanceException e = assertThrows(IssuanceException.class, () -> resolver.resolve(CLIENT_ID));

        assertEquals("invalid_client", e.error());
    }

    /**
     * A disabled client must not resolve to a usable config — this is the seam the class doc says a
     * trust-controller check later replaces, and today it is the only status gate issuance has.
     */
    @Test
    void resolveRejectsADisabledClient() {
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(clientWithProps(false, minimalAttestationProps()));
        PfIssuanceClientResolver resolver = new PfIssuanceClientResolver(store);

        IssuanceException e = assertThrows(IssuanceException.class, () -> resolver.resolve(CLIENT_ID));

        assertEquals("invalid_client", e.error());
        assertTrue(e.getMessage().contains("disabled"), e.getMessage());
    }

    @Test
    void resolveProjectsExtendedPropertiesIntoTheConfig() throws Exception {
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(clientWithProps(true, minimalAttestationProps()));
        PfIssuanceClientResolver resolver = new PfIssuanceClientResolver(store);

        AttestationIssuanceConfig config = resolver.resolve(CLIENT_ID);

        assertEquals("https://attester.example.com", config.issuer());
    }

    @Test
    void resolvePropagatesAnInvalidConfiguration() {
        ClientStore store = mock(ClientStore.class);
        // No attestation_issuer at all - fromProperties() must reject it, not resolve to a broken config.
        when(store.get(CLIENT_ID)).thenReturn(clientWithProps(true, Map.of()));
        PfIssuanceClientResolver resolver = new PfIssuanceClientResolver(store);

        IssuanceException e = assertThrows(IssuanceException.class, () -> resolver.resolve(CLIENT_ID));

        assertEquals("invalid_client", e.error());
    }

    // ---- attestationClients() --------------------------------------------------------------------

    @Test
    void attestationClientsSkipsDisabledClients() throws Exception {
        ClientStore store = mock(ClientStore.class);
        when(store.getAll()).thenReturn(List.of(clientWithProps(false, minimalAttestationProps())));
        PfIssuanceClientResolver resolver = new PfIssuanceClientResolver(store);

        assertTrue(resolver.attestationClients().isEmpty());
    }

    /** A client with no attestation_issuer at all is not configured for issuance - not a config error. */
    @Test
    void attestationClientsSkipsClientsWithNoAttestationIssuer() throws Exception {
        ClientStore store = mock(ClientStore.class);
        when(store.getAll()).thenReturn(List.of(clientWithProps(true, Map.of())));
        PfIssuanceClientResolver resolver = new PfIssuanceClientResolver(store);

        assertTrue(resolver.attestationClients().isEmpty());
    }

    /**
     * A single misconfigured attestation client must not sink the whole attester - every other client
     * stays resolvable.
     */
    @Test
    void attestationClientsSkipsAMisconfiguredClientButKeepsTheRest() throws Exception {
        ClientStore store = mock(ClientStore.class);
        Map<String, String> broken = new HashMap<>(minimalAttestationProps());
        broken.put(AttestationIssuanceConfig.P_TTL, "not-a-number"); // fromProperties() rejects this
        Client brokenClient = clientWithProps(true, broken);
        brokenClient.setClientId("https://rp.example.com/broken");
        Client goodClient = clientWithProps(true, minimalAttestationProps());
        goodClient.setClientId("https://rp.example.com/good");
        when(store.getAll()).thenReturn(List.of(brokenClient, goodClient));
        PfIssuanceClientResolver resolver = new PfIssuanceClientResolver(store);

        List<AttesterClient> clients = resolver.attestationClients();

        assertEquals(1, clients.size());
        assertEquals("https://rp.example.com/good", clients.get(0).clientId());
    }

    @Test
    void attestationClientsIsEmptyWhenTheStoreHasNoClients() throws Exception {
        ClientStore store = mock(ClientStore.class);
        when(store.getAll()).thenReturn(null);
        PfIssuanceClientResolver resolver = new PfIssuanceClientResolver(store);

        assertTrue(resolver.attestationClients().isEmpty());
    }
}
