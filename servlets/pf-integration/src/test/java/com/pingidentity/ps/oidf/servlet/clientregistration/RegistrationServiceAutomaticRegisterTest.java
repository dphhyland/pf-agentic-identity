package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * Unit tests for OpenID Federation §12.1 automatic (transparent) client registration.
 *
 * <p>Ported from pf-oidf-modules (2026-08-15) when that repo was reduced to the demo. Adapted to the
 * unwound packages ({@code ...oidf.federation}) and to {@link TrustChainValidationResult} now carrying
 * resolved metadata keyed BY ENTITY TYPE rather than a single flat leaf block.
 */
class RegistrationServiceAutomaticRegisterTest {

    private static final String CLIENT_ID = "https://rp.example.com/e/agent-42";
    private static final String OP_ISSUER = "https://as.example.com";
    private static final List<String> TRUST_CHAIN = List.of("leafJwt", "anchorJwt");

    private RegistrationService service(TrustChainValidator validator, ClientStore store) {
        return new RegistrationService(new RegistrationConfiguration("https://tc.example", false), validator, store);
    }

    /** A validation result whose leaf holds {@code metadata} under the given entity type. */
    private TrustChainValidationResult resultWith(String entityType, Map<String, Object> metadata) {
        JwtClaims leaf = new JwtClaims();
        leaf.setClaim("jwks", Map.of("keys", List.of(
                Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def", "kid", "k1"))));
        return new TrustChainValidationResult(
                "https://tc.example", CLIENT_ID, Map.of(entityType, metadata), TRUST_CHAIN, leaf);
    }

    private static Client clientWithStatus(String status) {
        Client client = new Client();
        ParamValues values = new ParamValues();
        values.setElements(List.of(status));
        Map<String, ParamValues> params = new HashMap<>();
        params.put("status", values);
        client.setExtendedParams(params);
        return client;
    }

    @Test
    void autoRegistersWhenClientAdvertisesAutomatic() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        Map<String, Object> meta = Map.of(
                "client_registration_types", List.of("automatic"),
                "grant_types", List.of("client_credentials"),
                "token_endpoint_auth_method", "private_key_jwt",
                "scope", "read_accounts create_opportunity",
                "client_name", "Agent 42");
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("openid_relying_party", meta));

        RegisteredClient registered = service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER);

        assertNotNull(registered);
        assertEquals("auto_registered", registered.toMap().get("status"));
        ArgumentCaptor<Client> captor = ArgumentCaptor.forClass(Client.class);
        verify(store).add(captor.capture());
        Client provisioned = captor.getValue();
        assertEquals(CLIENT_ID, provisioned.getClientId());
        assertEquals("auto_registered", provisioned.getExtendedParams().get("status").getElements().get(0));
    }

    /**
     * An agent leaf carries its client metadata as {@code oauth_client}, not {@code openid_relying_party}.
     * Reading only the latter (the deprecated {@code leafMetadata()}) made every agent unregisterable.
     */
    @Test
    void autoRegistersALeafCarryingOauthClientMetadata() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        Map<String, Object> meta = Map.of(
                "client_registration_types", List.of("automatic"),
                "grant_types", List.of("client_credentials"),
                "token_endpoint_auth_method", "private_key_jwt",
                "scope", "read_accounts");
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("oauth_client", meta));

        assertNotNull(service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER));
        verify(store).add(org.mockito.ArgumentMatchers.any());
    }

    /**
     * A client_credentials client has no redirect_uris / response_types. PingFederate's client store
     * iterates those lists unguarded when saving, so they must never reach it as null.
     */
    @Test
    void buildsUsableClientWhenRedirectAndResponseMetadataAreAbsent() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        Map<String, Object> meta = Map.of(
                "client_registration_types", List.of("automatic"),
                "grant_types", List.of("client_credentials"),
                "token_endpoint_auth_method", "private_key_jwt",
                "scope", "read_accounts");
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("oauth_client", meta));

        service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER);

        ArgumentCaptor<Client> captor = ArgumentCaptor.forClass(Client.class);
        verify(store).add(captor.capture());
        Client provisioned = captor.getValue();
        assertNotNull(provisioned.getRedirectUris(), "redirect URIs must be an empty list, never null");
        assertNotNull(provisioned.getRestrictedResponseTypes(), "response types must be an empty list, never null");
        assertEquals(0, provisioned.getRedirectUris().size());
    }

    @Test
    void isIdempotentForAnAlreadyRegisteredClient() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(new Client());

        assertNull(service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER));

        verify(store, never()).add(org.mockito.ArgumentMatchers.any());
        verifyNoInteractions(validator);
    }

    /**
     * An auto-registered client is wholly derived from its trust chain, so a chain presenting new keys
     * must refresh the stored record — otherwise a re-keyed entity is locked out for good (its
     * client_assertion no longer verifies against the stale stored jwks).
     */
    @Test
    void refreshesAnAutoRegisteredClientWhenTheChainRevalidates() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(clientWithStatus("auto_registered"));
        Map<String, Object> meta = Map.of(
                "client_registration_types", List.of("automatic"),
                "grant_types", List.of("client_credentials"),
                "token_endpoint_auth_method", "private_key_jwt",
                "scope", "read_accounts");
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("oauth_client", meta));

        assertNotNull(service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER));

        verify(store).update(org.mockito.ArgumentMatchers.any());
        verify(store, never()).add(org.mockito.ArgumentMatchers.any());
    }

    /** A manually registered client is never touched by automatic registration. */
    @Test
    void leavesAManuallyRegisteredClientAlone() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(clientWithStatus("registered"));

        assertNull(service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER));

        verify(store, never()).add(org.mockito.ArgumentMatchers.any());
        verify(store, never()).update(org.mockito.ArgumentMatchers.any());
        verifyNoInteractions(validator);
    }

    @Test
    void refusesClientThatDoesNotAdvertiseAutomatic() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        Map<String, Object> meta = Map.of(
                "grant_types", List.of("client_credentials"), "scope", "read_accounts");
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("oauth_client", meta));

        assertThrows(IllegalStateException.class,
                () -> service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER));
        verify(store, never()).add(org.mockito.ArgumentMatchers.any());
    }
}
