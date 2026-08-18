package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.pf.ClientStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ClientAuthenticationType;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * OpenID Federation §12.2 explicit registration at the service layer. The contract this pins:
 * the store is touched only after the trust chain has validated; a client this module did not
 * register is never modified (409, no side effect); a client it did register is refreshed from the
 * re-validated chain; nothing is ever disabled.
 */
class RegistrationServiceExplicitRegisterTest {

    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String OP_ISSUER = "https://as.example.com";
    private static final List<String> TRUST_CHAIN = List.of("leafJwt", "anchorJwt");

    private static SigningKeyProvider signer() throws Exception {
        RsaJsonWebKey k = RsaJwkGenerator.generateJwk(2048);
        k.setKeyId("op-1");
        return new SigningKeyProvider() {
            @Override public String keyId() { return "op-1"; }
            @Override public RSAPrivateKey privateKey() { return k.getRsaPrivateKey(); }
            @Override public RSAPublicKey publicKey() { return k.getRsaPublicKey(); }
        };
    }

    private RegistrationService service(TrustChainValidator validator, ClientStore store) throws Exception {
        return new RegistrationService(new RegistrationConfiguration("https://tc.example", false), validator, store, signer());
    }

    private static ExplicitRegistrationRequest request(Map<String, Object> metadata) {
        return new ExplicitRegistrationRequest(CLIENT_ID, CLIENT_ID, TRUST_CHAIN, metadata);
    }

    private static TrustChainValidationResult resultWith(String entityType, Map<String, Object> metadata) {
        JwtClaims leaf = new JwtClaims();
        leaf.setClaim("jwks", Map.of("keys", List.of(
                Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def", "kid", "k1"))));
        return new TrustChainValidationResult("https://tc.example", CLIENT_ID, Map.of(entityType, metadata), TRUST_CHAIN, leaf);
    }

    private static Client clientWithStatus(String status) {
        Client client = new Client();
        if (status != null) {
            ParamValues values = new ParamValues();
            values.setElements(List.of(status));
            Map<String, ParamValues> params = new HashMap<>();
            params.put("status", values);
            client.setExtendedParams(params);
        }
        return client;
    }

    private static Map<String, Object> rpMetadata(String... registrationTypes) {
        return Map.of(
                "client_registration_types", List.of(registrationTypes),
                "redirect_uris", List.of(CLIENT_ID + "/cb"),
                "client_name", "RP");
    }

    @Test
    void registersANewClientAfterTheChainValidates() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("explicit")));

        RegisteredClient rc = service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER);

        assertNotNull(rc.signedJwt());
        assertEquals("registered", rc.toMap().get("status"));
        ArgumentCaptor<Client> captor = ArgumentCaptor.forClass(Client.class);
        verify(store).add(captor.capture());
        verify(store, never()).update(any());
        verify(store, never()).disable(any());
        assertEquals(ClientAuthenticationType.PRIVATE_KEY_JWT, captor.getValue().getClientAuthnType());
    }

    @Test
    void neverTouchesAClientThisModuleDidNotRegister() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(clientWithStatus(null));   // console / terraform client
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("explicit")));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER));

        assertEquals(409, e.status());
        verify(store, never()).add(any());
        verify(store, never()).update(any());
        verify(store, never()).disable(any());
    }

    @Test
    void refreshesAClientItPreviouslyRegisteredInsteadOfDisablingIt() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(clientWithStatus("registered"));
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("explicit")));

        service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER);

        verify(store).update(any());
        verify(store, never()).add(any());
        verify(store, never()).disable(any());
    }

    @Test
    void anAutoRegisteredClientMayBePromotedByExplicitRegistration() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(clientWithStatus("auto_registered"));
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("explicit")));

        service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER);

        verify(store).update(any());
        verify(store, never()).disable(any());
    }

    @Test
    void chainValidationFailureLeavesTheStoreUntouched() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(clientWithStatus("registered"));
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenThrow(new IllegalArgumentException("no route to anchor"));

        assertThrows(IllegalArgumentException.class,
                () -> service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER));

        verify(store, never()).add(any());
        verify(store, never()).update(any());
        verify(store, never()).disable(any());
    }

    @Test
    void refusesALeafThatDoesNotAdvertiseExplicitRegistration() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("automatic")));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER));

        assertEquals(400, e.status());
        verify(store, never()).add(any());
    }

    @Test
    void registersAnOauthClientLeafWithNoRelyingPartyBlock() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        Map<String, Object> agent = Map.of(
                "client_registration_types", List.of("explicit"),
                "grant_types", List.of("client_credentials"),
                "client_name", "Agent");
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(resultWith("oauth_client", agent));

        RegisteredClient rc = service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER);

        assertNotNull(rc);
        verify(store).add(any());
    }
}
