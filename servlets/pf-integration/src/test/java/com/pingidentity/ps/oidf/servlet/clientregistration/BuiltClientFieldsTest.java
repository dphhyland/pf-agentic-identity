package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.pf.ClientStore;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.sourceid.oauth20.domain.Client;

/**
 * What actually gets written onto the PF client when a federation leaf omits optional metadata.
 *
 * <p>{@code String.valueOf(null)} is the four-character string {@code "null"}, not null — so every
 * absent optional field was being written to PF as that literal. A client genuinely named "null" is
 * cosmetic; a client whose {@code restrictedScopes} is {@code ["null"]} is not, because no token will
 * ever carry a scope by that name and the client is quietly unusable.
 *
 * <p>Also pins the approval-page rule, which used to be an unconditional bypass.
 */
class BuiltClientFieldsTest {

    private static final String CLIENT_ID = "https://rp.example.com/e/agent-42";
    private static final String OP_ISSUER = "https://as.example.com";
    private static final List<String> TRUST_CHAIN = List.of("leafJwt", "anchorJwt");

    /** Registers a leaf carrying exactly {@code metadata} and returns the Client handed to the store. */
    private static Client register(Map<String, Object> metadata) throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        JwtClaims leaf = new JwtClaims();
        leaf.setClaim("jwks", Map.of("keys", List.of(
                Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def", "kid", "k1"))));
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(new TrustChainValidationResult("https://tc.example", CLIENT_ID,
                        Map.of("oauth_client", metadata), TRUST_CHAIN, leaf, Set.of("oauth_client")));

        new RegistrationService(new RegistrationConfiguration("https://tc.example", false), validator, store)
                .automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER);

        ArgumentCaptor<Client> captor = ArgumentCaptor.forClass(Client.class);
        verify(store).add(captor.capture());
        return captor.getValue();
    }

    /** The minimum a leaf must advertise to auto-register; everything else deliberately absent. */
    private static Map<String, Object> bareMetadata(String... extraPairs) {
        java.util.LinkedHashMap<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("client_registration_types", List.of("automatic"));
        m.put("grant_types", List.of("client_credentials"));
        for (int i = 0; i + 1 < extraPairs.length; i += 2) {
            m.put(extraPairs[i], extraPairs[i + 1]);
        }
        return m;
    }

    @Test
    void anAbsentScopeIsNoScopesNotAScopeCalledNull() throws Exception {
        Client c = register(bareMetadata());

        assertFalse(c.getRestrictedScopes().contains("null"),
                "a client restricted to a scope named \"null\" can never be issued a token");
        assertTrue(c.getRestrictedScopes().isEmpty());
    }

    @Test
    void anAbsentClientNameIsNotTheLiteralNull() throws Exception {
        Client c = register(bareMetadata());
        assertNotEquals("null", c.getName());
    }

    @Test
    void absentSigningAlgorithmsAreNotTheLiteralNull() throws Exception {
        Client c = register(bareMetadata());

        assertNotEquals("null", c.getTokenEndpointAuthSigningAlgorithm());
        assertNotEquals("null", c.getIdTokenSigningAlgorithm());
        assertNotEquals("null", c.getRequestObjectSigningAlgorithm());
    }

    @Test
    void whatTheLeafDoesAdvertiseIsStillCarriedThrough() throws Exception {
        Client c = register(bareMetadata("scope", "read_accounts create_opportunity",
                "client_name", "Agent 42"));

        assertEquals(List.of("read_accounts", "create_opportunity"), c.getRestrictedScopes());
        assertEquals("Agent 42", c.getName());
    }

    // ---- the approval page ------------------------------------------------------------------------

    @Test
    void aClientCredentialsOnlyClientBypassesTheApprovalPage() throws Exception {
        Client c = register(bareMetadata());
        assertTrue(c.isBypassApprovalPage(), "there is no resource owner present to ask");
    }

    @Test
    void aUserFacingClientDoesNotBypassTheApprovalPage() throws Exception {
        java.util.LinkedHashMap<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("client_registration_types", List.of("automatic"));
        m.put("grant_types", List.of("authorization_code", "refresh_token"));
        Client c = register(m);

        assertFalse(c.isBypassApprovalPage(),
                "an authorization_code client has a user in front of it; consent was being suppressed");
    }
}
