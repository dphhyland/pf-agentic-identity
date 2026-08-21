package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * A trust chain proves an entity is who it says and that the anchor vouches for its existence. It does
 * not, by itself, say what that entity may <em>do</em>: OpenID Federation lets a chain carry no
 * {@code metadata_policy} at all, and when none does, the leaf's self-published {@code scope},
 * {@code grant_types} and {@code response_types} are resolved verbatim and written onto a PF client.
 *
 * <p>{@code MetadataPolicy} applies a policy faithfully — the gap was that nothing required one to
 * exist. These tests pin the fail-closed default and, as much as the default itself, the two ordering
 * decisions around it: which rejection wins when more than one applies, and which entity type is
 * checked when a leaf carries several.
 */
class RegistrationMetadataPolicyRequirementTest {

    private static final String CLIENT_ID = "https://rp.example.com/e/agent-42";
    private static final String OP_ISSUER = "https://as.example.com";
    private static final List<String> TRUST_CHAIN = List.of("leafJwt", "anchorJwt");
    private static final String REQUIRE_PROP = "oidf.require.metadata.policy";

    /** Metadata an unconstrained leaf could publish about itself — note the scope it simply asks for. */
    private static final Map<String, Object> GREEDY_METADATA = Map.of(
            "client_registration_types", List.of("automatic", "explicit"),
            "grant_types", List.of("client_credentials"),
            "token_endpoint_auth_method", "private_key_jwt",
            "scope", "read_accounts transfer_funds admin",
            "client_name", "Agent 42");

    @BeforeEach
    @AfterEach
    void clearConfig() throws Exception {
        System.clearProperty(REQUIRE_PROP);
        java.lang.reflect.Field instance = FederationRuntimeConfig.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    private RegistrationService service(TrustChainValidator validator, ClientStore store) {
        return new RegistrationService(new RegistrationConfiguration("https://tc.example", false), validator, store);
    }

    private static TrustChainValidationResult result(Map<String, Object> metadataByType, Set<String> policed) {
        JwtClaims leaf = new JwtClaims();
        leaf.setClaim("jwks", Map.of("keys", List.of(
                Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def", "kid", "k1"))));
        return new TrustChainValidationResult("https://tc.example", CLIENT_ID, metadataByType, TRUST_CHAIN, leaf, policed);
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

    // ---- the default: no policy anywhere in the chain is a refusal, not a silent grant ---------------

    @Test
    void automaticRegistrationIsRefusedWhenNoSuperiorConstrainedTheType() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(result(Map.of("oauth_client", GREEDY_METADATA), Set.of()));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER));

        assertEquals(400, e.status());
        assertTrue(e.getMessage().contains("metadata_policy"), e.getMessage());
        assertTrue(e.getMessage().contains(FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV),
                "the rejection must name the flag that relaxes it: " + e.getMessage());
        verify(store, never()).add(any());
        verify(store, never()).update(any());
    }

    @Test
    void explicitRegistrationIsRefusedWhenNoSuperiorConstrainedTheType() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(result(Map.of("oauth_client", GREEDY_METADATA), Set.of()));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service(validator, store).explicitRegister(
                        new ExplicitRegistrationRequest(CLIENT_ID, CLIENT_ID, TRUST_CHAIN, Map.of()), OP_ISSUER));

        assertEquals(400, e.status());
        verify(store, never()).add(any());
    }

    @Test
    void aPolicedTypeRegistersNormally() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(result(Map.of("oauth_client", GREEDY_METADATA), Set.of("oauth_client")));

        RegisteredClient registered = service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER);

        assertNotNull(registered);
        verify(store).add(any());
    }

    // ---- the type checked is the one CONSUMED, not merely one that happens to be policed ------------

    /**
     * The registration path prefers {@code oauth_client}. An anchor that publishes a policy only for
     * {@code openid_relying_party} has therefore constrained nothing about the block actually used, and
     * treating that as "policed" would be the whole defect wearing a policy as a disguise.
     */
    @Test
    void aPolicyForAnEntityTypeThisRegistrationDoesNotUseDoesNotCount() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(result(
                        Map.of("oauth_client", GREEDY_METADATA, "openid_relying_party", GREEDY_METADATA),
                        Set.of("openid_relying_party")));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER));

        assertTrue(e.getMessage().contains("oauth_client"),
                "must name the type actually consumed, not the one that happened to be policed: " + e.getMessage());
        verify(store, never()).add(any());
    }

    // ---- ordering: a more specific rejection still wins ---------------------------------------------

    /**
     * A client PF's administrator owns is not ours to touch, and saying so is more useful than telling
     * the caller its chain lacks a policy. The 409 is deliberately checked first.
     */
    @Test
    void theManuallyAdministeredConflictStillWinsOverThePolicyCheck() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(clientWithStatus(null));   // no status = administrator's
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(result(Map.of("oauth_client", GREEDY_METADATA), Set.of()));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service(validator, store).explicitRegister(
                        new ExplicitRegistrationRequest(CLIENT_ID, CLIENT_ID, TRUST_CHAIN, Map.of()), OP_ISSUER));

        assertEquals(409, e.status(), "the specific conflict, not the policy check: " + e.getMessage());
        assertTrue(e.getMessage().contains("administered outside"), e.getMessage());
    }

    // ---- the escape hatch, for interop and bootstrap ------------------------------------------------

    @Test
    void theRequirementCanBeTurnedOffDeliberately() throws Exception {
        System.setProperty(REQUIRE_PROP, "false");
        java.lang.reflect.Field instance = FederationRuntimeConfig.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);

        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        when(validator.validate(anyList(), eq(CLIENT_ID), eq(OP_ISSUER), anyLong(), anyLong(), anyLong()))
                .thenReturn(result(Map.of("oauth_client", GREEDY_METADATA), Set.of()));

        RegisteredClient registered = service(validator, store).automaticRegister(TRUST_CHAIN, CLIENT_ID, OP_ISSUER);

        assertNotNull(registered, "with the flag off, an unconstrained chain registers");
        verify(store).add(any());
    }

    @Test
    void theDefaultIsOnWhenNothingIsConfigured() {
        assertTrue(FederationRuntimeConfig.get().requireMetadataPolicy(),
                "an unset OIDF_REQUIRE_METADATA_POLICY must mean ON - a permissive default is invisible "
                        + "in exactly the deployments least likely to notice it");
    }
}
