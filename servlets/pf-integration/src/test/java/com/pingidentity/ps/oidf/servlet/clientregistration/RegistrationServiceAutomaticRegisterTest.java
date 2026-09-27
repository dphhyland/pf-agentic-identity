package com.pingidentity.ps.oidf.servlet.clientregistration;

import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.ANCHOR;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.OP_ISSUER;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.agentMetadata;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.chain;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.federationClient;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.jwks;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.param;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.result;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidationRequest;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ClientAuthenticationType;

/**
 * OpenID Federation §12.1 automatic registration, as the token endpoint drives it through
 * {@link RegistrationService#admit}: a client the OP has never seen, named by its Entity Identifier, is
 * provisioned from its validated chain before PingFederate authenticates the request.
 *
 * <p>Ported from pf-oidf-modules (2026-08-15) when that repo was reduced to the demo; moved from the retired
 * {@code automaticRegister} onto {@code admit} with the registration lifetime.
 */
class RegistrationServiceAutomaticRegisterTest {

    private static final String CLIENT_ID = "https://rp.example.com/e/agent-42";
    private final MutableClock clock = MutableClock.startingNow();
    private final List<String> presented = chain(CLIENT_ID, ANCHOR, this.clock);

    private RegistrationService service(TrustChainValidator validator, ClientStore store) throws Exception {
        return RegistrationFixtures.service(validator, store, this.clock, ExpiryEnforcement.REFUSE);
    }

    private Client registeredFrom(String entityType, Map<String, Object> metadata) throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(result(CLIENT_ID, this.presented, Map.of(entityType, metadata), Set.of(entityType), -1L));

        assertEquals(RegistrationService.Admission.REGISTERED, service(validator, store).admit(CLIENT_ID, this.presented, OP_ISSUER));

        ArgumentCaptor<Client> captor = ArgumentCaptor.forClass(Client.class);
        verify(store).add(captor.capture());
        return captor.getValue();
    }

    @Test
    @Requirement("OIDFED §12.1(4.1)")
    void aClientNamedByItsEntityIdentifierIsRegisteredUnderIt() throws Exception {
        Client provisioned = registeredFrom("openid_relying_party", agentMetadata("automatic"));

        assertEquals(CLIENT_ID, provisioned.getClientId());
        assertEquals("auto_registered", param(provisioned, FederationClientParams.STATUS));
        assertEquals(ANCHOR, param(provisioned, FederationClientParams.TRUST_ANCHOR));
        assertEquals("openid_relying_party", param(provisioned, FederationClientParams.ENTITY_TYPE));
        assertEquals(this.presented, provisioned.getExtendedParams().get("trust_chain").getElements(),
                "the chain stored is the one validated, so the next request can tell a newer one from it");
    }

    @Test
    @Requirement("OIDFED §12.1(4.2)")
    void anAutomaticallyRegisteredClientAuthenticatesWithItsKeys() throws Exception {
        Client provisioned = registeredFrom("oauth_client", agentMetadata("automatic"));

        assertEquals(ClientAuthenticationType.PRIVATE_KEY_JWT, provisioned.getClientAuthnType());
        assertEquals("oauth_client", param(provisioned, FederationClientParams.ENTITY_TYPE));
    }

    /**
     * §12.1.2: the OP verifies the client's authentication with the keys its metadata publishes, and §3.1.1 keeps
     * the Federation Entity Keys out of other protocols. So an agent that publishes {@code jwks} for
     * {@code oauth_client} is registered with those keys, and a {@code private_key_jwt} assertion signed with its
     * Federation Entity Key is not one PingFederate accepts.
     */
    @Test
    @Requirement("OIDFED §12.1.2")
    void anAgentThatPublishesKeysForOauthClientIsRegisteredWithThem() throws Exception {
        Map<String, Object> metadata = new java.util.HashMap<>(agentMetadata("automatic"));
        metadata.put("jwks", jwks("agent-1", "xyz"));

        Client provisioned = registeredFrom("oauth_client", metadata);

        assertTrue(provisioned.getJwks().contains("\"kid\":\"agent-1\""), "its oauth_client keys");
        assertFalse(provisioned.getJwks().contains("\"kid\":\"k1\""), "not its Federation Entity Keys");
        assertNull(provisioned.getJwksUrl());
    }

    /** An agent that publishes no protocol keys keeps its Federation Entity Keys, as before. */
    @Test
    void anAgentThatPublishesNoKeysIsRegisteredWithItsFederationEntityKeys() throws Exception {
        Client provisioned = registeredFrom("oauth_client", agentMetadata("automatic"));

        assertTrue(provisioned.getJwks().contains("\"kid\":\"k1\""), "its Federation Entity Keys");
        assertNull(provisioned.getJwksUrl());
    }

    @Test
    @Requirement("OIDFED §12.3(1)")
    void theRegistrationRecordsWhenItEnds() throws Exception {
        Client provisioned = registeredFrom("oauth_client", agentMetadata("automatic"));

        long expiresAt = Long.parseLong(param(provisioned, FederationClientParams.EXPIRES_AT));
        assertEquals(this.clock.epochSecond() + 86_400L, expiresAt, "a chain of unknown expiry lives the deployment's maximum");
    }

    /**
     * A client_credentials client has no redirect_uris / response_types. PingFederate's client store
     * iterates those lists unguarded when saving, so they must never reach it as null.
     */
    @Test
    void buildsUsableClientWhenRedirectAndResponseMetadataAreAbsent() throws Exception {
        Client provisioned = registeredFrom("oauth_client", agentMetadata("automatic"));

        assertNotNull(provisioned.getRedirectUris(), "redirect URIs must be an empty list, never null");
        assertNotNull(provisioned.getRestrictedResponseTypes(), "response types must be an empty list, never null");
        assertEquals(0, provisioned.getRedirectUris().size());
    }

    @Test
    void anUnknownClientWithNoChainIsLeftToPingFederate() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);

        assertEquals(RegistrationService.Admission.NOT_FEDERATION, service(validator, store).admit(CLIENT_ID, List.of(), OP_ISSUER));
        assertEquals(RegistrationService.Admission.NOT_FEDERATION, service(validator, store).admit(CLIENT_ID, null, OP_ISSUER));

        verifyNoInteractions(validator);
        verify(store, never()).add(any());
    }

    /** A console or Terraform client - no {@code status} - is never touched, whatever chain the request carries. */
    @Test
    void leavesAClientItDidNotRegisterAlone() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(new Client());

        assertEquals(RegistrationService.Admission.NOT_FEDERATION, service(validator, store).admit(CLIENT_ID, this.presented, OP_ISSUER));

        verifyNoInteractions(validator);
        verify(store, never()).update(any());
    }

    /** An explicit registration is its RP's to renew: automatic registration never rewrites a current one. */
    @Test
    void leavesACurrentExplicitRegistrationAlone() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(federationClient(CLIENT_ID, "registered", this.clock.epochSecond() + 3600L, this.presented));

        assertEquals(RegistrationService.Admission.CURRENT, service(validator, store).admit(CLIENT_ID, this.presented, OP_ISSUER));

        verifyNoInteractions(validator);
        verify(store, never()).update(any());
    }

    @Test
    @Requirement("OIDFED §5.1.2(4.2)")
    void refusesAClientThatDoesNotAdvertiseAutomatic() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(result(CLIENT_ID, this.presented, Map.of("oauth_client", agentMetadata("explicit")), Set.of("oauth_client"), -1L));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service(validator, store).admit(CLIENT_ID, this.presented, OP_ISSUER));

        assertEquals(400, e.status());
        assertEquals("invalid_client_metadata", e.error());
        assertEquals(RegistrationRejectedException.Kind.METADATA, e.kind());
        verify(store, never()).add(any());
    }

    @Test
    void refusesAChainThatHasNoClientMetadataAtAll() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(result(CLIENT_ID, this.presented, Map.of("federation_entity", Map.of("organization_name", "x")), Set.of(), -1L));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service(validator, store).admit(CLIENT_ID, this.presented, OP_ISSUER));

        assertEquals("invalid_client_metadata", e.error());
        verify(store, never()).add(any());
    }

    /** The token endpoint is where agents arrive: a leaf that is both is registered from its oauth_client metadata. */
    @Test
    @Requirement("OIDFED §12(3)")
    void automaticRegistrationPrefersTheOauthClientMetadata() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        Map<String, Object> asRp = Map.of("client_registration_types", List.of("automatic"), "client_name", "as an RP");
        when(validator.validate(any(ValidationRequest.class))).thenReturn(result(CLIENT_ID, this.presented,
                Map.of("oauth_client", agentMetadata("automatic"), "openid_relying_party", asRp), Set.of("oauth_client", "openid_relying_party"), -1L));

        service(validator, store).admit(CLIENT_ID, this.presented, OP_ISSUER);

        ArgumentCaptor<Client> captor = ArgumentCaptor.forClass(Client.class);
        verify(store).add(captor.capture());
        assertEquals("oauth_client", param(captor.getValue(), FederationClientParams.ENTITY_TYPE));
        assertEquals("Agent", captor.getValue().getName());
    }

    /** An empty oauth_client block says nothing: the RP metadata beside it is what registers. */
    @Test
    void anEmptyOauthClientBlockDefersToTheRelyingPartyMetadata() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(validator.validate(any(ValidationRequest.class))).thenReturn(result(CLIENT_ID, this.presented,
                Map.of("oauth_client", Map.of(), "openid_relying_party", agentMetadata("automatic")), Set.of("openid_relying_party"), -1L));

        service(validator, store).admit(CLIENT_ID, this.presented, OP_ISSUER);

        ArgumentCaptor<Client> captor = ArgumentCaptor.forClass(Client.class);
        verify(store).add(captor.capture());
        assertEquals("openid_relying_party", param(captor.getValue(), FederationClientParams.ENTITY_TYPE));
    }
}
