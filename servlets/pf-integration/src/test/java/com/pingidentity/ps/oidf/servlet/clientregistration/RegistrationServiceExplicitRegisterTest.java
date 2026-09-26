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
import com.pingidentity.ps.oidf.federation.ValidationRequest;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.pf.ClientStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.conformance.Requirement;
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
    /** The RP's configuration and the anchor's statement about it: the anchor is the RP's Immediate Superior. */
    private static final List<String> TRUST_CHAIN = RegistrationFixtures.chain(CLIENT_ID, "https://tc.example", java.time.Clock.systemUTC());

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
        // Policed: a superior declared a metadata_policy for this entity type - the default requirement.
        return new TrustChainValidationResult("https://tc.example", CLIENT_ID, Map.of(entityType, metadata), TRUST_CHAIN, leaf, Set.of(entityType));
    }

    /** As {@link #resultWith} but with NO superior policy for the type - a chain that constrains nothing. */
    private TrustChainValidationResult unpolicedResultWith(String entityType, Map<String, Object> metadata) {
        JwtClaims leaf = new JwtClaims();
        leaf.setClaim("jwks", Map.of("keys", List.of(
                Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def", "kid", "k1"))));
        return new TrustChainValidationResult("https://tc.example", CLIENT_ID, Map.of(entityType, metadata), TRUST_CHAIN, leaf, Set.of());
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
    @Requirement("OIDFED §12.2.2(2.8)")
    void registersANewClientAfterTheChainValidates() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        when(validator.validate(any(ValidationRequest.class)))
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
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("explicit")));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER));

        assertEquals(409, e.status());
        verify(store, never()).add(any());
        verify(store, never()).update(any());
        verify(store, never()).disable(any());
    }

    @Test
    @Requirement("OIDFED §12.2.2(2.7)")
    void refreshesAClientItPreviouslyRegisteredInsteadOfDisablingIt() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(clientWithStatus("registered"));
        when(validator.validate(any(ValidationRequest.class)))
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
        when(validator.validate(any(ValidationRequest.class)))
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
        when(validator.validate(any(ValidationRequest.class)))
                .thenThrow(new IllegalArgumentException("no route to anchor"));

        assertThrows(IllegalArgumentException.class,
                () -> service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER));

        verify(store, never()).add(any());
        verify(store, never()).update(any());
        verify(store, never()).disable(any());
    }

    @Test
    @Requirement("OIDFED §5.1.2(4.2)")
    void refusesALeafThatDoesNotAdvertiseExplicitRegistration() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("automatic")));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER));

        assertEquals(400, e.status());
        verify(store, never()).add(any());
    }

    @Test
    @Requirement("OIDFED §12(3)")
    void registersAnOauthClientLeafWithNoRelyingPartyBlock() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(null);
        Map<String, Object> agent = Map.of(
                "client_registration_types", List.of("explicit"),
                "grant_types", List.of("client_credentials"),
                "client_name", "Agent");
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(resultWith("oauth_client", agent));

        RegisteredClient rc = service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER);

        assertNotNull(rc);
        verify(store).add(any());
    }

    // ---- §12.2.3: the response is an Entity Statement about the RP, for the RP --------------------------

    private static final String INTERMEDIATE = "https://intermediate.example";

    /** Registers through an Intermediate, the chain expiring at {@code chainExp}, and returns what was answered and stored. */
    private static Registered registerThroughIntermediate(String entityType, Map<String, Object> metadata, long chainExp,
                                                           com.pingidentity.ps.oidf.federation.testkit.MutableClock clock) throws Exception {
        return registerThroughIntermediate(Map.of(entityType, metadata), chainExp, clock);
    }

    private static Registered registerThroughIntermediate(Map<String, Object> metadataByType,
                                                           com.pingidentity.ps.oidf.federation.testkit.MutableClock clock) throws Exception {
        return registerThroughIntermediate(metadataByType, -1L, clock);
    }

    private static Registered registerThroughIntermediate(Map<String, Object> metadataByType, long chainExp,
                                                           com.pingidentity.ps.oidf.federation.testkit.MutableClock clock) throws Exception {
        List<String> chain = RegistrationFixtures.chain(CLIENT_ID, INTERMEDIATE, clock);
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(RegistrationFixtures.result(CLIENT_ID, chain, metadataByType, metadataByType.keySet(), chainExp));
        RegisteredClient rc = RegistrationFixtures.service(validator, store, clock,
                        com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement.REFUSE)
                .explicitRegister(request(Map.of()), OP_ISSUER);
        ArgumentCaptor<Client> stored = ArgumentCaptor.forClass(Client.class);
        verify(store).add(stored.capture());
        JwtClaims leaf = com.pingidentity.ps.oidf.jose.JwtCodec.parseUnverifiedClaims(chain.get(0));
        return new Registered(rc, stored.getValue(), leaf);
    }

    private record Registered(RegisteredClient response, Client stored, JwtClaims leaf) {
        JwtClaims claims() throws Exception {
            return com.pingidentity.ps.oidf.jose.JwtCodec.parseUnverifiedClaims(this.response.signedJwt());
        }

        Map<String, Object> header() throws Exception {
            return com.pingidentity.ps.oidf.jose.JwtCodec.getJwtHeaders(this.response.signedJwt());
        }
    }

    @Test
    @Requirement({"OIDFED §12.2.3(6)", "OIDFED §12.2.3(8.12)", "OIDFED §12.2.3(9)"})
    void theResponseIsSignedByTheOpForTheRpAlone() throws Exception {
        var clock = com.pingidentity.ps.oidf.federation.testkit.MutableClock.startingNow();
        Registered r = registerThroughIntermediate("openid_relying_party", rpMetadata("explicit"), -1L, clock);

        JwtClaims claims = r.claims();
        assertEquals(OP_ISSUER, claims.getIssuer());
        assertEquals(CLIENT_ID, claims.getSubject());
        assertEquals(List.of(CLIENT_ID), claims.getAudience());
        assertEquals(clock.epochSecond(), claims.getIssuedAt().getValue());
        assertEquals("explicit-registration-response+jwt", r.header().get("typ"));
        assertEquals("op-1", r.header().get("kid"));
        org.jose4j.jws.JsonWebSignature jws = new org.jose4j.jws.JsonWebSignature();
        jws.setCompactSerialization(r.response().signedJwt());
        jws.setKey(RegistrationFixtures.signer().publicKey());
        org.junit.jupiter.api.Assertions.assertTrue(jws.verifySignature(), "signed with the OP's current key");
    }

    @Test
    @Requirement({"OIDFED §12.2.3(2)", "OIDFED §12.2.3(8.16)"})
    void theResponseNamesTheAnchorAndTheRpsImmediateSuperior() throws Exception {
        Registered r = registerThroughIntermediate("openid_relying_party", rpMetadata("explicit"), -1L,
                com.pingidentity.ps.oidf.federation.testkit.MutableClock.startingNow());

        assertEquals(RegistrationFixtures.ANCHOR, r.claims().getClaimValue("trust_anchor"));
        assertEquals(List.of(INTERMEDIATE), r.claims().getClaimValue("authority_hints"),
                "a single-element array naming the superior that issued the statement about the RP - not the anchor");
        assertEquals(RegistrationFixtures.ANCHOR, RegistrationFixtures.param(r.stored(), FederationClientParams.TRUST_ANCHOR));
    }

    /** An RP that is itself a configured anchor has no superior: its chain is its configuration alone. */
    @Test
    void anRpWhoseChainIsItsConfigurationAloneNamesTheAnchorAsSuperior() throws Exception {
        var clock = com.pingidentity.ps.oidf.federation.testkit.MutableClock.startingNow();
        List<String> alone = List.of(RegistrationFixtures.chain(CLIENT_ID, INTERMEDIATE, clock).get(0));
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(validator.validate(any(ValidationRequest.class))).thenReturn(RegistrationFixtures.result(CLIENT_ID, alone,
                Map.of("openid_relying_party", rpMetadata("explicit")), Set.of("openid_relying_party"), -1L));

        RegisteredClient rc = RegistrationFixtures.service(validator, store, clock,
                com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement.REFUSE).explicitRegister(request(Map.of()), OP_ISSUER);

        assertEquals(List.of(RegistrationFixtures.ANCHOR),
                com.pingidentity.ps.oidf.jose.JwtCodec.parseUnverifiedClaims(rc.signedJwt()).getClaimValue("authority_hints"));
    }

    @Test
    @Requirement({"OIDFED §12.2.3(3)", "OIDFED §12.2.2(2.9)", "OIDFED §12.3(1)"})
    void theResponseAndTheRegistrationExpireWithTheChain() throws Exception {
        var clock = com.pingidentity.ps.oidf.federation.testkit.MutableClock.startingNow();
        long chainExp = clock.epochSecond() + 1800L;
        Registered r = registerThroughIntermediate("openid_relying_party", rpMetadata("explicit"), chainExp, clock);

        assertEquals(chainExp, r.claims().getExpirationTime().getValue());
        assertEquals(chainExp, r.response().expiresAt());
        assertEquals(Long.toString(chainExp), RegistrationFixtures.param(r.stored(), FederationClientParams.EXPIRES_AT));
    }

    @Test
    @Requirement("OIDFED §12.2.3(8.10)")
    void theResponseCarriesTheRpsOwnKeysVerbatim() throws Exception {
        Registered r = registerThroughIntermediate("openid_relying_party", rpMetadata("explicit"), -1L,
                com.pingidentity.ps.oidf.federation.testkit.MutableClock.startingNow());

        assertEquals(r.leaf().getClaimValue("jwks"), r.claims().getClaimValue("jwks"),
                "the jwks of the RP's Entity Configuration, not the OP's own keys");
    }

    @Test
    @Requirement({"OIDFED §12.2.3(4)", "OIDFED §12.2.3(5)"})
    void theResponseCarriesTheRegisteredMetadataWithItsClientIdAndDefaults() throws Exception {
        var clock = com.pingidentity.ps.oidf.federation.testkit.MutableClock.startingNow();
        Registered r = registerThroughIntermediate("openid_relying_party", rpMetadata("explicit"), -1L, clock);

        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) ((Map<String, Object>) r.claims().getClaimValue("metadata")).get("openid_relying_party");
        assertEquals(CLIENT_ID, metadata.get("client_id"));
        assertEquals(clock.epochSecond(), ((Number) metadata.get("client_id_issued_at")).longValue());
        assertEquals("private_key_jwt", metadata.get("token_endpoint_auth_method"), "the default, as registered");
        assertEquals(List.of(CLIENT_ID + "/cb"), metadata.get("redirect_uris"));
        assertEquals(Set.of("openid_relying_party"), ((Map<?, ?>) r.claims().getClaimValue("metadata")).keySet());
    }

    @Test
    @Requirement("OIDFED §12(3)")
    void anAgentRegisteredFromOauthClientMetadataIsAnsweredUnderThatType() throws Exception {
        Map<String, Object> agent = Map.of("client_registration_types", List.of("explicit"), "grant_types", List.of("client_credentials"));
        Registered r = registerThroughIntermediate("oauth_client", agent, -1L,
                com.pingidentity.ps.oidf.federation.testkit.MutableClock.startingNow());

        assertEquals(Set.of("oauth_client"), ((Map<?, ?>) r.claims().getClaimValue("metadata")).keySet());
        assertEquals("oauth_client", RegistrationFixtures.param(r.stored(), FederationClientParams.ENTITY_TYPE));
    }

    @Test
    @Requirement("OIDFED §12.3(1)")
    void aChainThatExpiresSoonerThanARegistrationNeedsIsRefused() throws Exception {
        var clock = com.pingidentity.ps.oidf.federation.testkit.MutableClock.startingNow();
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(validator.validate(any(ValidationRequest.class))).thenReturn(RegistrationFixtures.result(CLIENT_ID, TRUST_CHAIN,
                Map.of("openid_relying_party", rpMetadata("explicit")), Set.of("openid_relying_party"), clock.epochSecond() + 30L));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> RegistrationFixtures.service(validator, store, clock, com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement.REFUSE)
                        .explicitRegister(request(Map.of()), OP_ISSUER));

        assertEquals("invalid_trust_chain", e.error());
        verify(store, never()).add(any());
    }

    @Test
    @Requirement("OIDFED §12.2.4(1)")
    void aChainThatDoesNotValidateIsRefusedWithItsFederationError() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(validator.validate(any(ValidationRequest.class))).thenThrow(new com.pingidentity.ps.oidf.federation.TrustChainValidationException(
                com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind.ROUTE, null, CLIENT_ID, "no route"));

        try (var events = com.pingidentity.ps.oidf.federation.testkit.EventCapture.install()) {
            RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                    () -> service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER));

            assertEquals(400, e.status());
            assertEquals("invalid_trust_chain", e.error());
            assertEquals(RegistrationRejectedException.Kind.TRUST, e.kind());
            assertEquals(CLIENT_ID, events.only(com.pingidentity.ps.oidf.federation.event.FederationEvents.REGISTRATION_REFUSED).subject());
        }
        verify(store, never()).add(any());
    }

    @Test
    void theChainValidatedIsTheOneTheRequestPresentedToTheOp() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("explicit")));
        List<String> peer = List.of("peer-statement");
        ExplicitRegistrationRequest request = new ExplicitRegistrationRequest(CLIENT_ID, CLIENT_ID, TRUST_CHAIN, Map.of(), null, peer);

        service(validator, store).explicitRegister(request, OP_ISSUER);

        ArgumentCaptor<ValidationRequest> asked = ArgumentCaptor.forClass(ValidationRequest.class);
        verify(validator).validate(asked.capture());
        assertEquals(CLIENT_ID, asked.getValue().subject());
        assertEquals(OP_ISSUER, asked.getValue().opIssuer());
        assertEquals(TRUST_CHAIN, asked.getValue().presentedChain());
        assertEquals(peer, asked.getValue().peerTrustChain());
    }

    // ---- a renewal re-enables only what expiry disabled ----------------------------------------------------

    private static Client disabledRegistration(boolean byExpiry) {
        Client existing = RegistrationFixtures.federationClient(CLIENT_ID, "registered", 1L, TRUST_CHAIN);
        if (byExpiry) {
            existing.getExtendedParams().put(FederationClientParams.DISABLED_AT, RegistrationFixtures.values(List.of("2")));
        }
        existing.setEnabled(false);
        return existing;
    }

    @Test
    @Requirement("OIDFED §12.3(1)")
    void registeringAgainEnablesAClientItsExpiryDisabled() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(disabledRegistration(true));
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("explicit")));

        service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER);

        ArgumentCaptor<Client> updated = ArgumentCaptor.forClass(Client.class);
        verify(store).update(updated.capture());
        org.junit.jupiter.api.Assertions.assertTrue(updated.getValue().isEnabled());
        org.junit.jupiter.api.Assertions.assertNull(RegistrationFixtures.param(updated.getValue(), FederationClientParams.DISABLED_AT),
                "the mark goes with the disable it recorded");
    }

    @Test
    @Requirement("OIDFED §12.2.6(2)")
    void registeringAgainLeavesAnOperatorsDisableInPlace() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        when(store.get(CLIENT_ID)).thenReturn(disabledRegistration(false));
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("explicit")));

        service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER);

        ArgumentCaptor<Client> updated = ArgumentCaptor.forClass(Client.class);
        verify(store).update(updated.capture());
        org.junit.jupiter.api.Assertions.assertFalse(updated.getValue().isEnabled(),
                "an OP may end a registration early (§12.2.6); registering again does not overrule it");
    }

    /** §12.2 is written for OpenID Connect RPs: a leaf that is both is registered explicitly as the RP. */
    @Test
    @Requirement("OIDFED §12(3)")
    void explicitRegistrationPrefersTheRelyingPartyMetadata() throws Exception {
        Map<String, Object> agent = Map.of("client_registration_types", List.of("explicit"), "client_name", "as an agent");
        Registered r = registerThroughIntermediate(Map.of("oauth_client", agent, "openid_relying_party", rpMetadata("explicit")),
                com.pingidentity.ps.oidf.federation.testkit.MutableClock.startingNow());

        assertEquals(Set.of("openid_relying_party"), ((Map<?, ?>) r.claims().getClaimValue("metadata")).keySet());
        assertEquals("RP", r.stored().getName());
    }

    @Test
    void aRefreshRecordsWhetherTheKeysChanged() throws Exception {
        TrustChainValidator validator = mock(TrustChainValidator.class);
        ClientStore store = mock(ClientStore.class);
        Client existing = RegistrationFixtures.federationClient(CLIENT_ID, "registered", 1L, TRUST_CHAIN);
        existing.setJwks("{\"keys\":[{\"kid\":\"old\"}]}");
        when(store.get(CLIENT_ID)).thenReturn(existing);
        when(validator.validate(any(ValidationRequest.class)))
                .thenReturn(resultWith("openid_relying_party", rpMetadata("explicit")));

        try (var events = com.pingidentity.ps.oidf.federation.testkit.EventCapture.install()) {
            service(validator, store).explicitRegister(request(Map.of()), OP_ISSUER);

            var refreshed = events.only(com.pingidentity.ps.oidf.federation.event.FederationEvents.REGISTRATION_REFRESHED);
            assertEquals("true", refreshed.fields().get("keys_changed"));
            assertEquals("1", refreshed.fields().get("previous_expires_at"));
        }
    }

    @Test
    void keysAreComparedAsJsonNotAsText() {
        org.junit.jupiter.api.Assertions.assertTrue(RegistrationService.sameKeys("{\"keys\":[{\"kid\":\"a\",\"kty\":\"EC\"}]}",
                "{ \"keys\" : [ { \"kty\":\"EC\", \"kid\":\"a\" } ] }"));
        org.junit.jupiter.api.Assertions.assertFalse(RegistrationService.sameKeys("{\"keys\":[{\"kid\":\"a\"}]}", "{\"keys\":[{\"kid\":\"b\"}]}"));
        org.junit.jupiter.api.Assertions.assertFalse(RegistrationService.sameKeys(null, "{}"));
        org.junit.jupiter.api.Assertions.assertFalse(RegistrationService.sameKeys("{}", null));
        org.junit.jupiter.api.Assertions.assertTrue(RegistrationService.sameKeys(null, null));
        org.junit.jupiter.api.Assertions.assertFalse(RegistrationService.sameKeys("not json", "{}"));
    }
}
