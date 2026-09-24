package com.pingidentity.ps.oidf.servlet.clientregistration;

import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.ANCHOR;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.federationClient;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.param;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.result;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidationRequest;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import com.pingidentity.ps.oidf.pf.testkit.FakeClientStore;
import com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationService.Admission;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.sourceid.oauth20.domain.Client;

/**
 * Automatic registration at the authorization and PAR endpoints (OpenID Federation 1.0 §12.1.1), through
 * {@link RegistrationService#admit}: only an RP, only with its own keys, and only once the request has shown it holds
 * one of them. The request is a stranger's until that proof verifies, so these tests are also about what a stranger
 * can make the OP do: register nothing, fetch nothing it need not, and spoil nothing for the real RP.
 */
class RegistrationServiceFrontChannelTest {

    private static final String RP = "https://rp.example.com";
    private static final String OP = "https://op.example.com";

    private final MutableClock clock = MutableClock.startingNow();
    private final TrustChainValidator validator = mock(TrustChainValidator.class);
    private final FakeClientStore store = new FakeClientStore();
    private final Set<String> spent = new HashSet<>();
    private final RequestObject.ReplayGuard replay = (client, jti, ttl) -> this.spent.add(client + " " + jti);
    private final List<String> chain = RegistrationFixtures.chain(RP, ANCHOR, this.clock);
    private EllipticCurveJsonWebKey rpKey;
    private EventCapture events;

    @BeforeEach
    void setUp() throws Exception {
        this.rpKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        this.rpKey.setKeyId("rp-1");
        this.events = EventCapture.install();
    }

    @AfterEach
    void tearDown() {
        this.events.close();
    }

    private RegistrationService service() {
        return new RegistrationService(new RegistrationConfiguration(ANCHOR, false), this.validator, this.store, null,
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((url, accept) -> {
                    throw new java.io.IOException("no fetch expected: " + url);
                }, this.clock), new RegistrationCoordinator(8, 0L));
    }

    private Map<String, Object> rpMetadata() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("client_registration_types", List.of("automatic"));
        metadata.put("redirect_uris", List.of(RP + "/cb"));
        metadata.put("jwks", Map.of("keys", List.of(this.rpKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))));
        return metadata;
    }

    private void federationResolves(Map<String, Object> metadataByType) throws Exception {
        when(this.validator.validate(any(ValidationRequest.class)))
                .thenReturn(result(RP, this.chain, metadataByType, metadataByType.keySet(), -1L));
    }

    private String requestObject(EllipticCurveJsonWebKey signer, Consumer<Map<String, Object>> change, List<String> trustChain) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("client_id", RP);
        claims.put("iss", RP);
        claims.put("aud", OP);
        claims.put("jti", "jti-" + System.nanoTime());
        claims.put("exp", this.clock.epochSecond() + 300);
        change.accept(claims);
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(JsonUtil.toJson(claims));
            jws.setKey(signer.getPrivateKey());
            jws.setAlgorithmHeaderValue("ES256");
            jws.setKeyIdHeaderValue(signer.getKeyId());
            if (trustChain != null) {
                jws.setHeader("trust_chain", trustChain);
            }
            return jws.getCompactSerialization();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private RequestObject proof(String compact) throws RegistrationRejectedException {
        return RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, compact);
    }

    private Admission admit(RegistrationService service, RequestObject proof, AutoRegistrationSettings settings) throws Exception {
        return service.admit(RP, proof == null ? List.of() : proof.trustChain(), OP,
                service.frontChannel("authorization", RP, OP, proof, null, this.replay, settings));
    }

    private Admission admit(RegistrationService service, RequestObject proof) throws Exception {
        return this.admit(service, proof, AutoRegistrationSettings.DEFAULTS);
    }

    @Test
    @Requirement({"OIDFED §12.1.1.1.2(1)", "OIDFED §12.1.1.1.2(7)", "OIDFED §12.1.1.2.1(2)"})
    void anRpIsRegisteredWithItsOwnKeysOnceItsRequestObjectVerifies() throws Exception {
        this.federationResolves(Map.of("openid_relying_party", this.rpMetadata()));

        assertEquals(Admission.REGISTERED, this.admit(this.service(), this.proof(this.requestObject(this.rpKey, c -> { }, null))));

        Client client = this.store.get(RP);
        assertTrue(client.isRequireSignedRequests());
        assertEquals("rp-1", ((Map<?, ?>) ((List<?>) JsonUtil.parseJson(client.getJwks()).get("keys")).get(0)).get("kid"),
                "the keys it publishes for openid_relying_party, not its Federation Entity Keys");
        assertEquals("openid_relying_party", param(client, FederationClientParams.ENTITY_TYPE));
        assertEquals(1, this.spent.size(), "its jti is spent");
        assertEquals("authorization", this.events.only(FederationEvents.REGISTRATION_CREATED).fields().get("endpoint"));
    }

    /**
     * A stranger sends a request object for a real RP, signed with some other key. Nothing is registered, and the
     * refusal is not remembered against the RP: its own request a moment later registers it - reusing the chain the
     * stranger's request resolved, so the stranger's flood costs one resolution, not one per request.
     */
    @Test
    @Requirement({"OIDFED §12.1.1.1.2(7)", "OIDFED §12.1.1(2)"})
    void aRequestObjectSignedByAnotherKeyRegistersNothingAndSpoilsNothing() throws Exception {
        this.federationResolves(Map.of("openid_relying_party", this.rpMetadata()));
        EllipticCurveJsonWebKey stranger = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        stranger.setKeyId("rp-1");
        RegistrationService service = this.service();

        for (int i = 0; i < 3; i++) {
            RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                    () -> this.admit(service, this.proof(this.requestObject(stranger, c -> { }, null))));
            assertEquals(401, e.status());
            assertEquals("invalid_client", e.error());
        }
        assertEquals(List.of(), this.store.writes());
        assertEquals(Set.of(), this.spent, "nothing spent for a proof that failed");

        assertEquals(Admission.REGISTERED, this.admit(service, this.proof(this.requestObject(this.rpKey, c -> { }, null))));
        verify(this.validator, times(1)).validate(any(ValidationRequest.class));
    }

    @Test
    @Requirement("OIDFED §12.1.1(2)")
    void withoutProofNothingIsRegisteredOrFetched() throws Exception {
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> this.admit(this.service(), null));

        assertEquals("invalid_request", e.error());
        assertEquals(RegistrationRejectedException.Kind.REQUEST, e.kind());
        verifyNoInteractions(this.validator);
    }

    @Test
    void anUnreadableProofIsRefusedAsItsOwnError() throws Exception {
        RegistrationRejectedException unreadable = RegistrationRejectedException.request(400, "invalid_request_object", "not a JWS");
        RegistrationService service = this.service();

        assertSame(unreadable, assertThrows(RegistrationRejectedException.class, () -> service.admit(RP, List.of(), OP,
                service.frontChannel("authorization", RP, OP, null, unreadable, this.replay, AutoRegistrationSettings.DEFAULTS))));
        verifyNoInteractions(this.validator);
    }

    @Test
    @Requirement("OIDFED §12.1.1.1(2.8)")
    void aRequestObjectThatBreaksTheProfileCostsNoFetch() throws Exception {
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> this.admit(this.service(), this.proof(this.requestObject(this.rpKey, c -> c.put("sub", RP), null))));

        assertEquals("invalid_request_object", e.error());
        verifyNoInteractions(this.validator);
    }

    @Test
    void anEncryptedRequestObjectRegistersOnlyWhereThatIsAllowed() throws Exception {
        this.federationResolves(Map.of("openid_relying_party", this.rpMetadata()));
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String jwe = b64.encodeToString("{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\"}".getBytes(StandardCharsets.UTF_8)) + ".a.b.c.d";
        AutoRegistrationSettings refuse = new AutoRegistrationSettings(true, true, false, "openid", false, true, 65_536, 8, 2_000L, null);

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> this.admit(this.service(), this.proof(jwe), refuse));
        assertEquals("invalid_request_object", e.error());
        verifyNoInteractions(this.validator);

        assertEquals(Admission.REGISTERED, this.admit(this.service(), this.proof(jwe)));
        assertEquals(Set.of(), this.spent, "PingFederate checks it once it has decrypted it");
    }

    @Test
    @Requirement("OIDFED §12.1.1.1.2(5)")
    void onlyAnRpIsRegisteredHere() throws Exception {
        this.federationResolves(Map.of("oauth_client", RegistrationFixtures.agentMetadata("automatic")));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> this.admit(this.service(), this.proof(this.requestObject(this.rpKey, c -> { }, null))));

        assertEquals("invalid_client_metadata", e.error());
        assertTrue(e.getMessage().contains("openid_relying_party"), e.getMessage());
        assertEquals(List.of(), this.store.writes());
    }

    @Test
    @Requirement("OIDFED §12.1.1.1.2(7)")
    void anRpThatPublishesNoKeysOfItsOwnIsNotRegisteredHere() throws Exception {
        Map<String, Object> keyless = this.rpMetadata();
        keyless.remove("jwks");
        this.federationResolves(Map.of("openid_relying_party", keyless));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> this.admit(this.service(), this.proof(this.requestObject(this.rpKey, c -> { }, null))));

        assertEquals("invalid_client_metadata", e.error());
    }

    @Test
    @Requirement("OIDFED §12.1.1.1(2.10)")
    void aRequestObjectUsedBeforeRegistersNothing() throws Exception {
        this.federationResolves(Map.of("openid_relying_party", this.rpMetadata()));
        RegistrationService service = this.service();

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> service.admit(RP, List.of(), OP,
                service.frontChannel("authorization", RP, OP, this.proof(this.requestObject(this.rpKey, c -> { }, null)), null,
                        (client, jti, ttl) -> false, AutoRegistrationSettings.DEFAULTS)));

        assertTrue(e.getMessage().contains("used before"), e.getMessage());
        assertEquals(List.of(), this.store.writes());
    }

    @Test
    void anRpWithACurrentRegistrationGoesStraightThrough() throws Exception {
        this.store.with(federationClient(RP, "auto_registered", this.clock.epochSecond() + 3600, this.chain));

        assertEquals(Admission.CURRENT, this.admit(this.service(), null));
        verifyNoInteractions(this.validator);
    }

    @Test
    @Requirement({"OIDFED §12.1.1.1.2(2)", "OIDFED §12.1.1.1.2(5)"})
    void aChainInTheRequestObjectIsTriedAsItStandsThenDiscoveryFromTheRp() throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenAnswer(invocation -> {
            ValidationRequest request = invocation.getArgument(0);
            if (!request.presentedChain().isEmpty()) {
                throw new com.pingidentity.ps.oidf.federation.TrustChainValidationException(
                        com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind.BUDGET, null, RP, "incomplete");
            }
            return result(RP, this.chain, Map.of("openid_relying_party", this.rpMetadata()), Set.of("openid_relying_party"), -1L);
        });

        assertEquals(Admission.REGISTERED, this.admit(this.service(), this.proof(this.requestObject(this.rpKey, c -> { }, List.of("partial")))));

        ArgumentCaptor<ValidationRequest> asked = ArgumentCaptor.forClass(ValidationRequest.class);
        verify(this.validator, times(2)).validate(asked.capture());
        assertEquals(List.of("partial"), asked.getAllValues().get(0).presentedChain());
        assertEquals(0, asked.getAllValues().get(0).maxFetches());
        assertEquals(List.of(), asked.getAllValues().get(1).presentedChain());
    }

    @Test
    void aClientAnotherRequestRegisteredMeanwhileIsNotRegisteredAgain() throws Exception {
        Client registeredMeanwhile = federationClient(RP, "auto_registered", this.clock.epochSecond() + 3600, this.chain);
        ClientStore racing = mock(ClientStore.class);
        when(racing.get(RP)).thenReturn(null, registeredMeanwhile);
        RegistrationService service = new RegistrationService(new RegistrationConfiguration(ANCHOR, false), this.validator, racing, null,
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((u, a) -> "", this.clock),
                new RegistrationCoordinator(8, 0L));

        assertEquals(Admission.REGISTERED, service.admit(RP, List.of(), OP, service.frontChannel("authorization", RP, OP,
                this.proof(this.requestObject(this.rpKey, c -> { }, null)), null, this.replay, AutoRegistrationSettings.DEFAULTS)));

        verifyNoInteractions(this.validator);
        verify(racing, times(0)).add(any());
    }

    @Test
    void aClientAnotherServerAddedFirstIsLeftAsItWrote() throws Exception {
        this.federationResolves(Map.of("openid_relying_party", this.rpMetadata()));
        Client theirs = federationClient(RP, "auto_registered", this.clock.epochSecond() + 3600, this.chain);
        ClientStore racing = mock(ClientStore.class);
        when(racing.get(RP)).thenReturn(null, null, theirs);
        doThrow(new IllegalStateException("duplicate client")).when(racing).add(any());
        RegistrationService service = new RegistrationService(new RegistrationConfiguration(ANCHOR, false), this.validator, racing, null,
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((u, a) -> "", this.clock),
                new RegistrationCoordinator(8, 0L));

        assertEquals(Admission.REGISTERED, this.admit(service, this.proof(this.requestObject(this.rpKey, c -> { }, null))));

        ClientStore failing = mock(ClientStore.class);
        doThrow(new IllegalStateException("store down")).when(failing).add(any());
        RegistrationService broken = new RegistrationService(new RegistrationConfiguration(ANCHOR, false), this.validator, failing, null,
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((u, a) -> "", this.clock),
                new RegistrationCoordinator(8, 0L));
        assertEquals("store down", assertThrows(IllegalStateException.class,
                () -> this.admit(broken, this.proof(this.requestObject(this.rpKey, c -> { }, null)))).getMessage());
    }

    @Test
    void whenTheServerIsBusyAnRpIsToldToRetryAndACurrentOneCarriesOn() throws Exception {
        RegistrationCoordinator busy = mock(RegistrationCoordinator.class);
        doThrow(RegistrationRejectedException.busy("busy")).when(busy).register(anyString(), any());
        RegistrationService service = new RegistrationService(new RegistrationConfiguration(ANCHOR, false), this.validator, this.store, null,
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((u, a) -> "", this.clock), busy);

        assertEquals(RegistrationRejectedException.Kind.BUSY, assertThrows(RegistrationRejectedException.class,
                () -> this.admit(service, this.proof(this.requestObject(this.rpKey, c -> { }, null)))).kind());

        this.store.with(federationClient(RP, "auto_registered", this.clock.epochSecond() + 100, this.chain));
        assertEquals(Admission.DEFERRED, this.admit(service, this.proof(this.requestObject(this.rpKey, c -> { }, null))),
                "due, not expired: its registration stands");
        assertFalse(this.events.codes().contains(FederationEvents.REGISTRATION_REFRESH_DEFERRED), "busy is nobody's fault");

        this.clock.advance(java.time.Duration.ofSeconds(200));
        assertEquals(RegistrationRejectedException.Kind.BUSY, assertThrows(RegistrationRejectedException.class,
                () -> this.admit(service, this.proof(this.requestObject(this.rpKey, c -> { }, null)))).kind(),
                "expired: nothing to fall back on, so retry");
    }

    /** At the token endpoint an RP that publishes keys is registered with them; one that publishes none, as before. */
    @Test
    @Requirement("OIDFED §12.1.1.2.1(2)")
    void theTokenEndpointRegistersAnRpWithItsOwnKeysWhenItHasSome() throws Exception {
        this.federationResolves(Map.of("openid_relying_party", this.rpMetadata()));
        this.service().admit(RP, this.chain, OP);
        assertTrue(this.store.get(RP).getJwks().contains("rp-1"));

        FakeClientStore other = new FakeClientStore();
        Map<String, Object> keyless = this.rpMetadata();
        keyless.remove("jwks");
        when(this.validator.validate(any(ValidationRequest.class)))
                .thenReturn(result(RP, this.chain, Map.of("openid_relying_party", keyless), Set.of("openid_relying_party"), -1L));
        new RegistrationService(new RegistrationConfiguration(ANCHOR, false), this.validator, other, null,
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((u, a) -> "", this.clock),
                new RegistrationCoordinator(8, 0L)).admit(RP, this.chain, OP);
        assertTrue(other.get(RP).getJwks().contains("\"kid\":\"k1\""), "its Federation Entity Keys, as before 0.3.0");
        assertNull(other.get(RP).getJwksUrl());
    }

    /** A renewal at the front channel is held to the same proof: a forged request refuses, and the registration stands. */
    @Test
    @Requirement("OIDFED §12.1.1.1.2(7)")
    void aRenewalWithAForgedProofIsRefusedAndChangesNothing() throws Exception {
        this.federationResolves(Map.of("openid_relying_party", this.rpMetadata()));
        this.store.with(federationClient(RP, "auto_registered", this.clock.epochSecond() + 100, this.chain));
        EllipticCurveJsonWebKey stranger = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        stranger.setKeyId("rp-1");

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> this.admit(this.service(), this.proof(this.requestObject(stranger, c -> { }, null))));

        assertEquals(RegistrationRejectedException.Kind.REQUEST, e.kind());
        assertEquals(List.of(), this.store.writes());
    }

    @Test
    void sameRecordComparesTheRegistrationNotTheObject() {
        Client a = federationClient(RP, "auto_registered", 100L, List.of("ec-1"));
        assertTrue(RegistrationService.sameRecord(null, null));
        assertFalse(RegistrationService.sameRecord(a, null));
        assertFalse(RegistrationService.sameRecord(null, a));
        assertTrue(RegistrationService.sameRecord(a, federationClient(RP, "auto_registered", 100L, List.of("ec-1"))));
        assertFalse(RegistrationService.sameRecord(a, federationClient(RP, "auto_registered", 200L, List.of("ec-1"))));
        assertFalse(RegistrationService.sameRecord(a, federationClient(RP, "auto_registered", 100L, List.of("ec-2"))));
    }

    /** At the token endpoint an RP's keys by reference are fetched as at the front channel. */
    @Test
    void theTokenEndpointFollowsAnRpsKeysByReferenceToo() throws Exception {
        String jwks = JsonUtil.toJson(Map.of("keys", List.of(this.rpKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))));
        for (String parameter : List.of("jwks_uri", "signed_jwks_uri")) {
            Map<String, Object> byReference = this.rpMetadata();
            byReference.remove("jwks");
            byReference.put(parameter, RP + "/keys");
            FakeClientStore fresh = new FakeClientStore();
            when(this.validator.validate(any(ValidationRequest.class)))
                    .thenReturn(result(RP, this.chain, Map.of("openid_relying_party", byReference), Set.of("openid_relying_party"), -1L));
            RegistrationService service = new RegistrationService(new RegistrationConfiguration(ANCHOR, false), this.validator, fresh, null,
                    new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((u, a) -> jwks, this.clock),
                    new RegistrationCoordinator(8, 0L));

            if ("jwks_uri".equals(parameter)) {
                service.admit(RP, this.chain, OP);
                assertEquals(RP + "/keys", fresh.get(RP).getJwksUrl());
            } else {
                assertEquals("invalid_client_metadata", assertThrows(RegistrationRejectedException.class,
                        () -> service.admit(RP, this.chain, OP)).error(), "not a jwk-set+jwt: refused, not skipped");
            }
        }
    }
}
