package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

/**
 * What this entity does with client authentication at its federation endpoints (OpenID Federation 1.0 §8.8): says which
 * endpoints take it in its Entity Configuration (§8.8.1), refuses a request without it where it is required and with it
 * where it is not used, and records who authenticated and who was refused.
 */
class FederationServiceClientAuthTest {
    private static final String PF = "https://pf.example.com";
    private static final String TA = "https://ta.example.com";
    private static final String CLIENT = "https://client.example.com";
    private static final String FETCH = "federation_fetch_endpoint";
    private static final String LIST = "federation_list_endpoint";
    private static final String RESOLVE = "federation_resolve_endpoint";
    private static final PublicJsonWebKey PF_KEY = Keys.rsa("pf-1");
    private static final EndpointAuthPolicy POLICY = EndpointAuthPolicy.parse("{\"federation_fetch_endpoint\": \"required\","
            + " \"federation_resolve_endpoint\": \"optional\", \"federation_trust_mark_endpoint\": \"required\"}", List.of("ES256", "RS256"));

    private final MutableClock clock = MutableClock.startingNow();
    private final Federation federation = Federation.builder(this.clock).anchor(TA).leaf(CLIENT, TA).build();

    private static FederationConfiguration configuration() {
        return configuration(FederationConfiguration.ResolveDiscovery.KNOWN);
    }

    private static FederationConfiguration configuration(FederationConfiguration.ResolveDiscovery discovery) {
        return new FederationConfiguration(List.of(PF), List.of(), null, false, false, null, null, null, 0, "RS256",
                AttestationMetadataConfig.defaults(), null, null, FederationConfiguration.DEFAULT_CLIENT_REGISTRATION_TYPES, discovery);
    }

    private FederationService.Builder pf() {
        return this.pf(configuration());
    }

    private FederationService.Builder pf(FederationConfiguration configuration) {
        return FederationService.builder(configuration, Keys.signingKeys(PF_KEY))
                .resolver(this.federation.trustAnchors(), this.federation.gateway(TA), Set.of(),
                        ValidatorOptions.defaults().withClock(this.clock))
                .clock(this.clock);
    }

    private FederationService service() {
        return this.pf().endpointAuth(POLICY, (client, jti, ttl) -> true).build();
    }

    private String assertion(String audience) {
        return Statements.spec(null).claim("iss", CLIENT).claim("sub", CLIENT).claim("aud", audience).claim("jti", "j")
                .exp(this.clock.instant().getEpochSecond() + 60).sign(this.federation.key(CLIENT), this.clock);
    }

    private static Map<?, ?> federationEntity(FederationService service) throws Exception {
        return (Map<?, ?>) ((Map<?, ?>) JwtCodec.parseUnverifiedClaims(service.createEntityConfigurationJwt(PF)).getClaimValue("metadata"))
                .get("federation_entity");
    }

    @Test
    @Requirement({"OIDFED §8.8.1(2)", "OIDFED §8.8.1(3)", "OIDFED §8.8.1(6)", "OIDFED §8.8.1(7)", "OIDFED §5.1.1(3.16)"})
    void theEntityConfigurationSaysWhichOfItsEndpointsTakeClientAuthentication() throws Exception {
        Map<?, ?> advertised = federationEntity(this.service());

        assertEquals(List.of("private_key_jwt"), advertised.get("federation_fetch_endpoint_auth_methods"));
        assertEquals(List.of("none", "private_key_jwt"), advertised.get("federation_resolve_endpoint_auth_methods"));
        assertFalse(advertised.containsKey("federation_list_endpoint_auth_methods"), "absent is [\"none\"]");
        assertFalse(advertised.containsKey("federation_trust_mark_endpoint_auth_methods"), "an endpoint this entity doesn't serve says nothing");
        assertEquals(List.of("ES256", "RS256"), advertised.get("endpoint_auth_signing_alg_values_supported"));

        Map<?, ?> plain = federationEntity(this.pf().build());
        assertTrue(plain.keySet().stream().noneMatch(name -> name.toString().contains("_auth_")), "by default nothing authenticates");

        Map<?, ?> unserved = federationEntity(this.pf().endpointAuth(EndpointAuthPolicy.parse(
                "{\"federation_trust_mark_endpoint\": \"required\"}", List.of("ES256")), (client, jti, ttl) -> true).build());
        assertFalse(unserved.containsKey("endpoint_auth_signing_alg_values_supported"), "no algorithms for endpoints nobody can call");
    }

    @Test
    @Requirement({"OIDFED §8.8(1)", "OIDFED §8.8.1(3)"})
    void anEndpointThatRequiresAuthenticationRefusesARequestWithoutIt() {
        try (EventCapture events = EventCapture.install()) {
            FederationException e = assertThrows(FederationException.class, () -> this.service().authenticateClient(FETCH, null, null, PF));

            assertEquals(FederationError.INVALID_CLIENT, e.error());
            FederationEvent refused = events.only(FederationEvents.CLIENT_REFUSED);
            assertEquals("missing", refused.reason());
            assertTrue(refused.audit());
            assertEquals(FETCH, refused.fields().get("endpoint"));
        }
    }

    @Test
    @Requirement({"OIDFED §8.8(1)", "OIDFED §8.8.1(6)"})
    void anEndpointThatTakesNoneAcceptsOnlyUnauthenticatedRequests() {
        try (EventCapture events = EventCapture.install()) {
            FederationService service = this.service();
            assertNull(service.authenticateClient(LIST, null, null, PF));
            assertNull(service.authenticateClient(RESOLVE, null, null, PF), "optional: unauthenticated is fine");
            assertTrue(events.events().isEmpty());

            FederationException e = assertThrows(FederationException.class,
                    () -> service.authenticateClient(LIST, EndpointClientAuthentication.ASSERTION_TYPE, this.assertion(PF), PF));
            assertEquals(FederationError.INVALID_REQUEST, e.error());
            assertEquals("not_accepted", events.only(FederationEvents.CLIENT_REFUSED).reason());
            assertThrows(FederationException.class, () -> this.pf().build().authenticateClient(FETCH, "x", null, PF),
                    "half an assertion is still an attempt to authenticate");
        }
    }

    @Test
    @Requirement({"OIDFED §8.8(2)", "OIDFED §8.8.1(3)"})
    void aClientThatAuthenticatesIsKnownByItsEntityIdentifier() {
        try (EventCapture events = EventCapture.install()) {
            assertEquals(CLIENT, this.service().authenticateClient(RESOLVE, EndpointClientAuthentication.ASSERTION_TYPE, this.assertion(PF), PF));

            FederationEvent authenticated = events.only(FederationEvents.CLIENT_AUTHENTICATED);
            assertEquals(CLIENT, authenticated.subject());
            assertEquals(RESOLVE, authenticated.fields().get("endpoint"));
            assertFalse(authenticated.audit());
            events.assertNoJwtIn();
        }
    }

    @Test
    @Requirement("OIDFED §8.8(2)")
    void aClientThatDoesNotAuthenticateIsRefusedAndTheRefusalIsAudited() {
        try (EventCapture events = EventCapture.install()) {
            FederationException e = assertThrows(FederationException.class, () -> this.service().authenticateClient(FETCH,
                    EndpointClientAuthentication.ASSERTION_TYPE, this.assertion("https://someone-else.example.com"), PF));

            assertEquals(FederationError.INVALID_CLIENT, e.error());
            FederationEvent refused = events.only(FederationEvents.CLIENT_REFUSED);
            assertEquals("invalid", refused.reason());
            assertTrue(refused.audit());
            events.assertNoJwtIn();

            assertEquals(FederationError.INVALID_CLIENT, assertThrows(FederationException.class,
                    () -> this.service().authenticateClient(FETCH, null, this.assertion(PF), PF)).error(), "an assertion needs its type");
        }
    }

    @Test
    @Requirement("OIDFED §10.5(1)")
    void aClientWhoseFederationCannotBeReachedIsTemporarilyUnavailable() {
        this.federation.http().failing(CLIENT + "/.well-known/openid-federation", new IOException("timed out"));
        try (EventCapture events = EventCapture.install()) {
            FederationException e = assertThrows(FederationException.class, () -> this.service().authenticateClient(FETCH,
                    EndpointClientAuthentication.ASSERTION_TYPE, this.assertion(PF), PF));

            assertEquals(FederationError.TEMPORARILY_UNAVAILABLE, e.error());
            assertEquals("transport", events.only(FederationEvents.CLIENT_REFUSED).reason());
        }
    }

    @Test
    @Requirement("OIDFED §8.3.2(7)")
    void aResolveResponseIsAddressedToTheClientThatAuthenticatedAndToNobodyElse() throws Exception {
        FederationService service = this.pf(configuration(FederationConfiguration.ResolveDiscovery.ANY)).build();
        ResolveRequest request = new ResolveRequest(CLIENT, List.of(TA), List.of());

        assertEquals(List.of(CLIENT), JwtCodec.parseUnverifiedClaims(service.resolve(request, PF, CLIENT)).getAudience());
        assertNull(JwtCodec.parseUnverifiedClaims(service.resolve(request, PF)).getClaimValue("aud"), "unauthenticated, no aud");
    }

    @Test
    void clientAuthenticationNeedsAnchorsToKnowAClientBy() {
        FederationService.Builder anchorless = FederationService.builder(configuration(), Keys.signingKeys(PF_KEY))
                .endpointAuth(POLICY, (client, jti, ttl) -> true);
        IllegalStateException e = assertThrows(IllegalStateException.class, anchorless::build);
        assertTrue(e.getMessage().contains("§8.8"));
        FederationService.builder(configuration(), Keys.signingKeys(PF_KEY))
                .endpointAuth(EndpointAuthPolicy.none(), (client, jti, ttl) -> true).build();

        assertThrows(NullPointerException.class, () -> this.pf().endpointAuth(null, (client, jti, ttl) -> true));
        assertThrows(NullPointerException.class, () -> this.pf().endpointAuth(POLICY, null));
        assertEquals(EndpointAuthPolicy.none(), this.pf().build().endpointAuth());
        assertEquals(POLICY, this.service().endpointAuth());
    }
}
