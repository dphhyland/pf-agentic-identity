package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/** The historical keys endpoint (OpenID Federation 1.0 §8.7): what it answers, and that it is advertised only when on. */
class FederationServiceHistoricalKeysTest {
    private static final String PF = "https://pf.example";
    private static final PublicJsonWebKey PF_KEY = Keys.rsa("pf-2");
    private static final Map<String, Object> RETIRED = Map.of("kty", "RSA", "kid", "pf-1", "n", "abc", "e", "AQAB", "exp", 1_800_086_400L);

    private final MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));

    private FederationService pf(HistoricalKeys keys) {
        FederationConfiguration configuration = new FederationConfiguration(List.of(PF), List.of(), null, false, false, null, null, null, 0, "RS256",
                AttestationMetadataConfig.defaults(), null, null, FederationConfiguration.DEFAULT_CLIENT_REGISTRATION_TYPES,
                FederationConfiguration.ResolveDiscovery.KNOWN);
        return FederationService.builder(configuration, Keys.signingKeys(PF_KEY)).historicalKeys(keys).clock(this.clock).build();
    }

    @Test
    @Requirement({"OIDFED §8.7.2(1)", "OIDFED §8.7.2(2)", "OIDFED §8.7.2(3)", "OIDFED §8.7.2(5.2)", "OIDFED §8.7.2(5.4)", "OIDFED §8.7.2(5.6)"})
    void theHistoricalKeysAreASignedJwkSetOfTheKeysThisEntitySignedWithBefore() throws Exception {
        String jwt = this.pf(() -> List.of(RETIRED)).historicalKeys(PF);

        assertEquals("jwk-set+jwt", JwtCodec.getJwtHeaders(jwt).get("typ"));
        assertEquals("pf-2", JwtCodec.getJwtHeaders(jwt).get("kid"), "signed with the key in use");
        JwtClaims claims = JwtCodec.verifySignature(jwt, List.of(PF_KEY), Set.of());
        assertEquals(PF, claims.getIssuer());
        assertEquals(this.clock.epochSecond(), claims.getIssuedAt().getValue());
        assertEquals(List.of(RETIRED), claims.getClaimValue("keys"));
    }

    @Test
    @Requirement("OIDFED §5.1.1(3.14)")
    void theEndpointIsAdvertisedOnlyWhenThisEntityPublishesItsHistory() throws Exception {
        Map<?, ?> with = federationEntity(this.pf(List::of));
        Map<?, ?> without = federationEntity(this.pf(null));

        assertEquals(PF + "/federation/historical_keys", with.get("federation_historical_keys_endpoint"));
        assertFalse(without.containsKey("federation_historical_keys_endpoint"));
        assertEquals(FederationError.NOT_FOUND, assertThrows(FederationException.class, () -> this.pf(null).historicalKeys(PF)).error());
        assertEquals(List.of(), JwtCodec.parseUnverifiedClaims(this.pf(List::of).historicalKeys(PF)).getClaimValue("keys"),
                "before the first rotation there is no history, only an empty list");
    }

    /** What a rotation is noticed by: the key the configuration publishes, and signs with. */
    @Test
    void theKeyInUseIsTheOneTheConfigurationPublishes() throws Exception {
        FederationService service = this.pf(null);

        Map<String, Object> inUse = service.signingKey();

        assertEquals("pf-2", inUse.get("kid"));
        assertEquals(List.of(inUse), ((Map<?, ?>) JwtCodec.parseUnverifiedClaims(service.createEntityConfigurationJwt(PF)).getClaimValue("jwks"))
                .get("keys"));
    }

    private static Map<?, ?> federationEntity(FederationService service) throws Exception {
        return (Map<?, ?>) ((Map<?, ?>) JwtCodec.parseUnverifiedClaims(service.createEntityConfigurationJwt(PF)).getClaimValue("metadata"))
                .get("federation_entity");
    }
}
