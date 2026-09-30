package com.pingidentity.ps.oidf.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.jose.CompactJws;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import com.pingidentity.ps.oidf.trustmark.InMemoryTrustMarkRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.jwk.JsonWebKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * H-FED-9: a hosted entity's signed configuration is kept until it is due for renewal, and dropped the moment anything
 * about the entity - or the Trust Marks it holds - changes.
 */
class HostedEntityConfigurationCacheTest {
    private static final String AUTHORITY = "https://as.example.com";
    private static final String ID = AUTHORITY + "/agents/a1";

    private final AtomicInteger signatures = new AtomicInteger();
    private final LocalJwkSigner key = new LocalJwkSigner(Keys.ec("hosting-1").toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
    private final HostedEntitySigner signer = entity -> {
        this.signatures.incrementAndGet();
        return this.key;
    };

    @AfterEach
    void forget() {
        HostedEntityConfigurationCache.shared().clear();
    }

    private static HostedEntity entity() {
        return HostedEntity.hosted(ID, "k1", Map.of("oauth_client", Map.of("client_name", "agent")), null);
    }

    @Test
    void aConfigurationIsSignedOnceAndServedUntilAQuarterOfItsLifetimeHasPassed() {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));
        HostedEntityConfigurationCache cache = new HostedEntityConfigurationCache(clock, 8);
        HostedEntity entity = entity();
        Instant iat = clock.instant();

        cache.put(entity, "jwt-1", iat, iat.plusSeconds(3600));
        assertEquals("jwt-1", cache.get(entity));
        clock.advance(Duration.ofSeconds(899));
        assertEquals("jwt-1", cache.get(entity), "more than three quarters of its hour left");
        clock.advance(Duration.ofSeconds(1));
        assertNull(cache.get(entity), "fifteen minutes on, it is signed afresh");
        assertEquals(0, cache.size());
    }

    @Test
    void aConfigurationIsKeptOnlyForTheRecordItWasBuiltFrom() {
        HostedEntityConfigurationCache cache = new HostedEntityConfigurationCache(new MutableClock(Instant.ofEpochSecond(1_800_000_000L)), 8);
        HostedEntity entity = entity();
        cache.put(entity, "jwt-1", Instant.ofEpochSecond(1_800_000_000L), Instant.ofEpochSecond(1_800_003_600L));

        assertNull(cache.get(entity.withStatus(EntityStatus.SUSPENDED)), "a record changed elsewhere is built afresh");
        assertNull(cache.get(entity), "and the old one is dropped");
    }

    @Test
    void theLeastRecentlyServedIsDroppedFirstAndEitherSpellingInvalidates() {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));
        HostedEntityConfigurationCache cache = new HostedEntityConfigurationCache(clock, 2);
        HostedEntity a = HostedEntity.hosted(AUTHORITY + "/agents/a", "k", Map.of(), null);
        HostedEntity b = HostedEntity.hosted(AUTHORITY + "/agents/b", "k", Map.of(), null);
        HostedEntity c = HostedEntity.hosted(AUTHORITY + "/agents/c", "k", Map.of(), null);
        Instant iat = clock.instant();
        cache.put(a, "a", iat, iat.plusSeconds(3600));
        cache.put(b, "b", iat, iat.plusSeconds(3600));
        cache.get(a);
        cache.put(c, "c", iat, iat.plusSeconds(3600));

        assertNull(cache.get(b));
        assertEquals("a", cache.get(a));
        cache.invalidate(AUTHORITY + "/agents/a/");
        cache.invalidate(null);
        assertNull(cache.get(a));
        assertEquals(1, cache.size());
        assertThrows(IllegalArgumentException.class, () -> new HostedEntityConfigurationCache(clock, 0));
    }

    @Test
    void theBuilderSignsOnceUntilTheRegistryChangesTheEntity() throws Exception {
        HostedEntityConfigurationBuilder builder = new HostedEntityConfigurationBuilder(this.signer, AUTHORITY, id -> List.of(),
                HostedEntityConfigurationCache.shared());
        InMemoryHostedEntityRegistry registry = new InMemoryHostedEntityRegistry();
        registry.register(entity());

        String first = builder.buildEntityConfiguration(registry.find(ID).orElseThrow());
        assertEquals(first, builder.buildEntityConfiguration(registry.find(ID).orElseThrow()));
        assertEquals(1, this.signatures.get(), "one signature for two requests");

        registry.rotateHostingKey(ID, "k2", "admin:1");
        builder.buildEntityConfiguration(registry.find(ID).orElseThrow());
        assertEquals(2, this.signatures.get(), "a key change signs afresh");

        HostedEntity current = registry.find(ID).orElseThrow();
        builder.buildEntityConfiguration(current);
        HostedEntityConfigurationCache.changed(ID);
        builder.buildEntityConfiguration(current);
        assertEquals(3, this.signatures.get(), "a change the registry reports drops the kept one, same record or not");

        registry.setStatus(ID, EntityStatus.SUSPENDED, "review", "admin:2");
        assertEquals(0, HostedEntityConfigurationCache.shared().size(), "a status change drops it at once");
    }

    @Test
    void aTrustMarkGrantedOrRevokedDropsTheConfigurationThatCarriesTheMarks() throws Exception {
        HostedEntityConfigurationBuilder builder = new HostedEntityConfigurationBuilder(this.signer, AUTHORITY, id -> List.of(),
                HostedEntityConfigurationCache.shared());
        InMemoryTrustMarkRegistry marks = new InMemoryTrustMarkRegistry(new MutableClock(Instant.ofEpochSecond(1_800_000_000L)));
        HostedEntity entity = entity();

        builder.buildEntityConfiguration(entity);
        marks.grant("https://as.example.com/marks/certified", ID + "/", null, null);
        builder.buildEntityConfiguration(entity);
        marks.revoke("https://as.example.com/marks/certified", ID + "/", "lapsed", null);
        builder.buildEntityConfiguration(entity);

        assertEquals(3, this.signatures.get());
    }

    @Test
    void aConfigurationIsRenewedBeforeATrustMarkItCarriesExpires() {
        MutableClock clock = new MutableClock(Instant.now());
        long markExp = clock.instant().getEpochSecond() + 300;
        String mark = CompactJws.sign(Map.of("alg", this.key.algorithm(), "typ", "trust-mark+jwt"),
                Map.of("iss", AUTHORITY, "sub", ID, "trust_mark_type", AUTHORITY + "/marks/short", "exp", markExp), this.key);
        HostedEntityConfigurationBuilder builder = new HostedEntityConfigurationBuilder(this.signer, AUTHORITY,
                id -> List.of(Map.of("trust_mark_type", AUTHORITY + "/marks/short", "trust_mark", mark)),
                new HostedEntityConfigurationCache(clock, 8));
        HostedEntity entity = entity();

        String first = builder.buildEntityConfiguration(entity);
        clock.advance(Duration.ofSeconds(60));
        assertEquals(first, builder.buildEntityConfiguration(entity), "three quarters of the mark's five minutes left");
        assertEquals(1, this.signatures.get());
        clock.advance(Duration.ofSeconds(20));
        builder.buildEntityConfiguration(entity);
        assertEquals(2, this.signatures.get(), "a quarter of the mark's lifetime gone, not the configuration's, signs afresh");
    }

    @Test
    void theFreshnessOfAConfigurationEndsWithItsFirstTrustMarkAndAnUnreadableMarkIsNotKept() {
        String mark = CompactJws.sign(Map.of("alg", this.key.algorithm()), Map.of("exp", 1_800_000_300L), this.key);

        assertEquals(1_800_003_600L, HostedEntityConfigurationBuilder.earliestExpiry(List.of(), 1_800_003_600L, 1_800_000_000L));
        assertEquals(1_800_000_300L, HostedEntityConfigurationBuilder.earliestExpiry(
                List.of(Map.of("trust_mark", mark)), 1_800_003_600L, 1_800_000_000L));
        assertEquals(1_800_000_000L, HostedEntityConfigurationBuilder.earliestExpiry(
                List.of(Map.of("trust_mark", mark), Map.of("trust_mark", "not-a-jwt")), 1_800_003_600L, 1_800_000_000L));

        MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));
        HostedEntityConfigurationCache cache = new HostedEntityConfigurationCache(clock, 8);
        cache.put(entity(), "jwt-1", clock.instant(), clock.instant().minusSeconds(1));
        assertNull(cache.get(entity()), "a configuration whose mark has already expired is never served from here");
    }

    @Test
    void withoutACacheEveryConfigurationIsSigned() {
        HostedEntityConfigurationBuilder builder = new HostedEntityConfigurationBuilder(this.signer, AUTHORITY);
        HostedEntity entity = entity();

        assertNotEquals(null, builder.buildEntityConfiguration(entity));
        builder.buildEntityConfiguration(entity);
        assertEquals(2, this.signatures.get());
    }
}
