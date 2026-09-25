package com.pingidentity.ps.oidf.keyhistory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The key history as the endpoint, the rotation check at start-up and the operator see it (OpenID Federation 1.0 §8.7). */
class KeyHistoryTest {
    private static final Map<String, Object> K1 = Keys.publicJwk(Keys.rsa("k1"));
    private static final Map<String, Object> K2 = Keys.publicJwk(Keys.rsa("k2"));

    private final MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));
    private EventCapture events;

    @BeforeEach
    void capture() {
        this.events = EventCapture.install();
        KeyHistorySupport.resetForTests();
    }

    @AfterEach
    void release() {
        this.events.close();
        KeyHistorySupport.resetForTests();
    }

    private KeyHistory history() {
        return new KeyHistory(new InMemoryKeyHistoryStore(), this.clock, Duration.ofDays(1));
    }

    @Test
    @Requirement({"OIDFED §8.7.2(5.6)", "OIDFED §8.7.2(5.6.3.4)", "OIDFED §8.7.2(5.6.3.6)"})
    void aRotationIsNoticedAndTheOldKeyPublishedWithWhenItWasUsedAndHowLongItStaysValid() throws Exception {
        KeyHistory history = this.history();
        assertEquals(Optional.empty(), history.observe(K1));
        Instant firstSeen = this.clock.instant();
        this.clock.advance(Duration.ofDays(30));

        HistoricalKey retired = history.observe(K2).orElseThrow();

        assertEquals("k1", retired.kid());
        Map<String, Object> published = history.keys().get(0);
        assertEquals("k1", published.get("kid"));
        assertEquals(K1.get("n"), published.get("n"));
        assertEquals(firstSeen.getEpochSecond(), published.get("iat"));
        assertEquals(this.clock.instant().plus(Duration.ofDays(1)).getEpochSecond(), published.get("exp"));
        assertFalse(published.containsKey("revoked"));
        assertEquals("k1", this.events.only(FederationEvents.KEY_RETIRED).fields().get("kid"));
        assertEquals("k2", this.events.only(FederationEvents.KEY_RETIRED).fields().get("new_kid"));
    }

    @Test
    @Requirement({"OIDFED §8.7.2(5.6.3.8)", "OIDFED §8.7.2(5.6.3.8.2.4)", "OIDFED §8.7.3(1)"})
    void aRevokedKeyIsPublishedWithWhenAndWhy() throws Exception {
        KeyHistory history = this.history();
        history.observe(K1);
        history.observe(K2);
        this.clock.advance(Duration.ofHours(1));

        history.revoke("k1", "compromised", "admin:1234abcd");

        Map<?, ?> revoked = (Map<?, ?>) history.keys().get(0).get("revoked");
        assertEquals(this.clock.epochSecond(), revoked.get("revoked_at"));
        assertEquals("compromised", revoked.get("reason"));
        assertEquals("admin:1234abcd", this.events.only(FederationEvents.KEY_REVOKED).fields().get("actor"));
        assertEquals(List.of("k1"), history.retired().stream().map(HistoricalKey::kid).toList());
    }

    @Test
    @Requirement("OIDFED §8.7.3(1)")
    void aReasonIsOneSection8Point7Point3DefinesOrNone() throws Exception {
        KeyHistory history = this.history();
        history.observe(K1);
        history.observe(K2);

        assertThrows(IllegalArgumentException.class, () -> history.revoke("k1", "lost-laptop", null));
        assertFalse(((Map<?, ?>) history.revoke("k1", null, null).asJwk().get("revoked")).containsKey("reason"), "the reason MAY be omitted");
    }

    @Test
    void aStoreThatFailsIsThisServersFault() {
        KeyHistoryStore failing = new KeyHistoryStore() {
            @Override
            public Optional<HistoricalKey> rotateTo(Map<String, Object> publicJwk, Instant now, Instant retiredUntil) {
                return Optional.empty();
            }

            @Override
            public HistoricalKey revoke(String kid, Instant revokedAt, String reason) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<HistoricalKey> retired() throws AuthorityRegistryException {
                throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "down");
            }
        };

        FederationException e = assertThrows(FederationException.class, () -> new KeyHistory(failing, this.clock, Duration.ZERO).keys());

        assertEquals(FederationError.SERVER_ERROR, e.error());
    }

    @Test
    void aHistoricalKeyIsWhatItSaysItIs() {
        assertThrows(IllegalArgumentException.class, () -> new HistoricalKey(" ", K1, null, Instant.EPOCH, null, null));
        assertThrows(IllegalArgumentException.class, () -> new HistoricalKey("k1", K1, null, Instant.EPOCH, null, "compromised"),
                "a reason without a revocation");
        assertFalse(new HistoricalKey("k1", K1, null, Instant.EPOCH, null, null).asJwk().containsKey("iat"), "iat only when known");
    }

    // ---- the process-wide store ----------------------------------------------------------------------------

    @Test
    void withNothingConfiguredTheHistoryIsKeptInMemoryAndSticksToIt() throws Exception {
        assertFalse(KeyHistorySupport.isConfigured());

        KeyHistoryStore first = KeyHistorySupport.store();
        KeyHistorySupport.configureJdbcStore(new JdbcDataSource());

        assertInstanceOf(InMemoryKeyHistoryStore.class, first);
        assertTrue(KeyHistorySupport.isConfigured());
        assertSame(first, KeyHistorySupport.store());
    }

    @Test
    void theSharedViewUsesWhicheverStoreIsConfigured() throws Exception {
        JdbcDataSource h2 = new JdbcDataSource();
        h2.setURL("jdbc:h2:mem:keyhistory-support-" + System.nanoTime() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
        h2.setUser("sa");
        try (InputStream in = KeyHistoryTest.class.getResourceAsStream("/db/migration/V103__federation_key_history.sql");
             Connection c = h2.getConnection(); Statement s = c.createStatement()) {
            s.execute(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        KeyHistoryStore shared = KeyHistorySupport.shared();
        KeyHistorySupport.configureJdbcStore(h2);

        shared.rotateTo(K1, this.clock.instant(), this.clock.instant());
        shared.rotateTo(K2, this.clock.instant(), this.clock.instant());

        assertInstanceOf(JdbcKeyHistoryStore.class, KeyHistorySupport.store());
        assertEquals("k1", shared.retired().get(0).kid());
        assertEquals("superseded", shared.revoke("k1", this.clock.instant(), "superseded").reason());
    }
}
