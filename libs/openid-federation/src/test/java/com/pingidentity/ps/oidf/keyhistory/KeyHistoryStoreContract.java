package com.pingidentity.ps.oidf.keyhistory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** What every {@link KeyHistoryStore} does, whatever keeps the history. */
abstract class KeyHistoryStoreContract {
    static final Map<String, Object> K1 = Keys.publicJwk(Keys.rsa("k1"));
    static final Map<String, Object> K2 = Keys.publicJwk(Keys.rsa("k2"));
    static final Map<String, Object> K3 = Keys.publicJwk(Keys.rsa("k3"));
    static final Instant T0 = Instant.ofEpochSecond(1_800_000_000L);
    static final Instant T1 = T0.plusSeconds(3600);
    static final Instant T2 = T0.plusSeconds(7200);

    protected abstract KeyHistoryStore newStore() throws Exception;

    @Test
    void theFirstKeySeenRetiresNothingAndSeeingItAgainChangesNothing() throws Exception {
        KeyHistoryStore store = this.newStore();

        assertEquals(Optional.empty(), store.rotateTo(K1, T0, T0.plusSeconds(86_400)));
        assertEquals(Optional.empty(), store.rotateTo(K1, T1, T1.plusSeconds(86_400)));
        assertEquals(List.of(), store.retired());
    }

    @Test
    @Requirement("OIDFED §8.7(1)")
    void anotherKeyRetiresTheOneBeforeUntilTheGraceIsOver() throws Exception {
        KeyHistoryStore store = this.newStore();
        store.rotateTo(K1, T0, T0.plusSeconds(86_400));

        HistoricalKey retired = store.rotateTo(K2, T1, T1.plusSeconds(86_400)).orElseThrow();

        assertEquals("k1", retired.kid());
        assertEquals(K1.get("n"), retired.publicJwk().get("n"));
        assertEquals(T0, retired.issuedAt(), "it was in use from when it was first seen");
        assertEquals(T1.plusSeconds(86_400), retired.expiresAt());
        assertNull(retired.revokedAt());
        assertEquals(List.of(retired), store.retired());

        store.rotateTo(K3, T2, T2.plusSeconds(86_400));
        assertEquals(List.of("k1", "k2"), store.retired().stream().map(HistoricalKey::kid).toList(), "oldest first");
    }

    @Test
    @Requirement({"OIDFED §8.7(2)", "OIDFED §8.7.2(5.6.3.8)"})
    void aRetiredKeyCanBeRevokedEvenAfterItExpiredAndStaysRevoked() throws Exception {
        KeyHistoryStore store = this.newStore();
        store.rotateTo(K1, T0, T0.plusSeconds(60));
        store.rotateTo(K2, T1, T1.plusSeconds(60));

        HistoricalKey revoked = store.revoke("k1", T2, "compromised");

        assertEquals(T2, revoked.revokedAt());
        assertEquals("compromised", revoked.reason());
        assertEquals(revoked, store.revoke("k1", T2.plusSeconds(1), "superseded"), "revoking again changes nothing");
        assertEquals(revoked, store.retired().get(0));
    }

    @Test
    void onlyARetiredKeyCanBeRevoked() throws Exception {
        KeyHistoryStore store = this.newStore();
        store.rotateTo(K1, T0, T0);

        AuthorityRegistryException e = assertThrows(AuthorityRegistryException.class, () -> store.revoke("k1", T1, null));

        assertEquals(AuthorityRegistryException.NOT_FOUND, e.reason(), "the key in use is not history; rotate first");
    }

    @Test
    void aRetiredKeyThatSignsAgainIsNoLongerHistory() throws Exception {
        KeyHistoryStore store = this.newStore();
        store.rotateTo(K1, T0, T0.plusSeconds(60));
        store.rotateTo(K2, T1, T1.plusSeconds(60));

        HistoricalKey retired = store.rotateTo(K1, T2, T2.plusSeconds(60)).orElseThrow();

        assertEquals("k2", retired.kid());
        assertEquals(List.of("k2"), store.retired().stream().map(HistoricalKey::kid).toList());
    }

    /** A key revoked as compromised must never sign again: the deployment is refused, not quietly allowed. */
    @Test
    void aRevokedKeyMustNeverSignAgain() throws Exception {
        KeyHistoryStore store = this.newStore();
        store.rotateTo(K1, T0, T0.plusSeconds(60));
        store.rotateTo(K2, T1, T1.plusSeconds(60));
        store.revoke("k1", T1, "compromised");

        AuthorityRegistryException e = assertThrows(AuthorityRegistryException.class, () -> store.rotateTo(K1, T2, T2.plusSeconds(60)));

        assertEquals(AuthorityRegistryException.STALE_UPDATE, e.reason());
        assertTrue(store.rotateTo(K2, T2, T2).isEmpty(), "and the key in use is still the one it was");
    }
}
