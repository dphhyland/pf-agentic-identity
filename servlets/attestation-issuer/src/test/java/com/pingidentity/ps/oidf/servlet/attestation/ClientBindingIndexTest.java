/*
 * The attester's client index (plan item H-ATT-2, F-0060): built once, rebuilt on a schedule, on a stale read, and
 * after a miss at most once in five seconds, whoever asks.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.issuer.AttesterClient;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

class ClientBindingIndexTest {

    private static final Duration INTERVAL = Duration.ofSeconds(30);

    /** A source whose clients the test sets, counting its reads, failing when told to. */
    private static final class Source implements ClientBindingIndex.Loader {
        List<AttesterClient> clients = List.of();
        RuntimeException fail;
        int reads;

        @Override
        public List<AttesterClient> load() {
            this.reads++;
            if (this.fail != null) {
                throw this.fail;
            }
            return this.clients;
        }
    }

    private static AttesterClient client(String id) throws IssuanceException {
        return new AttesterClient(id, AttestationIssuanceConfig.fromProperties(Map.of(
                AttestationIssuanceConfig.P_ISSUER, "https://attester.example.com",
                AttestationIssuanceConfig.P_BUNDLE_URL, "https://attester.example.com/jwks.json")));
    }

    @Test
    void theIndexIsBuiltOnceAndReadFromThen() throws Exception {
        IssuanceRequestPathTest.MovableClock clock = new IssuanceRequestPathTest.MovableClock();
        Source source = new Source();
        source.clients = List.of(client("a"));
        ClientBindingIndex index = new ClientBindingIndex(source, clock, INTERVAL);
        for (int i = 0; i < 100; i++) {
            assertEquals(1, index.clients().size());
            clock.advance(Duration.ofMillis(500));
        }
        assertEquals(1, source.reads, "a hundred requests over fifty seconds, one read of PingFederate's clients");
        assertEquals(1, index.rebuilds());
    }

    @Test
    void theScheduleRebuildsItAndAChangeIsSeenWithinOneInterval() throws Exception {
        IssuanceRequestPathTest.MovableClock clock = new IssuanceRequestPathTest.MovableClock();
        Source source = new Source();
        source.clients = List.of(client("a"));
        ClientBindingIndex index = new ClientBindingIndex(source, clock, INTERVAL);
        index.clients();
        source.clients = List.of(client("a"), client("b"));
        clock.advance(INTERVAL);
        assertEquals(1, index.clients().size(), "not yet: the schedule has not run");
        index.refresh();
        assertEquals(2, index.clients().size());
    }

    @Test
    void aReadThatFindsTheIndexOlderThanTwoIntervalsRebuildsIt() throws Exception {
        IssuanceRequestPathTest.MovableClock clock = new IssuanceRequestPathTest.MovableClock();
        Source source = new Source();
        ClientBindingIndex index = new ClientBindingIndex(source, clock, INTERVAL);
        index.clients();
        clock.advance(INTERVAL.multipliedBy(2));
        index.clients();
        assertEquals(2, source.reads, "a schedule that stopped is covered by the reads");
    }

    @Test
    void missesRebuildAtMostOnceInFiveSecondsWhoeverAsks() throws Exception {
        IssuanceRequestPathTest.MovableClock clock = new IssuanceRequestPathTest.MovableClock();
        Source source = new Source();
        ClientBindingIndex index = new ClientBindingIndex(source, clock, INTERVAL);
        index.clients();
        int refreshed = 0;
        for (int i = 0; i < 1000; i++) {
            if (index.refreshAfterMiss()) {
                refreshed++;
            }
            clock.advance(Duration.ofMillis(10));
        }
        assertEquals(2, refreshed, "a thousand misses over ten seconds rebuild it twice");
        assertEquals(3, source.reads);
    }

    @Test
    void aFailedRebuildKeepsTheIndexItHadUntilTheNextAttempt() throws Exception {
        IssuanceRequestPathTest.MovableClock clock = new IssuanceRequestPathTest.MovableClock();
        Source source = new Source();
        source.clients = List.of(client("a"));
        ClientBindingIndex index = new ClientBindingIndex(source, clock, INTERVAL);
        index.clients();
        source.fail = new IllegalStateException("the client manager is not ready");
        index.refresh();
        clock.advance(INTERVAL.multipliedBy(2));
        assertEquals(1, index.clients().size(), "the stale read rebuilds, fails, and keeps what it had");
        int reads = source.reads;
        assertEquals(1, index.clients().size());
        assertEquals(reads, source.reads, "and is not retried by every request");
    }

    @Test
    void withNoIndexYetAFailureIsTheReadsAndAMissRefreshSaysNo() throws Exception {
        IssuanceRequestPathTest.MovableClock clock = new IssuanceRequestPathTest.MovableClock();
        Source source = new Source();
        source.fail = new IllegalStateException("the client manager is not ready");
        ClientBindingIndex index = new ClientBindingIndex(source, clock, INTERVAL);
        IssuanceException e = assertThrows(IssuanceException.class, index::clients);
        assertEquals("server_error", e.error());
        assertFalse(index.refreshAfterMiss(), "nothing could be read");
        index.refresh();
        assertEquals(0, index.rebuilds());

        ClientBindingIndex typed = new ClientBindingIndex(() -> {
            throw IssuanceException.invalidClient("no store");
        }, clock, INTERVAL);
        assertEquals("invalid_client", assertThrows(IssuanceException.class, typed::clients).error());
    }

    @Test
    void theResolverReadsItsIndexNotTheStoreEachTime() throws Exception {
        ClientStore store = mock(ClientStore.class);
        Client c = new Client();
        c.setClientId("https://rp.example.com/agent-1");
        c.setEnabled(true);
        Map<String, ParamValues> extended = new HashMap<>();
        for (Map.Entry<String, String> e : Map.of(AttestationIssuanceConfig.P_ISSUER, "https://attester.example.com",
                AttestationIssuanceConfig.P_BUNDLE_URL, "https://attester.example.com/jwks.json").entrySet()) {
            ParamValues values = new ParamValues();
            values.setElements(List.of(e.getValue()));
            extended.put(e.getKey(), values);
        }
        c.setExtendedParams(extended);
        List<Client> all = new ArrayList<>(List.of(c));
        all.add(null);
        when(store.getAll()).thenReturn(all);
        IssuanceRequestPathTest.MovableClock clock = new IssuanceRequestPathTest.MovableClock();
        PfIssuanceClientResolver resolver = new PfIssuanceClientResolver(store, clock, INTERVAL);
        for (int i = 0; i < 10; i++) {
            assertEquals(1, resolver.attestationClients().size());
        }
        verify(store, times(1)).getAll();
        assertTrue(resolver.refreshAfterMiss());
        assertFalse(resolver.refreshAfterMiss(), "within five seconds of the last");
        verify(store, times(2)).getAll();
    }

    @Test
    void resolversOverPingFederatesStoreShareOneIndex() {
        PfIssuanceClientResolver a = new PfIssuanceClientResolver(new PfMgmtClientStore());
        PfIssuanceClientResolver b = new PfIssuanceClientResolver(new PfMgmtClientStore());
        assertSame(a.index(), b.index());
        PfIssuanceClientResolver own = new PfIssuanceClientResolver(mock(ClientStore.class));
        assertFalse(own.index() == a.index());
    }
}
