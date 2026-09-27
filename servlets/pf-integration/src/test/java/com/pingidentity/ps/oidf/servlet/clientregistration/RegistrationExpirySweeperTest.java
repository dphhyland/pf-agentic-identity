package com.pingidentity.ps.oidf.servlet.clientregistration;

import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.federationClient;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.param;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.PfTracking;
import com.pingidentity.ps.oidf.pf.testkit.FakeClientStore;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;

/**
 * The sweeper disables each federation client whose recorded registration expiry has passed, so PingFederate
 * shows what §12.3 already refuses at the token endpoint - and leaves everything else alone.
 */
class RegistrationExpirySweeperTest {

    private final MutableClock clock = MutableClock.startingNow();
    private final FakeClientStore store = new FakeClientStore();
    private final RegistrationExpirySweeper sweeper =
            new RegistrationExpirySweeper(this.store, new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock));
    private EventCapture events;

    @BeforeEach
    void setUp() {
        this.events = EventCapture.install();
        System.clearProperty(RegistrationExpirySweeper.OWNER_PROPERTY);
    }

    @AfterEach
    void tearDown() {
        this.sweeper.stop();
        this.events.close();
        System.clearProperty(RegistrationExpirySweeper.OWNER_PROPERTY);
    }

    private long in(long seconds) {
        return this.clock.epochSecond() + seconds;
    }

    @Test
    @Requirement({"OIDFED §12.3(1)", "OIDFED §12.2.2(2.7)"})
    void anExpiredRegistrationIsDisabledNotDeleted() {
        this.store.with(federationClient("https://agent.example/1", "auto_registered", this.in(-1), null));
        this.store.with(federationClient("https://rp.example", "registered", this.in(-60), null));

        List<String> disabled = this.sweeper.sweepOnce();

        assertEquals(List.of("https://agent.example/1", "https://rp.example"), disabled);
        for (Client client : this.store.getAll()) {
            assertFalse(client.isEnabled(), client.getClientId());
            assertEquals(Long.toString(this.clock.epochSecond()), param(client, FederationClientParams.DISABLED_AT),
                    "marked, so a renewal knows the disable was expiry's");
        }
        assertEquals(2, this.events.withCode(FederationEvents.REGISTRATION_DISABLED).size());
        assertTrue(this.events.withCode(FederationEvents.REGISTRATION_DISABLED).get(0).audit());
    }

    @Test
    void everythingElseIsLeftAlone() {
        this.store.with(federationClient("https://current.example", "auto_registered", this.in(60), null));
        this.store.with(federationClient("https://legacy.example", "auto_registered", null, null));
        this.store.with(federationClient("https://console.example", null, this.in(-60), null));
        Client alreadyOff = federationClient("https://off.example", "registered", this.in(-60), null);
        alreadyOff.setEnabled(false);
        this.store.with(alreadyOff);
        Client plain = new Client();
        plain.setClientId("https://plain.example");
        this.store.with(plain);

        assertEquals(List.of(), this.sweeper.sweepOnce());
        assertEquals(List.of(), this.store.writes());
        assertEquals(List.of(), this.events.events());
    }

    @Test
    void onlyOneSweeperRunsInAJvm() {
        assertTrue(this.sweeper.startOnce(3600));
        assertNotNull(System.getProperty(RegistrationExpirySweeper.OWNER_PROPERTY));
        assertFalse(new RegistrationExpirySweeper(this.store, new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock))
                .startOnce(3600), "a second filter instance, or the other classloader's, finds it running");
    }

    @Test
    void theSweepRunsOnANamedManagedExecutorFirstAfterOneInterval() throws Exception {
        this.store.with(federationClient("https://agent.example/1", "auto_registered", this.in(-1), null));
        long started = System.nanoTime();
        assertTrue(this.sweeper.startOnce(1));
        ManagedExecutor executor = ManagedExecutors.live(RegistrationExpirySweeper.EXECUTOR_NAME).orElseThrow();
        assertEquals("oidf-registration-sweeper", executor.threadNamePrefix());
        assertEquals(0, executor.runs(), "nothing at start: the first pass is one interval away, as the old thread slept first");
        awaitRuns(executor, 1);
        assertTrue(System.nanoTime() - started >= 1_000_000_000L);
        assertFalse(this.store.getAll().iterator().next().isEnabled(), "and that pass disabled the expired client");
    }

    @Test
    void aPassThatFailsIsLoggedAndTheNextIntervalTriesAgain() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        ClientStore failingOnce = new ClientStore() {
            @Override public void add(Client client) { store.add(client); }
            @Override public void update(Client client) { store.update(client); }
            @Override public void disable(Client client) { store.disable(client); }
            @Override public Client get(String clientId) { return store.get(clientId); }
            @Override public Collection<Client> getAll() {
                if (calls.incrementAndGet() == 1) {
                    throw new IllegalStateException("the client store is down");
                }
                return store.getAll();
            }
        };
        RegistrationExpirySweeper flaky = new RegistrationExpirySweeper(failingOnce,
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock));
        try {
            assertTrue(flaky.startOnce(1));
            ManagedExecutor executor = ManagedExecutors.live(RegistrationExpirySweeper.EXECUTOR_NAME).orElseThrow();
            awaitRuns(executor, 2);
            assertEquals(0, executor.failures(), "the sweep's own catch logs it; nothing escapes to the executor");
            assertTrue(calls.get() >= 2, "tried again the next interval");
        } finally {
            flaky.stop();
        }
    }

    @Test
    void stopEndsTheSweepAndGivesTheOwnerBack() {
        assertTrue(this.sweeper.startOnce(3600));
        ManagedExecutor executor = ManagedExecutors.live(RegistrationExpirySweeper.EXECUTOR_NAME).orElseThrow();
        this.sweeper.stop();
        assertTrue(executor.isClosed());
        assertNull(System.getProperty(RegistrationExpirySweeper.OWNER_PROPERTY), "so a redeployed filter can start one");
        assertEquals(java.util.Optional.empty(), ManagedExecutors.live(RegistrationExpirySweeper.EXECUTOR_NAME));
        RegistrationExpirySweeper next = new RegistrationExpirySweeper(this.store,
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock));
        try {
            assertTrue(next.startOnce(3600), "the next one starts");
        } finally {
            next.stop();
        }
        new RegistrationExpirySweeper(this.store, new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock)).stop();
    }

    @Test
    void whenTheExecutorIsHeldElsewhereNothingStartsAndTheOwnerIsGivenBack() {
        String claim = "oidf.exec.owner." + RegistrationExpirySweeper.EXECUTOR_NAME;
        System.setProperty(claim, "another-copy");
        try {
            assertFalse(this.sweeper.startOnce(3600));
            assertNull(System.getProperty(RegistrationExpirySweeper.OWNER_PROPERTY));
        } finally {
            System.clearProperty(claim);
        }
    }

    private static void awaitRuns(ManagedExecutor executor, long runs) throws InterruptedException {
        long deadline = System.nanoTime() + 20_000_000_000L;
        while (executor.runs() < runs) {
            assertTrue(System.nanoTime() < deadline, "timed out waiting for " + runs + " run(s)");
            Thread.sleep(20);
        }
    }

    @Test
    void whileExpiriesAreOnlyLoggedNothingIsDisabledAndNoSweeperStarts() {
        RegistrationExpirySweeper logging = new RegistrationExpirySweeper(this.store, new RegistrationLifetime(
                new RegistrationSettings(86_400L, 60L, 300L, ExpiryEnforcement.LOG, 300L, true), this.clock));
        this.store.with(federationClient("https://agent.example/1", "auto_registered", this.in(-1), null));

        assertEquals(List.of(), logging.sweepOnce(), "log records expiries and enforces none, here included");
        assertTrue(this.store.getAll().iterator().next().isEnabled());
        assertFalse(logging.startOnce(3600));
        assertNull(System.getProperty(RegistrationExpirySweeper.OWNER_PROPERTY));
    }

    @Test
    void eachPassLogsUnderATrackingIdOfItsOwn() {
        AtomicReference<String> seen = new AtomicReference<>();
        FederationEvents.reset();
        FederationEvents.configure(event -> seen.set(PfTracking.trackingId()));
        this.store.with(federationClient("https://agent.example/1", "auto_registered", this.in(-1), null));

        this.sweeper.pass().run();

        assertTrue(seen.get().startsWith("oidf-sweep-"), seen.get());
        assertNull(PfTracking.trackingId(), "and gives it back");
    }

    @Test
    void anIntervalOfZeroTurnsItOff() {
        assertFalse(this.sweeper.startOnce(0));
        assertEquals(null, System.getProperty(RegistrationExpirySweeper.OWNER_PROPERTY));
    }
}
