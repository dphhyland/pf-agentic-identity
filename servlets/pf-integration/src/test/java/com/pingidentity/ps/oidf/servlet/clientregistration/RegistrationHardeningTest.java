package com.pingidentity.ps.oidf.servlet.clientregistration;

import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.ANCHOR;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.result;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.ResolutionBudget;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException;
import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidationRequest;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import com.pingidentity.ps.oidf.pf.testkit.FakeClientStore;
import com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationService.Admission;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Explicit registration (OpenID Federation 1.0 §12.2) bounded as automatic registration is (plan item S5c): the
 * coordinator's per-client lock and pool, a failure memory keyed on the whole presented chain, and a budget on every
 * validation. The validator is mocked here: what is counted is how often a request makes it resolve.
 */
class RegistrationHardeningTest {

    private static final String RP = "https://rp.example.com";
    private static final String OTHER = "https://other.example.com";
    private static final String OP = "https://op.example.com";

    private final MutableClock clock = MutableClock.startingNow();
    private final TrustChainValidator validator = mock(TrustChainValidator.class);
    private final FakeClientStore store = new FakeClientStore();
    private final List<String> chain = RegistrationFixtures.chain(RP, ANCHOR, this.clock);
    private final ExecutorService pool = Executors.newFixedThreadPool(2);
    private EventCapture events;

    @BeforeEach
    void setUp() {
        this.events = EventCapture.install();
    }

    @AfterEach
    void tearDown() {
        this.events.close();
        this.pool.shutdownNow();
    }

    private RegistrationService service(RegistrationCoordinator coordinator) throws Exception {
        return new RegistrationService(new RegistrationConfiguration(ANCHOR, false), this.validator, this.store, RegistrationFixtures.signer(),
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((url, accept) -> {
                    throw new java.io.IOException("no fetch expected: " + url);
                }, this.clock), coordinator);
    }

    private RegistrationService service() throws Exception {
        return this.service(new RegistrationCoordinator(8, 0L));
    }

    private static ExplicitRegistrationRequest post(String clientId, List<String> chain) {
        return new ExplicitRegistrationRequest(clientId, clientId, chain, Map.of());
    }

    private static Map<String, Object> rp() {
        return Map.of("openid_relying_party", Map.of("client_registration_types", List.of("explicit"), "redirect_uris", List.of(RP + "/cb")));
    }

    private TrustChainValidationResult resolved(String subject) throws Exception {
        return result(subject, RegistrationFixtures.chain(subject, ANCHOR, this.clock), rp(), Set.of("openid_relying_party"), -1L);
    }

    private static TrustChainValidationException untrusted() {
        return new TrustChainValidationException(TrustChainValidationException.Kind.SIGNATURE, null, null, "signature does not verify");
    }

    private static TrustChainValidationException unreachable() {
        return new TrustChainValidationException(TrustChainValidationException.Kind.TRANSPORT, null, null, "superior unreachable");
    }

    /** The same chain with its last statement changed: everything after the first statement differs. */
    private List<String> variedAfterTheFirst() {
        List<String> varied = new ArrayList<>(this.chain);
        varied.set(varied.size() - 1, varied.get(varied.size() - 1) + "x");
        return varied;
    }

    // ---- the coordinator ---------------------------------------------------------------------------------------

    /** Starts an explicit registration of {@code clientId} whose validation holds until {@code release} opens. */
    private Future<RegisteredClient> held(RegistrationService service, String clientId, CountDownLatch started, CountDownLatch release)
            throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenAnswer(call -> {
            started.countDown();
            release.await(5, TimeUnit.SECONDS);
            return this.resolved(clientId);
        });
        return this.pool.submit(() -> service.explicitRegister(post(clientId, RegistrationFixtures.chain(clientId, ANCHOR, this.clock)), OP));
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aSecondExplicitRegistrationOfTheSameClientWaitsThenIsTurnedAwayBusy() throws Exception {
        RegistrationService service = this.service(new RegistrationCoordinator(8, 50L));
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<RegisteredClient> first = this.held(service, RP, started, release);
        assertTrue(started.await(5, TimeUnit.SECONDS));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service.explicitRegister(post(RP, this.chain), OP));

        assertEquals(503, e.status());
        assertEquals("temporarily_unavailable", e.error());
        assertEquals(RegistrationRejectedException.Kind.BUSY, e.kind());
        assertTrue(e.getMessage().contains("in progress"), e.getMessage());
        release.countDown();
        assertNotNull(first.get(5, TimeUnit.SECONDS).signedJwt());
        verify(this.validator, times(1)).validate(any(ValidationRequest.class));
    }

    @Test
    void aSecondExplicitRegistrationOfTheSameClientThatWaitsLongEnoughRegistersAfterTheFirst() throws Exception {
        RegistrationService service = this.service(new RegistrationCoordinator(8, 5_000L));
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<RegisteredClient> first = this.held(service, RP, started, release);
        assertTrue(started.await(5, TimeUnit.SECONDS));

        Future<RegisteredClient> second = Executors.newSingleThreadExecutor().submit(() -> service.explicitRegister(post(RP, this.chain), OP));
        release.countDown();

        assertNotNull(first.get(5, TimeUnit.SECONDS));
        assertNotNull(second.get(5, TimeUnit.SECONDS), "it waited for the lock, then registered: a repeat request replaces the registration");
        verify(this.validator, times(2)).validate(any(ValidationRequest.class));
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void explicitRegistrationIsTurnedAwayWhenThePoolIsFull() throws Exception {
        RegistrationService service = this.service(new RegistrationCoordinator(1, 0L));
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<RegisteredClient> first = this.held(service, OTHER, started, release);
        assertTrue(started.await(5, TimeUnit.SECONDS));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> service.explicitRegister(post(RP, this.chain), OP));

        assertEquals(RegistrationRejectedException.Kind.BUSY, e.kind());
        assertTrue(e.getMessage().contains("too many"), e.getMessage());
        release.countDown();
        first.get(5, TimeUnit.SECONDS);
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void theExplicitValidationSpendsTheCoordinatorsBudget() throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenReturn(this.resolved(RP));
        ValidatorOptions resolution = ValidatorOptions.defaults().withMaxFetches(7).withResolutionWallClock(Duration.ofSeconds(9));

        this.service(new RegistrationCoordinator(8, 0L, resolution, Duration.ofSeconds(25), System::nanoTime))
                .explicitRegister(post(RP, this.chain), OP);

        ArgumentCaptor<ValidationRequest> asked = ArgumentCaptor.forClass(ValidationRequest.class);
        verify(this.validator).validate(asked.capture());
        ResolutionBudget budget = asked.getValue().budget();
        assertNotNull(budget, "a budget of the registration's, not the validator's default");
        assertEquals(7, budget.requests());
        assertEquals(Duration.ofSeconds(9), budget.wallClock());
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void theAutomaticValidationSpendsTheCoordinatorsBudget() throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenReturn(
                result(RP, this.chain, Map.of("oauth_client", RegistrationFixtures.agentMetadata("automatic")), Set.of("oauth_client"), -1L));
        ValidatorOptions resolution = ValidatorOptions.defaults().withMaxFetches(5).withResolutionWallClock(Duration.ofSeconds(3));

        assertEquals(Admission.REGISTERED, this.service(new RegistrationCoordinator(8, 0L, resolution, Duration.ofSeconds(25), System::nanoTime))
                .admit(RP, this.chain, OP));

        ArgumentCaptor<ValidationRequest> asked = ArgumentCaptor.forClass(ValidationRequest.class);
        verify(this.validator).validate(asked.capture());
        assertEquals(5, asked.getValue().budget().requests());
        assertEquals(Duration.ofSeconds(3), asked.getValue().budget().wallClock());
    }

    // ---- the failure memory ------------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §18.1(3)")
    void theSameBadChainPostedTwiceWithinTheBackoffIsResolvedOnce() throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenThrow(untrusted());
        RegistrationService service = this.service();

        RegistrationRejectedException first = assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        this.clock.advance(Duration.ofSeconds(RegistrationService.TRUST_FAILURE_BACKOFF_SECONDS - 1));
        RegistrationRejectedException second = assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));

        assertEquals(first.getMessage(), second.getMessage(), "the remembered failure is answered again");
        assertEquals(first.kind(), second.kind());
        assertEquals(400, second.status());
        assertEquals("invalid_trust_chain", second.error());
        verify(this.validator, times(1)).validate(any(ValidationRequest.class));

        this.clock.advance(Duration.ofSeconds(1));
        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        verify(this.validator, times(2)).validate(any(ValidationRequest.class));
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aChainThatDiffersOnlyAfterItsFirstStatementIsAnotherAttemptAndEachIsRemembered() throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenThrow(untrusted());
        RegistrationService service = this.service();
        List<String> varied = this.variedAfterTheFirst();

        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, varied), OP));
        verify(this.validator, times(2)).validate(any(ValidationRequest.class));

        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, varied), OP));
        verify(this.validator, times(2)).validate(any(ValidationRequest.class));
    }

    @Test
    void aFederationRefusalThatIsNotAChainsKeepsItsOwnCodeAndIsRemembered() throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenThrow(
                new com.pingidentity.ps.oidf.federation.FederationException(com.pingidentity.ps.oidf.federation.FederationError.INVALID_METADATA, "conflict"));
        RegistrationService service = this.service();

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        assertEquals(400, e.status());
        assertEquals("invalid_metadata", e.error());
        assertEquals(RegistrationRejectedException.Kind.METADATA, e.kind());
        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        verify(this.validator, times(1)).validate(any(ValidationRequest.class));
    }

    @Test
    void aTransportFailureIsRememberedForTheTransportBackoffOnly() throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenThrow(unreachable());
        RegistrationService service = this.service();

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        assertEquals(503, e.status());
        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        verify(this.validator, times(1)).validate(any(ValidationRequest.class));

        this.clock.advance(Duration.ofSeconds(RegistrationService.TRANSPORT_FAILURE_BACKOFF_SECONDS));
        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        verify(this.validator, times(2)).validate(any(ValidationRequest.class));
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aSuccessClearsTheClientsRememberedFailures() throws Exception {
        TrustChainValidationResult good = this.resolved(RP);
        List<String> goodChain = this.variedAfterTheFirst();
        when(this.validator.validate(any(ValidationRequest.class))).thenAnswer(call -> {
            ValidationRequest request = call.getArgument(0);
            if (request.presentedChain().equals(goodChain)) {
                return good;
            }
            throw untrusted();
        });
        RegistrationService service = this.service();

        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        assertNotNull(service.explicitRegister(post(RP, goodChain), OP).signedJwt());
        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));

        verify(this.validator, times(3)).validate(any(ValidationRequest.class));
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void anAutomaticSuccessClearsTheClientsRememberedFailuresAndNoOneElses() throws Exception {
        TrustChainValidationResult good = result(RP, this.chain, Map.of("oauth_client", RegistrationFixtures.agentMetadata("automatic")),
                Set.of("oauth_client"), -1L);
        List<String> goodChain = this.variedAfterTheFirst();
        when(this.validator.validate(any(ValidationRequest.class))).thenAnswer(call -> {
            ValidationRequest request = call.getArgument(0);
            if (request.presentedChain().equals(goodChain)) {
                return good;
            }
            throw untrusted();
        });
        RegistrationService service = this.service();
        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(OTHER, this.chain), OP));
        assertThrows(RegistrationRejectedException.class, () -> service.admit(RP, this.chain, OP));
        assertEquals(3, service.rememberedFailures(), "the other client's chain, and this one's chain and discovery");

        assertEquals(Admission.REGISTERED, service.admit(RP, goodChain, OP));

        assertEquals(1, service.rememberedFailures(), "only the other client's failure is left");
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aRememberedExplicitFailureIsAnsweredWithoutWaitingForTheCoordinator() throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenThrow(untrusted());
        RegistrationService service = this.service(new RegistrationCoordinator(1, 0L));
        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<RegisteredClient> first = this.held(service, OTHER, started, release);
        assertTrue(started.await(5, TimeUnit.SECONDS));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP));

        assertEquals(RegistrationRejectedException.Kind.TRUST, e.kind(), "the remembered failure, not the full pool's busy");
        assertEquals(400, e.status());
        release.countDown();
        first.get(5, TimeUnit.SECONDS);
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void theMemoryHoldsAtMostItsTotalHoweverManyClientsAStrangerNames() throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenThrow(untrusted());
        RegistrationService service = this.service();

        for (int i = 0; i < RegistrationService.ATTEMPT_MEMORY + 100; i++) {
            String stranger = "https://stranger-" + i + ".example.com";
            assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(stranger, this.chain), OP));
        }
        for (int i = 0; i < 100; i++) {
            List<String> varied = new ArrayList<>(this.chain);
            varied.add("x" + i);
            assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, varied), OP));
        }

        assertEquals(RegistrationService.ATTEMPT_MEMORY, service.rememberedFailures(), "one bound across every client and chain");
    }

    @Test
    void aRequestThatWaitedForTheSameBadChainFindsItsFailureUnderTheLock() throws Exception {
        RegistrationService service = this.service(new RegistrationCoordinator(8, 5_000L));
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(this.validator.validate(any(ValidationRequest.class))).thenAnswer(call -> {
            started.countDown();
            release.await(5, TimeUnit.SECONDS);
            throw untrusted();
        });
        Future<?> first = this.pool.submit(() -> service.explicitRegister(post(RP, this.chain), OP));
        assertTrue(started.await(5, TimeUnit.SECONDS));
        Future<?> second = this.pool.submit(() -> service.explicitRegister(post(RP, this.chain), OP));
        release.countDown();

        for (Future<?> f : List.of(first, second)) {
            java.util.concurrent.ExecutionException e = assertThrows(java.util.concurrent.ExecutionException.class, () -> f.get(5, TimeUnit.SECONDS));
            assertTrue(e.getCause() instanceof RegistrationRejectedException, String.valueOf(e.getCause()));
        }
        verify(this.validator, times(1)).validate(any(ValidationRequest.class));
    }

    @Test
    void aBusyRefusalIsNotRemembered() throws Exception {
        RegistrationService service = this.service(new RegistrationCoordinator(1, 0L));
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<RegisteredClient> first = this.held(service, OTHER, started, release);
        assertTrue(started.await(5, TimeUnit.SECONDS));
        assertEquals(RegistrationRejectedException.Kind.BUSY,
                assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(post(RP, this.chain), OP)).kind());
        release.countDown();
        first.get(5, TimeUnit.SECONDS);

        assertNotNull(service.explicitRegister(post(RP, this.chain), OP), "tried again, not answered from memory");
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void theAutomaticPathRemembersTheWholePresentedChain() throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenThrow(untrusted());
        RegistrationService service = this.service();
        List<String> varied = this.variedAfterTheFirst();

        // An unknown client is tried from the chain it presents, then by discovery: the first request costs both, the
        // varied chain one more (discovery is remembered), and repeating either costs nothing.
        assertThrows(RegistrationRejectedException.class, () -> service.admit(RP, this.chain, OP));
        verify(this.validator, times(2)).validate(any(ValidationRequest.class));
        assertThrows(RegistrationRejectedException.class, () -> service.admit(RP, varied, OP));
        verify(this.validator, times(3)).validate(any(ValidationRequest.class));
        assertThrows(RegistrationRejectedException.class, () -> service.admit(RP, this.chain, OP));
        assertThrows(RegistrationRejectedException.class, () -> service.admit(RP, varied, OP));

        verify(this.validator, times(3)).validate(any(ValidationRequest.class));
    }

    // ---- the keys ----------------------------------------------------------------------------------------------

    @Test
    void theKeyCoversEveryStatementInOrderAndThePeerChain() {
        List<String> ab = List.of("a", "b");
        String key = RegistrationService.chainKey("explicit", ab, List.of());

        assertEquals(key, RegistrationService.chainKey("explicit", List.of("a", "b"), List.of()));
        assertNotEquals(key, RegistrationService.chainKey("explicit", List.of("b", "a"), List.of()), "order");
        assertNotEquals(key, RegistrationService.chainKey("explicit", List.of("a", "c"), List.of()), "a later statement");
        assertNotEquals(key, RegistrationService.chainKey("explicit", List.of("ab"), List.of()), "where one statement ends");
        assertNotEquals(RegistrationService.chainKey("explicit", List.of("ab", "c"), List.of()),
                RegistrationService.chainKey("explicit", List.of("a", "bc"), List.of()), "the same count and concatenation, other boundaries");
        assertNotEquals(key, RegistrationService.chainKey("explicit", List.of("a"), List.of("b")), "the peer chain is its own list");
        assertNotEquals(key, RegistrationService.chainKey("presented", ab, List.of()), "the path");
        assertEquals(64, key.length());
        assertEquals("discovery", RegistrationService.hintKey(List.of()));
        assertEquals(RegistrationService.chainKey("presented", ab, List.of()), RegistrationService.hintKey(ab));
    }

    @Test
    void anExplicitRequestsKeyIsItsPresentedChainAndPeerChain() {
        ExplicitRegistrationRequest withPeer = new ExplicitRegistrationRequest(RP, RP, this.chain, Map.of(), null, List.of("peer"));

        assertEquals(RegistrationService.chainKey("explicit", this.chain, List.of("peer")), RegistrationService.explicitChainKey(withPeer));
        assertNotEquals(RegistrationService.explicitChainKey(post(RP, this.chain)), RegistrationService.explicitChainKey(withPeer));
    }
}
