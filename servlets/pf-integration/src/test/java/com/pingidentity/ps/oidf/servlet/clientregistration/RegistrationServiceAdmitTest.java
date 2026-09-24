package com.pingidentity.ps.oidf.servlet.clientregistration;

import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.ANCHOR;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.OP_ISSUER;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.agentMetadata;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.federationClient;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.jwks;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.param;
import static com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationFixtures.result;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidationRequest;
import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement;
import com.pingidentity.ps.oidf.pf.testkit.FakeClientStore;
import com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationService.Admission;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.sourceid.oauth20.domain.Client;

/**
 * {@link RegistrationService#admit}: what the token endpoint does with a request naming a client, before
 * PingFederate authenticates it. The request is unauthenticated, so every test here is also about what a
 * stranger can make the OP do: renew a registration it did not need to, roll it back, or spoil the real client's
 * next attempt. None of the three.
 */
class RegistrationServiceAdmitTest {

    private static final String CLIENT_ID = "https://rp.example.com/e/agent-7";
    private static final Map<String, Object> NEW_KEYS = jwks("k2", "rotated");

    private final MutableClock clock = MutableClock.startingNow();
    private final TrustChainValidator validator = mock(TrustChainValidator.class);
    private final FakeClientStore store = new FakeClientStore();
    private final List<List<String>> validated = new ArrayList<>();
    private EventCapture events;

    @BeforeEach
    void captureEvents() {
        this.events = EventCapture.install();
    }

    @AfterEach
    void releaseEvents() {
        this.events.close();
    }

    private RegistrationService service(ExpiryEnforcement enforcement) throws Exception {
        return RegistrationFixtures.service(this.validator, this.store, this.clock, enforcement);
    }

    private RegistrationService service() throws Exception {
        return this.service(ExpiryEnforcement.REFUSE);
    }

    /** The client's chain with its configuration issued {@code secondsAgo}, with these keys. */
    private List<String> chainIssued(long secondsAgo, Map<String, Object> keys) {
        return RegistrationFixtures.chain(CLIENT_ID, ANCHOR, this.clock.epochSecond() - secondsAgo, keys, Map.of());
    }

    private Client autoClient(Long expiresAt, List<String> chain) {
        Client client = federationClient(CLIENT_ID, "auto_registered", expiresAt, chain);
        this.store.with(client);
        return client;
    }

    private long in(long seconds) {
        return this.clock.epochSecond() + seconds;
    }

    /**
     * The federation's answer to every validation: a presented chain validates as itself unless
     * {@code presentedFails} says otherwise; discovery finds {@code discovered}, or fails with {@code discoveryFails}.
     * A chain that validates expires {@code expiresIn} seconds after it is validated (null: no known expiry).
     */
    private void federation(List<String> discovered, Long expiresIn, Kind presentedFails, Kind discoveryFails) throws Exception {
        when(this.validator.validate(any(ValidationRequest.class))).thenAnswer(invocation -> {
            ValidationRequest request = invocation.getArgument(0);
            this.validated.add(request.presentedChain());
            boolean presented = !request.presentedChain().isEmpty();
            Kind failure = presented ? presentedFails : discoveryFails;
            if (failure != null) {
                throw new TrustChainValidationException(failure, null, CLIENT_ID, "refused: " + failure.code());
            }
            List<String> chain = presented ? request.presentedChain() : discovered;
            long chainExp = expiresIn == null ? -1L : this.in(expiresIn);
            return result(CLIENT_ID, chain, Map.of("oauth_client", agentMetadata("automatic")), Set.of("oauth_client"), chainExp);
        });
    }

    private void federationValidates(List<String> discovered, Long expiresIn) throws Exception {
        this.federation(discovered, expiresIn, null, null);
    }

    private Client stored() {
        return this.store.get(CLIENT_ID);
    }

    // ---- a current registration costs one store read ------------------------------------------------------

    @Test
    void aCurrentRegistrationIsAdmittedWithoutValidating() throws Exception {
        List<String> chain = this.chainIssued(60, RegistrationFixtures.JWKS);
        this.autoClient(this.in(3600), chain);

        assertEquals(Admission.CURRENT, this.service().admit(CLIENT_ID, chain, OP_ISSUER));
        assertEquals(Admission.CURRENT, this.service().admit(CLIENT_ID, List.of(), OP_ISSUER));

        verifyNoInteractions(this.validator);
        assertEquals(List.of(), this.store.writes());
    }

    @Test
    void aNewerConfigurationThatChangesNothingIsNotANotice() throws Exception {
        this.autoClient(this.in(3600), this.chainIssued(600, RegistrationFixtures.JWKS));

        assertEquals(Admission.CURRENT, this.service().admit(CLIENT_ID, this.chainIssued(5, RegistrationFixtures.JWKS), OP_ISSUER),
                "an Entity Configuration re-signed with the same keys and metadata leaves the registration as it is");
        verifyNoInteractions(this.validator);
    }

    // ---- §12.5: a newer configuration with other keys or metadata is a notice of change -------------------

    @Test
    @Requirement({"OIDFED §12.5(2.1)", "OIDFED §12.1.1.1.2(2)"})
    void aNewerConfigurationWithOtherKeysRenewsTheRegistrationAtOnce() throws Exception {
        this.autoClient(this.in(3600), this.chainIssued(600, RegistrationFixtures.JWKS));
        List<String> rotated = this.chainIssued(5, NEW_KEYS);
        this.federationValidates(rotated, null);

        assertEquals(Admission.RENEWED, this.service().admit(CLIENT_ID, rotated, OP_ISSUER));

        assertEquals(List.of(rotated), this.validated, "validated from the chain the notice came with");
        assertEquals(rotated, this.stored().getExtendedParams().get("trust_chain").getElements());
        assertEquals(List.of("update " + CLIENT_ID), this.store.writes());
        FederationEvent refreshed = this.events.only(FederationEvents.REGISTRATION_REFRESHED);
        assertEquals(Long.toString(this.in(3600)), refreshed.fields().get("previous_expires_at"));
    }

    @Test
    void aNewerConfigurationWithOtherMetadataIsANoticeToo() throws Exception {
        this.autoClient(this.in(3600), this.chainIssued(600, RegistrationFixtures.JWKS));
        List<String> changed = RegistrationFixtures.chain(CLIENT_ID, ANCHOR, this.clock.epochSecond() - 5, RegistrationFixtures.JWKS,
                Map.of("oauth_client", Map.of("client_name", "Renamed")));
        this.federationValidates(changed, null);

        assertEquals(Admission.RENEWED, this.service().admit(CLIENT_ID, changed, OP_ISSUER));
    }

    /** Replaying a configuration the client has since replaced would roll its registration back to retired keys. */
    @Test
    void anOlderConfigurationIsNeverANotice() throws Exception {
        this.autoClient(this.in(3600), this.chainIssued(60, NEW_KEYS));

        assertEquals(Admission.CURRENT, this.service().admit(CLIENT_ID, this.chainIssued(600, RegistrationFixtures.JWKS), OP_ISSUER));
        verifyNoInteractions(this.validator);
    }

    @Test
    void aChainThatDoesNotStartWithTheClientsOwnConfigurationIsNoNotice() throws Exception {
        this.autoClient(this.in(3600), this.chainIssued(600, RegistrationFixtures.JWKS));
        List<String> someoneElses = RegistrationFixtures.chain("https://other.example", ANCHOR, this.clock.epochSecond(), NEW_KEYS, Map.of());

        assertEquals(Admission.CURRENT, this.service().admit(CLIENT_ID, someoneElses, OP_ISSUER));
        assertEquals(Admission.CURRENT, this.service().admit(CLIENT_ID, List.of("not a jwt"), OP_ISSUER));
        verifyNoInteractions(this.validator);
    }

    @Test
    void aRegistrationWithNoStoredChainTakesTheClientsConfigurationAsANotice() throws Exception {
        this.autoClient(this.in(3600), null);
        List<String> chain = this.chainIssued(5, RegistrationFixtures.JWKS);
        this.federationValidates(chain, null);

        assertEquals(Admission.RENEWED, this.service().admit(CLIENT_ID, chain, OP_ISSUER));
    }

    // ---- §12.3: renewed before expiry, bounded -------------------------------------------------------------

    @Test
    @Requirement("OIDFED §12.3(1)")
    void aRegistrationNearItsExpiryIsRenewed() throws Exception {
        this.autoClient(this.in(200), this.chainIssued(600, RegistrationFixtures.JWKS));
        List<String> discovered = this.chainIssued(1, RegistrationFixtures.JWKS);
        this.federationValidates(discovered, 7200L);

        assertEquals(Admission.RENEWED, this.service().admit(CLIENT_ID, List.of(), OP_ISSUER));

        assertEquals(List.of(List.of()), this.validated, "no chain presented: renewed by discovery");
        assertEquals(Long.toString(this.in(7200)), param(this.stored(), FederationClientParams.EXPIRES_AT));
    }

    @Test
    void aRegistrationRenewedMomentsAgoIsNotRenewedAgainForBeingDue() throws Exception {
        this.autoClient(this.in(200), this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federationValidates(this.chainIssued(1, RegistrationFixtures.JWKS), 120L);
        RegistrationService service = this.service();

        assertEquals(Admission.RENEWED, service.admit(CLIENT_ID, List.of(), OP_ISSUER));
        this.clock.advance(Duration.ofSeconds(10));
        assertEquals(Admission.CURRENT, service.admit(CLIENT_ID, List.of(), OP_ISSUER),
                "a chain that always expires inside the refresh window would otherwise renew on every request");
        this.clock.advance(Duration.ofSeconds(RegistrationService.RENEWAL_MIN_INTERVAL_SECONDS));
        assertEquals(Admission.RENEWED, service.admit(CLIENT_ID, List.of(), OP_ISSUER));

        verify(this.validator, times(2)).validate(any(ValidationRequest.class));
    }

    @Test
    @Requirement("OIDFED §12.3(1)")
    void aRenewalThatFailsBeforeExpiryLeavesTheRegistrationStanding() throws Exception {
        this.autoClient(this.in(200), this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federation(List.of(), null, null, Kind.SIGNATURE);
        RegistrationService service = this.service();

        assertEquals(Admission.DEFERRED, service.admit(CLIENT_ID, List.of(), OP_ISSUER));
        assertEquals(Admission.DEFERRED, service.admit(CLIENT_ID, List.of(), OP_ISSUER));

        verify(this.validator, times(1)).validate(any(ValidationRequest.class));
        assertEquals(List.of(), this.store.writes());
        assertEquals("trust", this.events.only(FederationEvents.REGISTRATION_REFRESH_DEFERRED).reason());

        this.clock.advance(Duration.ofSeconds(RegistrationService.TRUST_FAILURE_BACKOFF_SECONDS));
        assertEquals(Admission.DEFERRED, service.admit(CLIENT_ID, List.of(), OP_ISSUER));
        verify(this.validator, times(2)).validate(any(ValidationRequest.class));
    }

    @Test
    void aFederationThatCouldNotBeReachedIsAskedAgainSooner() throws Exception {
        this.autoClient(this.in(250), this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federation(List.of(), null, null, Kind.TRANSPORT);
        RegistrationService service = this.service();

        assertEquals(Admission.DEFERRED, service.admit(CLIENT_ID, List.of(), OP_ISSUER));
        this.clock.advance(Duration.ofSeconds(RegistrationService.TRANSPORT_FAILURE_BACKOFF_SECONDS - 1));
        assertEquals(Admission.DEFERRED, service.admit(CLIENT_ID, List.of(), OP_ISSUER));
        this.clock.advance(Duration.ofSeconds(1));
        assertEquals(Admission.DEFERRED, service.admit(CLIENT_ID, List.of(), OP_ISSUER));

        verify(this.validator, times(2)).validate(any(ValidationRequest.class));
    }

    /**
     * A stranger names a current client and presents a forged "newer" configuration. It fails, and is remembered -
     * under the forged chain. The client's own notice a moment later is a different attempt and goes ahead.
     */
    @Test
    void aForgedNoticeDoesNotSpoilTheClientsOwn() throws Exception {
        this.autoClient(this.in(3600), this.chainIssued(600, RegistrationFixtures.JWKS));
        List<String> forged = this.chainIssued(10, jwks("attacker", "forged"));
        List<String> genuine = this.chainIssued(5, NEW_KEYS);
        when(this.validator.validate(any(ValidationRequest.class))).thenAnswer(invocation -> {
            ValidationRequest request = invocation.getArgument(0);
            if (request.presentedChain().equals(forged)) {
                throw new TrustChainValidationException(Kind.SIGNATURE, CLIENT_ID, CLIENT_ID, "bad signature");
            }
            return result(CLIENT_ID, request.presentedChain(), Map.of("oauth_client", agentMetadata("automatic")), Set.of("oauth_client"), -1L);
        });
        RegistrationService service = this.service();

        assertEquals(Admission.DEFERRED, service.admit(CLIENT_ID, forged, OP_ISSUER));
        assertEquals(Admission.RENEWED, service.admit(CLIENT_ID, genuine, OP_ISSUER));
        assertEquals(genuine, this.stored().getExtendedParams().get("trust_chain").getElements());
    }

    // ---- past expiry ---------------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §12.1.1.1.2(2)")
    void anExpiredRegistrationIsRenewedFromThePresentedChain() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS));
        List<String> chain = this.chainIssued(5, RegistrationFixtures.JWKS);
        this.federationValidates(chain, null);

        assertEquals(Admission.RENEWED, this.service().admit(CLIENT_ID, chain, OP_ISSUER));
        assertEquals(List.of(chain), this.validated);
    }

    /** The presented chain is the caller's; when it fails, the federation's own answer is what counts. */
    @Test
    void anExpiredRegistrationIsRenewedByDiscoveryWhenThePresentedChainFails() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS));
        List<String> presented = this.chainIssued(5, RegistrationFixtures.JWKS);
        List<String> discovered = this.chainIssued(1, RegistrationFixtures.JWKS);
        this.federation(discovered, null, Kind.SIGNATURE, null);

        assertEquals(Admission.RENEWED, this.service().admit(CLIENT_ID, presented, OP_ISSUER));
        assertEquals(List.of(presented, List.of()), this.validated);
        assertEquals(discovered, this.stored().getExtendedParams().get("trust_chain").getElements());
    }

    @Test
    void anOlderConfigurationPresentedForAnExpiredRegistrationIsSetAsideForDiscovery() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(60, NEW_KEYS));
        this.federationValidates(this.chainIssued(1, NEW_KEYS), null);

        assertEquals(Admission.RENEWED, this.service().admit(CLIENT_ID, this.chainIssued(600, RegistrationFixtures.JWKS), OP_ISSUER));
        assertEquals(List.of(List.of()), this.validated, "the replayed configuration is never validated, so never registered");
    }

    @Test
    void aClientRegisteredBeforeExpiriesWereRecordedIsRenewedOnItsNextRequest() throws Exception {
        this.autoClient(null, this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federationValidates(this.chainIssued(1, RegistrationFixtures.JWKS), null);

        assertEquals(Admission.RENEWED, this.service().admit(CLIENT_ID, List.of(), OP_ISSUER));
        assertNotNull(param(this.stored(), FederationClientParams.EXPIRES_AT));
    }

    @Test
    @Requirement("OIDFED §12.3(1)")
    void anExpiredRegistrationThatCannotBeRenewedIsRefused() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federation(List.of(), null, Kind.SIGNATURE, Kind.ROUTE);

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> this.service().admit(CLIENT_ID, this.chainIssued(5, RegistrationFixtures.JWKS), OP_ISSUER));

        assertEquals(401, e.status());
        assertEquals("invalid_client", e.error());
        assertTrue(e.getMessage().contains("refused: route"), "the discovery failure is the reason given: " + e.getMessage());
        FederationEvent expired = this.events.only(FederationEvents.REGISTRATION_EXPIRED);
        assertTrue(expired.audit());
        assertEquals("refuse", expired.fields().get("enforcement"));
        assertTrue(this.stored().isEnabled(), "refused, not disabled");
        assertEquals(List.of(), this.store.writes());
    }

    @Test
    @Requirement("OIDFED §10.5")
    void anExpiredRegistrationWhoseFederationCannotBeReachedIsTemporarilyUnavailable() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federation(List.of(), null, null, Kind.TRANSPORT);

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> this.service().admit(CLIENT_ID, List.of(), OP_ISSUER));

        assertEquals(503, e.status());
        assertEquals("temporarily_unavailable", e.error());
        assertTrue(e.isTransport());
    }

    @Test
    void anExpiredClientsRememberedFailuresAreEnforcedWithoutAskingAgain() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federation(List.of(), null, Kind.SIGNATURE, Kind.ROUTE);
        List<String> presented = this.chainIssued(5, RegistrationFixtures.JWKS);
        RegistrationService service = this.service();

        assertThrows(RegistrationRejectedException.class, () -> service.admit(CLIENT_ID, presented, OP_ISSUER));
        RegistrationRejectedException again = assertThrows(RegistrationRejectedException.class, () -> service.admit(CLIENT_ID, presented, OP_ISSUER));

        assertEquals("invalid_client", again.error());
        verify(this.validator, times(2)).validate(any(ValidationRequest.class));
    }

    @Test
    void underDisableAnExpiredRegistrationIsDisabledAndMarkedAsExpirysDoing() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federation(List.of(), null, null, Kind.ROUTE);

        assertThrows(RegistrationRejectedException.class, () -> this.service(ExpiryEnforcement.DISABLE).admit(CLIENT_ID, List.of(), OP_ISSUER));

        assertFalse(this.stored().isEnabled());
        assertEquals(Long.toString(this.clock.epochSecond()), param(this.stored(), FederationClientParams.DISABLED_AT));
        assertEquals(List.of("disable " + CLIENT_ID), this.store.writes());
        assertTrue(this.events.only(FederationEvents.REGISTRATION_DISABLED).audit());
    }

    @Test
    void underDisableAClientAlreadyDisabledIsNotWrittenAgain() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS)).setEnabled(false);
        this.federation(List.of(), null, null, Kind.ROUTE);

        assertThrows(RegistrationRejectedException.class, () -> this.service(ExpiryEnforcement.DISABLE).admit(CLIENT_ID, List.of(), OP_ISSUER));

        assertEquals(List.of(), this.store.writes());
        assertEquals(List.of(), this.events.withCode(FederationEvents.REGISTRATION_DISABLED));
    }

    @Test
    void underLogAnExpiredRegistrationIsAllowedAndSaysSo() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federation(List.of(), null, null, Kind.ROUTE);

        assertEquals(Admission.EXPIRED_ALLOWED, this.service(ExpiryEnforcement.LOG).admit(CLIENT_ID, List.of(), OP_ISSUER));

        assertEquals("log", this.events.only(FederationEvents.REGISTRATION_EXPIRED).fields().get("enforcement"));
        assertTrue(this.stored().isEnabled());
    }

    // ---- enabling again ------------------------------------------------------------------------------------

    @Test
    void aRenewalEnablesAClientItsExpiryDisabled() throws Exception {
        Client client = this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS));
        RegistrationService.disableExpired(this.store, client, this.clock.epochSecond());
        this.federationValidates(this.chainIssued(1, RegistrationFixtures.JWKS), null);

        assertEquals(Admission.RENEWED, this.service().admit(CLIENT_ID, List.of(), OP_ISSUER));

        assertTrue(this.stored().isEnabled());
        assertNull(param(this.stored(), FederationClientParams.DISABLED_AT));
    }

    @Test
    @Requirement("OIDFED §12.2.6(2)")
    void aRenewalLeavesAnOperatorsDisableInPlace() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS)).setEnabled(false);
        this.federationValidates(this.chainIssued(1, RegistrationFixtures.JWKS), null);

        assertEquals(Admission.RENEWED, this.service().admit(CLIENT_ID, List.of(), OP_ISSUER));

        assertFalse(this.stored().isEnabled(), "the operator's disable outlives the renewal");
    }

    // ---- a client the OP has not seen ----------------------------------------------------------------------

    /**
     * A first registration tries the presented chain on its own, then the federation's answer by discovery. Both
     * failures are remembered, so the same request again costs nothing; another chain costs one attempt of its own.
     */
    @Test
    void aFailedFirstRegistrationIsNotRepeatedWithTheSameChain() throws Exception {
        this.federation(List.of(), null, Kind.SIGNATURE, Kind.SIGNATURE);
        List<String> chain = this.chainIssued(5, RegistrationFixtures.JWKS);
        RegistrationService service = this.service();

        RegistrationRejectedException first = assertThrows(RegistrationRejectedException.class, () -> service.admit(CLIENT_ID, chain, OP_ISSUER));
        RegistrationRejectedException second = assertThrows(RegistrationRejectedException.class, () -> service.admit(CLIENT_ID, chain, OP_ISSUER));
        assertSame(first, second);
        assertEquals(List.of(chain, List.of()), this.validated);

        assertThrows(RegistrationRejectedException.class, () -> service.admit(CLIENT_ID, this.chainIssued(1, NEW_KEYS), OP_ISSUER));
        assertEquals(3, this.validated.size(), "the new chain's own attempt; discovery is still remembered");
    }

    /** A chain someone presents is checked as it stands - nothing fetched on its say-so; discovery gets the full budget. */
    @Test
    @Requirement("OIDFED §18.1(5)")
    void aPresentedChainIsValidatedOnItsOwnAndDiscoveryFromTheClientsOwnConfiguration() throws Exception {
        this.federation(List.of(), null, Kind.SIGNATURE, Kind.SIGNATURE);
        List<String> chain = this.chainIssued(5, RegistrationFixtures.JWKS);

        assertThrows(RegistrationRejectedException.class, () -> this.service().admit(CLIENT_ID, chain, OP_ISSUER));

        ArgumentCaptor<ValidationRequest> asked = ArgumentCaptor.forClass(ValidationRequest.class);
        verify(this.validator, times(2)).validate(asked.capture());
        assertEquals(chain, asked.getAllValues().get(0).presentedChain());
        assertEquals(0, asked.getAllValues().get(0).maxFetches());
        assertEquals(List.of(), asked.getAllValues().get(1).presentedChain());
        assertEquals(-1, asked.getAllValues().get(1).maxFetches());
    }

    /** A notice of change renews a current registration only from its own chain: a forged one fetches nothing at all. */
    @Test
    void aNoticeThatDoesNotValidateOnItsOwnIsNotFollowedToDiscovery() throws Exception {
        this.autoClient(this.in(3600), this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federation(this.chainIssued(1, RegistrationFixtures.JWKS), null, Kind.BUDGET, null);

        assertEquals(Admission.DEFERRED, this.service().admit(CLIENT_ID, this.chainIssued(5, NEW_KEYS), OP_ISSUER));

        assertEquals(1, this.validated.size(), "no discovery on a stranger's say-so");
        assertEquals(List.of(), this.store.writes());
    }

    @Test
    void aFirstRegistrationIsRememberedAsARenewal() throws Exception {
        List<String> chain = this.chainIssued(5, RegistrationFixtures.JWKS);
        this.federationValidates(chain, 120L);
        RegistrationService service = this.service();

        assertEquals(Admission.REGISTERED, service.admit(CLIENT_ID, chain, OP_ISSUER));
        assertEquals(Admission.CURRENT, service.admit(CLIENT_ID, chain, OP_ISSUER),
                "due at once (its chain is short), but registered moments ago");
        assertEquals(List.of("add " + CLIENT_ID), this.store.writes());
    }

    // ---- explicit registrations are their RP's to renew ------------------------------------------------------

    @Test
    void aCurrentExplicitRegistrationIgnoresEvenANotice() throws Exception {
        this.store.with(federationClient(CLIENT_ID, "registered", this.in(200), this.chainIssued(600, RegistrationFixtures.JWKS)));

        assertEquals(Admission.CURRENT, this.service().admit(CLIENT_ID, this.chainIssued(5, NEW_KEYS), OP_ISSUER));
        verifyNoInteractions(this.validator);
    }

    @Test
    @Requirement("OIDFED §12.3(1)")
    void anExpiredExplicitRegistrationIsRefusedUntilItsRpRegistersAgain() throws Exception {
        this.store.with(federationClient(CLIENT_ID, "registered", this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS)));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> this.service().admit(CLIENT_ID, this.chainIssued(5, RegistrationFixtures.JWKS), OP_ISSUER));

        assertEquals(401, e.status());
        assertTrue(e.getMessage().contains("registering again"), e.getMessage());
        verifyNoInteractions(this.validator);
    }

    @Test
    void anExplicitRegistrationWithNoRecordedExpiryIsTreatedAsExpired() throws Exception {
        this.store.with(federationClient(CLIENT_ID, "registered", null, null));

        assertThrows(RegistrationRejectedException.class, () -> this.service().admit(CLIENT_ID, List.of(), OP_ISSUER));
        assertEquals(Admission.EXPIRED_ALLOWED, this.service(ExpiryEnforcement.LOG).admit(CLIENT_ID, List.of(), OP_ISSUER));
    }

    // ---- the pure checks -------------------------------------------------------------------------------------

    @Test
    void theNoticeChecksReadOnlyTheClientsOwnConfiguration() {
        List<String> registered = this.chainIssued(600, RegistrationFixtures.JWKS);
        Client client = federationClient(CLIENT_ID, "auto_registered", this.in(3600), registered);
        List<String> older = this.chainIssued(900, NEW_KEYS);
        List<String> newer = this.chainIssued(5, NEW_KEYS);

        assertFalse(RegistrationService.presentsChange(List.of(), client, CLIENT_ID));
        assertTrue(RegistrationService.presentsChange(newer, client, CLIENT_ID));
        assertFalse(RegistrationService.presentsChange(older, client, CLIENT_ID));
        assertFalse(RegistrationService.presentsChange(registered, client, "https://someone-else.example"));
        assertTrue(RegistrationService.predatesRegistration(older, client, CLIENT_ID));
        assertFalse(RegistrationService.predatesRegistration(newer, client, CLIENT_ID));
        assertFalse(RegistrationService.predatesRegistration(List.of(), client, CLIENT_ID));
        assertFalse(RegistrationService.predatesRegistration(older, federationClient(CLIENT_ID, "auto_registered", null, null), CLIENT_ID));
        List<String> noIat = List.of(com.pingidentity.ps.oidf.federation.testkit.Statements.spec("entity-statement+jwt")
                .claim("iss", CLIENT_ID).claim("sub", CLIENT_ID).claim("jwks", NEW_KEYS).withoutIat().unsigned()
                .sign(null, this.clock));
        assertFalse(RegistrationService.presentsChange(noIat, client, CLIENT_ID), "without iat a configuration is never newer");
        List<String> aboutAnother = List.of(com.pingidentity.ps.oidf.federation.testkit.Statements.spec("entity-statement+jwt")
                .claim("iss", CLIENT_ID).claim("sub", "https://another.example").claim("jwks", NEW_KEYS).unsigned().sign(null, this.clock));
        assertFalse(RegistrationService.presentsChange(aboutAnother, client, CLIENT_ID),
                "a statement the client issued about someone else is not its configuration");
    }

    @Test
    void aClientWithNoExtendedParametersCanStillBeDisabledForExpiry() {
        Client bare = new Client();
        bare.setClientId(CLIENT_ID);
        bare.setExtendedParams(null);
        this.store.with(bare);

        RegistrationService.disableExpired(this.store, bare, 42L);

        assertFalse(this.stored().isEnabled());
        assertEquals("42", param(this.stored(), FederationClientParams.DISABLED_AT));
    }

    @Test
    void theChainValidatedForARenewalCarriesTheOpAndTheEntryAgeLimit() throws Exception {
        this.autoClient(this.in(-1), this.chainIssued(600, RegistrationFixtures.JWKS));
        this.federationValidates(this.chainIssued(1, RegistrationFixtures.JWKS), null);

        this.service().admit(CLIENT_ID, List.of(), OP_ISSUER);

        ArgumentCaptor<ValidationRequest> asked = ArgumentCaptor.forClass(ValidationRequest.class);
        verify(this.validator).validate(asked.capture());
        assertEquals(CLIENT_ID, asked.getValue().subject());
        assertEquals(OP_ISSUER, asked.getValue().opIssuer());
        assertEquals(60L, asked.getValue().maxPresentedEntryAgeSeconds());
    }
}
