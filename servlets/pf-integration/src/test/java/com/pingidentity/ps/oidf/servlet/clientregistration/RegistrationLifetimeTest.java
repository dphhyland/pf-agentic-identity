package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;

/**
 * OpenID Federation 1.0 §12.3: "The validity of an Automatic or Explicit Registration at an OP MUST NOT exceed
 * the lifetime of the Trust Chain the OP used to create the registration." {@link RegistrationLifetime} is where
 * that is decided: the earlier of the chain's expiry and the deployment's maximum, never shorter than its minimum.
 */
class RegistrationLifetimeTest {

    private final MutableClock clock = MutableClock.startingNow();
    /** Max a day, min a minute, renew in the last five minutes. */
    private final RegistrationLifetime lifetime = new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock);

    private TrustChainValidationResult chainExpiringAt(long exp) {
        return new TrustChainValidationResult.Builder().trustAnchorIssuer("https://ta.example").leafSubject("https://rp.example")
                .resolvedMetadata(Map.of()).trustChain(List.of()).expEpochSeconds(exp).build();
    }

    private long in(long seconds) {
        return this.clock.epochSecond() + seconds;
    }

    @Test
    @Requirement({"OIDFED §12.3(1)", "OIDFED §12.2.2(2.9)"})
    void aRegistrationEndsWithItsChain() throws Exception {
        assertEquals(this.in(3600), this.lifetime.expiresAt(this.chainExpiringAt(this.in(3600))));
    }

    @Test
    void aRegistrationNeverOutlivesTheDeploymentsMaximum() throws Exception {
        assertEquals(this.in(86_400), this.lifetime.expiresAt(this.chainExpiringAt(this.in(10 * 86_400))));
        assertEquals(this.in(86_400), this.lifetime.expiresAt(this.chainExpiringAt(-1L)), "a chain of unknown expiry gets the maximum");
    }

    @Test
    @Requirement("OIDFED §12.3(1)")
    void aChainAboutToExpireRegistersNothing() {
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> this.lifetime.expiresAt(this.chainExpiringAt(this.in(59))));

        assertEquals(400, e.status());
        assertEquals("invalid_trust_chain", e.error());
        assertEquals(RegistrationRejectedException.Kind.TRUST, e.kind());
        assertTrue(e.getMessage().contains("59s"), e.getMessage());
    }

    @Test
    void theMinimumItselfIsLongEnough() throws Exception {
        assertEquals(this.in(60), this.lifetime.expiresAt(this.chainExpiringAt(this.in(60))));
    }

    @Test
    void expiryIsTheRecordedInstantItself() {
        assertFalse(this.lifetime.isExpired(OptionalLong.of(this.in(1))));
        assertTrue(this.lifetime.isExpired(OptionalLong.of(this.in(0))));
        assertTrue(this.lifetime.isExpired(OptionalLong.empty()), "nothing recorded: nothing has checked it against §12.3");
    }

    @Test
    void renewalIsDueInTheLastStretchBeforeExpiry() {
        assertFalse(this.lifetime.isDueForRenewal(OptionalLong.of(this.in(301))));
        assertTrue(this.lifetime.isDueForRenewal(OptionalLong.of(this.in(300))));
        assertTrue(this.lifetime.isDueForRenewal(OptionalLong.of(this.in(-5))));
        assertTrue(this.lifetime.isDueForRenewal(OptionalLong.empty()));
    }

    @Test
    void theStoredExpiryIsReadFromTheClientAndNothingElse() {
        assertEquals(OptionalLong.of(1234L), RegistrationLifetime.storedExpiry(
                RegistrationFixtures.federationClient("https://rp.example", "auto_registered", 1234L, null)));
        assertEquals(OptionalLong.empty(), RegistrationLifetime.storedExpiry(new Client()));
        Client noParams = new Client();
        noParams.setExtendedParams(null);
        assertEquals(OptionalLong.empty(), RegistrationLifetime.storedExpiry(noParams));
        assertEquals(OptionalLong.empty(), RegistrationLifetime.storedExpiry(
                RegistrationFixtures.federationClient("https://rp.example", "auto_registered", null, null)));
        Client garbled = RegistrationFixtures.federationClient("https://rp.example", "auto_registered", null, null);
        garbled.getExtendedParams().put(FederationClientParams.EXPIRES_AT, RegistrationFixtures.values(List.of("soon")));
        assertEquals(OptionalLong.empty(), RegistrationLifetime.storedExpiry(garbled));
        Client empty = RegistrationFixtures.federationClient("https://rp.example", "auto_registered", null, null);
        empty.getExtendedParams().put(FederationClientParams.EXPIRES_AT, RegistrationFixtures.values(List.of()));
        assertEquals(OptionalLong.empty(), RegistrationLifetime.storedExpiry(empty));
        Client noValues = RegistrationFixtures.federationClient("https://rp.example", "auto_registered", null, null);
        noValues.getExtendedParams().put(FederationClientParams.EXPIRES_AT, new org.sourceid.oauth20.domain.ParamValues());
        assertEquals(OptionalLong.empty(), RegistrationLifetime.storedExpiry(noValues));
    }

    @Test
    void theSettingsAreTheOnesItWasGiven() {
        RegistrationSettings settings = RegistrationFixtures.settings(ExpiryEnforcement.DISABLE);
        assertEquals(ExpiryEnforcement.DISABLE, new RegistrationLifetime(settings, this.clock).settings().expiryEnforcement());
        assertEquals(this.clock.epochSecond(), this.lifetime.now());
    }
}
