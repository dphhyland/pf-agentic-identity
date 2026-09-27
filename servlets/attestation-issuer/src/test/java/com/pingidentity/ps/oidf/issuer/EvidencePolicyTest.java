package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * The deployment-wide policy on evidence: how long it may still live, whether it may name more than one
 * audience, and that production may shorten the lifetime cap but never lengthen it.
 */
class EvidencePolicyTest {
    private static final long NOW = 1_800_000_000L;

    private static Function<String, String> none() {
        return k -> null;
    }

    private static InstanceIdentity spiffe(long exp, List<String> aud) {
        return new InstanceIdentity("spiffe", "spiffe://d/x", "d", null, Map.of(), exp, "spiffe-jwt", "digest", aud);
    }

    private static InstanceIdentity wallet(long exp, List<String> aud) {
        return new InstanceIdentity("wallet", "urn:w:1", "https://wp.example", null, Map.of(), exp, "wallet-instance-attestation", "digest", aud);
    }

    @Test
    void theDefaultIsADayAndAnyAudienceCount() {
        EvidencePolicy p = EvidencePolicy.fromEnvironment(none(), none());
        assertEquals(86400L, p.maxEvidenceLifetimeSeconds());
        assertFalse(p.requireSingleAudience());
        assertEquals(86400L, EvidencePolicy.defaults().maxEvidenceLifetimeSeconds());
    }

    @Test
    void theLifetimeComesFromThePropertyThenTheVariable() {
        assertEquals(600L, EvidencePolicy.fromEnvironment(Map.of(EvidencePolicy.MAX_LIFETIME_PROPERTY, " 600 ")::get,
                Map.of(EvidencePolicy.MAX_LIFETIME_ENV, "700")::get).maxEvidenceLifetimeSeconds());
        assertEquals(700L, EvidencePolicy.fromEnvironment(k -> " ", Map.of(EvidencePolicy.MAX_LIFETIME_ENV, "700")::get).maxEvidenceLifetimeSeconds());
    }

    @Test
    void aLifetimeThatIsNotAPositiveNumberIsRefusedNamingTheVariable() {
        for (String bad : new String[]{"soon", "0", "-5"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> EvidencePolicy.fromEnvironment(none(), Map.of(EvidencePolicy.MAX_LIFETIME_ENV, bad)::get));
            assertTrue(e.getMessage().contains(EvidencePolicy.MAX_LIFETIME_ENV), e.getMessage());
        }
        assertThrows(IllegalArgumentException.class, () -> new EvidencePolicy(0L, false));
    }

    @Test
    void productionMayShortenTheCapButNotLengthenIt() {
        assertEquals(3600L, EvidencePolicy.fromEnvironment(none(), Map.of(EvidencePolicy.MAX_LIFETIME_ENV, "3600")::get).maxEvidenceLifetimeSeconds());
        assertEquals(86400L, EvidencePolicy.fromEnvironment(none(), Map.of(EvidencePolicy.MAX_LIFETIME_ENV, "86400")::get).maxEvidenceLifetimeSeconds());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> EvidencePolicy.fromEnvironment(none(), Map.of(EvidencePolicy.MAX_LIFETIME_ENV, "86401")::get));
        assertTrue(e.getMessage().contains("production cap"), e.getMessage());
        assertEquals(604800L, EvidencePolicy.fromEnvironment(none(),
                Map.of(EvidencePolicy.MAX_LIFETIME_ENV, "604800", EvidencePolicy.PROFILE_ENV, "development")::get).maxEvidenceLifetimeSeconds(),
                "a rig may accept week-long evidence");
    }

    @Test
    void theSingleAudienceSwitchIsTrueOrFalseAndNothingElse() {
        assertTrue(EvidencePolicy.fromEnvironment(none(), Map.of(EvidencePolicy.SINGLE_AUDIENCE_ENV, "TRUE")::get).requireSingleAudience());
        assertFalse(EvidencePolicy.fromEnvironment(none(), Map.of(EvidencePolicy.SINGLE_AUDIENCE_ENV, "false")::get).requireSingleAudience());
        assertTrue(EvidencePolicy.fromEnvironment(Map.of(EvidencePolicy.SINGLE_AUDIENCE_PROPERTY, "true")::get, none()).requireSingleAudience());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> EvidencePolicy.fromEnvironment(none(), Map.of(EvidencePolicy.SINGLE_AUDIENCE_ENV, "yes")::get));
        assertTrue(e.getMessage().contains(EvidencePolicy.SINGLE_AUDIENCE_ENV), e.getMessage());
    }

    @Test
    void everythingButDevelopmentIsProduction() {
        assertTrue(EvidencePolicy.isProduction(none()));
        assertTrue(EvidencePolicy.isProduction(k -> "production"));
        assertTrue(EvidencePolicy.isProduction(k -> "dev"));
        assertFalse(EvidencePolicy.isProduction(k -> " Development "));
    }

    @Test
    void evidenceThatLivesLongerThanTheCapIsRefusedByFormat() {
        EvidencePolicy p = new EvidencePolicy(3600L, false);
        assertEquals("invalid_svid", assertThrows(IssuanceException.class,
                () -> p.check(spiffe(NOW + 3601L, List.of("a")), NOW)).error());
        assertEquals("invalid_instance_attestation", assertThrows(IssuanceException.class,
                () -> p.check(wallet(NOW + 3601L, List.of("a")), NOW)).error());
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> p.check(spiffe(NOW + 3600L, List.of("a")), NOW));
    }

    @Test
    void multiAudienceEvidenceIsRefusedOnlyWhenRequired() throws Exception {
        new EvidencePolicy(3600L, false).check(spiffe(NOW + 60L, List.of("a", "b")), NOW);
        EvidencePolicy strict = new EvidencePolicy(3600L, true);
        strict.check(spiffe(NOW + 60L, List.of("a")), NOW);
        strict.check(spiffe(NOW + 60L, List.of()), NOW);
        IssuanceException e = assertThrows(IssuanceException.class, () -> strict.check(spiffe(NOW + 60L, List.of("a", "b")), NOW));
        assertEquals("invalid_svid", e.error());
        assertTrue(e.getMessage().contains(EvidencePolicy.SINGLE_AUDIENCE_ENV), e.getMessage());
    }

    @Test
    void theAttestationTtlIsTheClientsAndNeverPastTheEvidence() {
        assertEquals(300L, EvidencePolicy.effectiveTtlSeconds(300L, spiffe(NOW + 600L, List.of()), NOW));
        assertEquals(30L, EvidencePolicy.effectiveTtlSeconds(300L, spiffe(NOW + 30L, List.of()), NOW));
        assertEquals(1L, EvidencePolicy.effectiveTtlSeconds(300L, spiffe(NOW - 5L, List.of()), NOW), "never zero or negative");
    }
}
