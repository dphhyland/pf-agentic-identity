package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** H-FED-9: the resolve endpoint's per-caller cap on distinct subjects, and the short cache of its responses. */
class ResolveGuardTest {
    private static final String ISSUER = "https://pf.example";
    private final MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_800_000_000L));

    private static ResolveRequest request(String subject) {
        return new ResolveRequest(subject, List.of("https://ta.example"), List.of());
    }

    @Test
    @Requirement("OIDFED §18.1(1)")
    void aCallerIsAnsweredAboutAtMostNDistinctSubjectsAMinute() {
        ResolveGuard guard = new ResolveGuard(2, Duration.ofSeconds(60), this.clock);
        guard.admit("192.0.2.1", "https://a.example");
        this.clock.advance(Duration.ofSeconds(10));
        guard.admit("192.0.2.1", "https://b.example");
        guard.admit("192.0.2.1", "https://a.example/");

        ResolveGuard.Limited limited = assertThrows(ResolveGuard.Limited.class, () -> guard.admit("192.0.2.1", "https://c.example"));
        assertEquals(FederationError.TEMPORARILY_UNAVAILABLE, limited.error());
        assertEquals(51, limited.retryAfterSeconds(), "until the first subject leaves the minute, rounded up");
        guard.admit("192.0.2.2", "https://c.example");

        this.clock.advance(Duration.ofSeconds(50));
        guard.admit("192.0.2.1", "https://c.example");
        assertThrows(ResolveGuard.Limited.class, () -> guard.admit("192.0.2.1", "https://d.example"));
        guard.admit("192.0.2.1", "https://c.example");
        assertThrows(IllegalArgumentException.class, () -> new ResolveGuard(0, Duration.ofSeconds(60), this.clock));
    }

    @Test
    @Requirement({"OIDFED §18.1(7)", "OIDFED §8.3.2(9.8)"})
    void aResponseIsKeptForTheCacheTimeOrUntilItsExpWhicheverIsSooner() {
        ResolveGuard guard = new ResolveGuard(10, Duration.ofSeconds(60), this.clock);
        long now = this.clock.instant().getEpochSecond();
        guard.keep(request("https://a.example"), ISSUER, null, "jwt-a", now + 3600);
        guard.keep(request("https://b.example"), ISSUER, null, "jwt-b", now + 20);
        guard.keep(request("https://c.example"), ISSUER, null, "jwt-c", now);

        assertEquals("jwt-a", guard.kept(request("https://a.example/"), ISSUER + "/", null), "either spelling");
        assertNull(guard.kept(request("https://a.example"), ISSUER, "https://client.example"), "another audience is another response");
        assertNull(guard.kept(new ResolveRequest("https://a.example", List.of("https://ta2.example"), List.of()), ISSUER, null));
        assertNull(guard.kept(new ResolveRequest("https://a.example", List.of("https://ta.example"), List.of("openid_provider")), ISSUER, null));
        assertNull(guard.kept(request("https://c.example"), ISSUER, null), "an expired response is never kept");
        this.clock.advance(Duration.ofSeconds(20));
        assertNull(guard.kept(request("https://b.example"), ISSUER, null), "its exp came first");
        assertEquals("jwt-a", guard.kept(request("https://a.example"), ISSUER, null));
        this.clock.advance(Duration.ofSeconds(40));
        assertNull(guard.kept(request("https://a.example"), ISSUER, null), "sixty seconds on");

        ResolveGuard none = new ResolveGuard(10, Duration.ZERO, this.clock);
        none.keep(request("https://a.example"), ISSUER, "https://client.example", "jwt-a", now + 3600);
        assertNull(none.kept(request("https://a.example"), ISSUER, "https://client.example"), "0 keeps nothing");
    }

    @Test
    void theLimitsComeFromTheFederationResolutionSettings() {
        Catalogue catalogue = Catalogue.load(ResolveGuard.class.getClassLoader(), ValidatorOptions.COMPONENT);
        ResolveGuard defaults = ResolveGuard.fromSettings(Settings.of(catalogue, Sources.of(Map.of(), Map.of())), this.clock);
        for (int i = 0; i < 30; i++) {
            defaults.admit("192.0.2.1", "https://s" + i + ".example");
        }
        assertThrows(ResolveGuard.Limited.class, () -> defaults.admit("192.0.2.1", "https://s30.example"), "thirty by default");

        ResolveGuard one = ResolveGuard.fromSettings(Settings.of(catalogue, Sources.of(Map.of(ResolveGuard.SUBJECTS_PER_MINUTE_SETTING, "1",
                ResolveGuard.CACHE_SECONDS_SETTING, "0"), Map.of())), this.clock);
        one.admit("192.0.2.1", "https://a.example");
        assertThrows(ResolveGuard.Limited.class, () -> one.admit("192.0.2.1", "https://b.example"));
        assertThrows(SettingRefused.class, () -> ResolveGuard.fromSettings(Settings.of(catalogue,
                Sources.of(Map.of(ResolveGuard.CACHE_SECONDS_SETTING, "61"), Map.of())), this.clock));
        assertEquals(ResolveGuard.class, ResolveGuard.fromProcess(this.clock).getClass());
    }
}
