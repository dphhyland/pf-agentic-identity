package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.Setting;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The validator's limits come from the federation-resolution catalogue, with the code's defaults and a range each. */
class ValidatorOptionsSettingsTest {
    private static final Catalogue CATALOGUE = Catalogue.load(ValidatorOptions.class.getClassLoader(), ValidatorOptions.COMPONENT);

    private static ValidatorOptions read(Map<String, String> env) {
        return ValidatorOptions.fromSettings(Settings.of(CATALOGUE, Sources.of(env::get, null, null)));
    }

    @Test
    void unsetSettingsGiveTheDefaultsTheCodeHadBefore() {
        ValidatorOptions options = read(Map.of());

        assertEquals(ValidatorOptions.DEFAULT_MAX_FETCHES, options.maxFetches());
        assertEquals(ValidatorOptions.DEFAULT_MAX_AUTHORITY_HINTS, options.maxAuthorityHints());
        assertEquals(ValidatorOptions.DEFAULT_MAX_ROUTE_ATTEMPTS, options.maxRouteAttempts());
        assertEquals(ValidatorOptions.DEFAULT_CLOCK_SKEW_SECONDS, options.clockSkewSeconds());
        assertEquals(ValidatorOptions.DEFAULT_RESOLUTION_WALL_CLOCK, options.resolutionWallClock());
        assertTrue(options.requirePeerChainSameAnchor());
        // This test process sets none of them, so the process's defaults are the catalogue's.
        assertEquals(options, ValidatorOptions.defaults().withClock(options.clock()));
    }

    @Test
    void eachSettingIsRead() {
        ValidatorOptions options = read(Map.of(
                ValidatorOptions.MAX_REQUESTS_SETTING, "40",
                ValidatorOptions.MAX_AUTHORITY_HINTS_SETTING, "3",
                ValidatorOptions.MAX_ROUTE_ATTEMPTS_SETTING, "2",
                ValidatorOptions.CLOCK_SKEW_SETTING, "5",
                ValidatorOptions.WALL_CLOCK_SETTING, "12"));

        assertEquals(40, options.maxFetches());
        assertEquals(3, options.maxAuthorityHints());
        assertEquals(2, options.maxRouteAttempts());
        assertEquals(5, options.clockSkewSeconds());
        assertEquals(Duration.ofSeconds(12), options.resolutionWallClock());
    }

    /** Every setting has a range; each end is accepted and one past it refused, naming the setting. */
    @Test
    void eachSettingIsHeldToItsRange() {
        List<String> names = List.of(ValidatorOptions.MAX_REQUESTS_SETTING, ValidatorOptions.MAX_AUTHORITY_HINTS_SETTING,
                ValidatorOptions.MAX_ROUTE_ATTEMPTS_SETTING, ValidatorOptions.CLOCK_SKEW_SETTING, ValidatorOptions.WALL_CLOCK_SETTING);
        assertEquals(names.size(), CATALOGUE.settings().size(), "the catalogue holds these settings and no others");
        for (String name : names) {
            Setting setting = CATALOGUE.setting(name);
            assertTrue(setting.min() != null && setting.max() != null, name + " has a range");
            read(Map.of(name, String.valueOf(setting.min())));
            read(Map.of(name, String.valueOf(setting.max())));
            for (String wrong : List.of(String.valueOf(setting.min() - 1), String.valueOf(setting.max() + 1), "ten")) {
                SettingRefused refused = assertThrows(SettingRefused.class, () -> read(Map.of(name, wrong)), name + "=" + wrong);
                assertEquals(name, refused.setting());
            }
        }
    }

    @Test
    void theWallClockMustBePositive() {
        ValidatorOptions defaults = read(Map.of());
        assertThrows(IllegalArgumentException.class, () -> defaults.withResolutionWallClock(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> defaults.withResolutionWallClock(Duration.ofSeconds(-1)));
        assertThrows(NullPointerException.class, () -> defaults.withResolutionWallClock(null));
        assertEquals(Duration.ofMillis(1500), defaults.withResolutionWallClock(Duration.ofMillis(1500)).resolutionWallClock());
    }
}
