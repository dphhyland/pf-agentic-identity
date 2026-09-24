package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The deployment-wide federation settings. What matters here is that every reader gets the same
 * answer regardless of which component asked first - the defect this class replaced was three public
 * statics written as a constructor side effect, where initialisation order decided the trust anchor.
 */
class FederationRuntimeConfigTest {

    private static FederationRuntimeConfig of(Map<String, String> env, Map<String, String> props) {
        return FederationRuntimeConfig.from(env::get, props::get);
    }

    @Test
    void baseUrlDefaultsToTheHostWhenNotSeparatelyConfigured() {
        FederationRuntimeConfig c = of(Map.of(FederationRuntimeConfig.HOST_ENV, "https://anchor.example"), Map.of());

        assertEquals("https://anchor.example", c.trustControllerHost());
        assertEquals("https://anchor.example", c.trustControllerBaseUrl());
    }

    @Test
    void baseUrlMayCarryAContextPathDistinctFromTheIdentity() {
        FederationRuntimeConfig c = of(Map.of(
                FederationRuntimeConfig.HOST_ENV, "https://pf.example",
                FederationRuntimeConfig.BASE_URL_ENV, "https://pf.example/oidf"), Map.of());

        assertEquals("https://pf.example", c.trustControllerHost());
        assertEquals("https://pf.example/oidf", c.trustControllerBaseUrl(),
                "a PF serving federation under a context path needs these to differ - the old filter "
                        + "collapsed them by passing the bare host as both");
    }

    @Test
    void systemPropertyBeatsEnvironmentVariable() {
        FederationRuntimeConfig c = of(
                Map.of(FederationRuntimeConfig.HOST_ENV, "https://from-env.example"),
                Map.of("oidf.federation.trust.controller.host", "https://from-prop.example"));

        assertEquals("https://from-prop.example", c.trustControllerHost());
    }

    @Test
    void unconfiguredIsReportable() {
        FederationRuntimeConfig c = of(Map.of(), Map.of());

        assertFalse(c.isTrustControllerConfigured(),
                "callers log this once instead of failing every request with an unexplained rejection");
        assertEquals("", c.trustControllerHost());
        assertEquals("", c.trustControllerBaseUrl());
        assertFalse(c.ignoreSslErrors());
    }

    @Test
    void ignoreSslErrorsIsOffUnlessExplicitlyTrue() {
        assertFalse(of(Map.of(), Map.of()).ignoreSslErrors());
        assertFalse(of(Map.of(FederationRuntimeConfig.IGNORE_SSL_ENV, "no"), Map.of()).ignoreSslErrors());
        assertTrue(of(Map.of(FederationRuntimeConfig.IGNORE_SSL_ENV, "true"), Map.of()).ignoreSslErrors());
    }

    @Test
    void valuesAreTrimmedSoAStrayNewlineDoesNotBreakAnchorMatching() {
        FederationRuntimeConfig c = of(Map.of(FederationRuntimeConfig.HOST_ENV, "  https://anchor.example\n"), Map.of());

        assertEquals("https://anchor.example", c.trustControllerHost());
        assertTrue(c.isTrustControllerConfigured());
    }

    // ---- registration lifetime (OpenID Federation 1.0 §12.3) ---------------------------------------------

    @Test
    void registrationDefaultsAreADayAMinuteAndRefusal() {
        FederationRuntimeConfig.RegistrationSettings r = of(Map.of(), Map.of()).registration();

        assertEquals(FederationRuntimeConfig.RegistrationSettings.DEFAULTS, r);
        assertEquals(86_400L, r.maxTtlSeconds());
        assertEquals(60L, r.minTtlSeconds());
        assertEquals(300L, r.refreshBeforeExpirySeconds());
        assertEquals(FederationRuntimeConfig.ExpiryEnforcement.REFUSE, r.expiryEnforcement());
        assertEquals(300L, r.sweepIntervalSeconds());
        assertTrue(r.failClosed(), "a failed registration refuses the token request unless someone chose otherwise");
    }

    @Test
    void registrationSettingsComeFromTheEnvironmentOrSystemProperties() {
        FederationRuntimeConfig.RegistrationSettings r = of(Map.of(
                FederationRuntimeConfig.REGISTRATION_MAX_TTL_ENV, "3600",
                FederationRuntimeConfig.REGISTRATION_MIN_TTL_ENV, "30",
                FederationRuntimeConfig.REGISTRATION_EXPIRY_ENFORCEMENT_ENV, "Disable",
                FederationRuntimeConfig.AUTO_REGISTRATION_FAIL_CLOSED_ENV, "FALSE"), Map.of(
                "oidf.registration.refresh.before.expiry.seconds", "120",
                "oidf.registration.sweep.interval.seconds", "0")).registration();

        assertEquals(3600L, r.maxTtlSeconds());
        assertEquals(30L, r.minTtlSeconds());
        assertEquals(120L, r.refreshBeforeExpirySeconds());
        assertEquals(FederationRuntimeConfig.ExpiryEnforcement.DISABLE, r.expiryEnforcement());
        assertEquals(0L, r.sweepIntervalSeconds());
        assertFalse(r.failClosed());
    }

    @Test
    void aSettingThatIsNotWhatItShouldBeRefusesToStart() {
        assertRefused(Map.of(FederationRuntimeConfig.REGISTRATION_EXPIRY_ENFORCEMENT_ENV, "warn"),
                FederationRuntimeConfig.REGISTRATION_EXPIRY_ENFORCEMENT_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.REGISTRATION_MAX_TTL_ENV, "a day"), FederationRuntimeConfig.REGISTRATION_MAX_TTL_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.REGISTRATION_MIN_TTL_ENV, "100000"), FederationRuntimeConfig.REGISTRATION_MIN_TTL_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.REGISTRATION_SWEEP_INTERVAL_ENV, "-1"), FederationRuntimeConfig.REGISTRATION_SWEEP_INTERVAL_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.REGISTRATION_REFRESH_BEFORE_EXPIRY_ENV, "-5"),
                FederationRuntimeConfig.REGISTRATION_REFRESH_BEFORE_EXPIRY_ENV);
    }

    /** A typo in a security switch must not quietly mean "off": {@code yes} is refused, not read as false. */
    @Test
    void failClosedIsTrueOrFalseAndNothingElse() {
        assertRefused(Map.of(FederationRuntimeConfig.AUTO_REGISTRATION_FAIL_CLOSED_ENV, "yes"),
                FederationRuntimeConfig.AUTO_REGISTRATION_FAIL_CLOSED_ENV);
        assertTrue(of(Map.of(FederationRuntimeConfig.AUTO_REGISTRATION_FAIL_CLOSED_ENV, " True "), Map.of()).registration().failClosed());
    }

    private static void assertRefused(Map<String, String> env, String named) {
        IllegalStateException e = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () -> of(env, Map.of()));
        assertTrue(e.getMessage().contains(named), e.getMessage());
    }

    // ---- automatic registration at the front channel, and its limits ----------------------------------------

    @Test
    void autoRegistrationDefaultsAreOnPagedAndBounded() {
        FederationRuntimeConfig.AutoRegistrationSettings a = of(Map.of(), Map.of()).autoRegistration();

        assertEquals(FederationRuntimeConfig.AutoRegistrationSettings.DEFAULTS, a);
        assertTrue(a.frontChannel());
        assertTrue(a.pageOnAuthorizationError());
        assertTrue(a.allowEncryptedRequestObjects());
        assertEquals("openid", a.defaultScopes());
        assertFalse(a.requirePar());
        assertTrue(a.requirePkce());
        assertEquals(65_536, a.maxRequestObjectBytes());
        assertEquals(8, a.maxConcurrentResolutions());
        assertEquals(2_000L, a.lockWaitMillis());
        assertEquals(null, a.errorPage());
    }

    @Test
    void autoRegistrationSettingsComeFromTheEnvironmentOrSystemProperties() {
        FederationRuntimeConfig.AutoRegistrationSettings a = of(Map.of(
                FederationRuntimeConfig.AUTO_REGISTRATION_FRONT_CHANNEL_ENV, "false",
                FederationRuntimeConfig.AUTO_REGISTRATION_AUTHZ_ERROR_MODE_ENV, "Passthrough",
                FederationRuntimeConfig.AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS_ENV, "REFUSE",
                FederationRuntimeConfig.AUTO_REGISTRATION_DEFAULT_SCOPES_ENV, "openid profile",
                FederationRuntimeConfig.AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS_ENV, "2",
                FederationRuntimeConfig.FEDERATION_ERROR_PAGE_ENV, "/opt/error.html"), Map.of(
                "oidf.auto.registration.require.par", "true",
                "oidf.auto.registration.require.pkce", "false",
                "oidf.auto.registration.max.request.object.bytes", "1024",
                "oidf.auto.registration.lock.wait.ms", "0")).autoRegistration();

        assertFalse(a.frontChannel());
        assertFalse(a.pageOnAuthorizationError());
        assertFalse(a.allowEncryptedRequestObjects());
        assertEquals("openid profile", a.defaultScopes());
        assertTrue(a.requirePar());
        assertFalse(a.requirePkce());
        assertEquals(1024, a.maxRequestObjectBytes());
        assertEquals(2, a.maxConcurrentResolutions());
        assertEquals(0L, a.lockWaitMillis());
        assertEquals("/opt/error.html", a.errorPage());
        assertEquals("openid", new FederationRuntimeConfig.AutoRegistrationSettings(true, true, true, " ", false, true, 1, 1, 0L, null)
                .defaultScopes(), "blank scopes are the default");
    }

    @Test
    void anAutoRegistrationSettingThatIsNotWhatItShouldBeRefusesToStart() {
        assertRefused(Map.of(FederationRuntimeConfig.AUTO_REGISTRATION_AUTHZ_ERROR_MODE_ENV, "redirect"),
                FederationRuntimeConfig.AUTO_REGISTRATION_AUTHZ_ERROR_MODE_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS_ENV, "maybe"),
                FederationRuntimeConfig.AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.AUTO_REGISTRATION_FRONT_CHANNEL_ENV, "on"),
                FederationRuntimeConfig.AUTO_REGISTRATION_FRONT_CHANNEL_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS_ENV, "0"),
                FederationRuntimeConfig.AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES_ENV, "big"),
                FederationRuntimeConfig.AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.AUTO_REGISTRATION_LOCK_WAIT_MS_ENV, "-1"),
                FederationRuntimeConfig.AUTO_REGISTRATION_LOCK_WAIT_MS_ENV);
    }

    @Test
    void theDefaultValuesCanBeNamedOutright() {
        FederationRuntimeConfig.AutoRegistrationSettings a = of(Map.of(
                FederationRuntimeConfig.AUTO_REGISTRATION_AUTHZ_ERROR_MODE_ENV, "page",
                FederationRuntimeConfig.AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS_ENV, "allow"), Map.of()).autoRegistration();

        assertTrue(a.pageOnAuthorizationError());
        assertTrue(a.allowEncryptedRequestObjects());
    }
}
