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

    // ---- Trust Marks ---------------------------------------------------------------------------------------

    @Test
    void noTrustMarkIsRequiredAndNoStatusCheckedUnlessConfigured() {
        FederationRuntimeConfig config = of(Map.of(), Map.of());

        assertTrue(config.requiredTrustMarks().isEmpty());
        assertFalse(config.trustMarkStatusCheck());
    }

    @Test
    void requiredTrustMarksAndTheStatusCheckComeFromTheEnvironmentOrSystemProperties() {
        FederationRuntimeConfig config = of(Map.of(FederationRuntimeConfig.REQUIRED_TRUST_MARKS_ENV,
                "{\"*\": [\"https://ta.example.com/marks/certified\"]}"), Map.of("oidf.federation.trust.mark.status.check", "true"));

        assertEquals(java.util.List.of("https://ta.example.com/marks/certified"), config.requiredTrustMarks().requiredFor("oauth_client"));
        assertTrue(config.trustMarkStatusCheck());
    }

    /** A requirement the operator mistyped must stop the deployment, not register everyone without it. */
    @Test
    void aTrustMarkSettingThatIsNotWhatItShouldBeRefusesToStart() {
        assertRefused(Map.of(FederationRuntimeConfig.REQUIRED_TRUST_MARKS_ENV, "[\"https://ta.example.com/marks/certified\"]"),
                FederationRuntimeConfig.REQUIRED_TRUST_MARKS_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.TRUST_MARK_STATUS_CHECK_ENV, "yes"), FederationRuntimeConfig.TRUST_MARK_STATUS_CHECK_ENV);
    }

    @Test
    void thisEntityIssuesAndPublishesNoTrustMarksUnlessConfigured() {
        assertEquals(FederationRuntimeConfig.TrustMarkIssuingSettings.NONE, of(Map.of(), Map.of()).trustMarkIssuing());
    }

    @Test
    void theTrustMarkIssuingSettingsComeFromTheEnvironmentOrSystemProperties() {
        String mark = com.pingidentity.ps.oidf.federation.testkit.Statements.spec("trust-mark+jwt").claim("iss", "https://tmi.example")
                .claim("sub", "https://pf.example").claim("trust_mark_type", "https://tmi.example/marks/audited")
                .sign(com.pingidentity.ps.oidf.federation.testkit.Keys.ec("tmi-1"), java.time.Clock.systemUTC());
        String ownerJwks = org.jose4j.json.JsonUtil.toJson(com.pingidentity.ps.oidf.federation.testkit.Keys.publicJwks(
                com.pingidentity.ps.oidf.federation.testkit.Keys.ec("owner-1")));
        FederationRuntimeConfig.TrustMarkIssuingSettings settings = of(Map.of(
                FederationRuntimeConfig.TRUST_MARK_TYPES_ENV, "{\"https://pf.example/marks/open\": {\"subjects\": \"any\"}}",
                FederationRuntimeConfig.TRUST_MARKS_ENV, "[{\"trust_mark_type\": \"https://tmi.example/marks/audited\", \"trust_mark\": \"" + mark + "\"}]"),
                Map.of("oidf.federation.trust.mark.issuers", "{\"https://tmi.example/marks/audited\": [\"https://tmi.example\"]}",
                        "oidf.federation.trust.mark.owners", "{\"https://owner.example/marks/owned\": {\"sub\": \"https://owner.example\", \"jwks\": "
                                + ownerJwks + "}}")).trustMarkIssuing();

        assertEquals(java.util.List.of("https://pf.example/marks/open"), java.util.List.copyOf(settings.types().keySet()));
        assertEquals(mark, settings.carried().get(0).get("trust_mark"));
        assertEquals(java.util.List.of("https://tmi.example"), settings.issuers().get("https://tmi.example/marks/audited"));
        assertTrue(settings.owners().containsKey("https://owner.example/marks/owned"));
    }

    /** A Trust Mark setting the operator got wrong stops the deployment, naming the setting. */
    @Test
    void aTrustMarkIssuingSettingThatIsNotWhatItShouldBeRefusesToStart() {
        assertRefused(Map.of(FederationRuntimeConfig.TRUST_MARK_TYPES_ENV, "[]"), FederationRuntimeConfig.TRUST_MARK_TYPES_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.TRUST_MARKS_ENV, "{}"), FederationRuntimeConfig.TRUST_MARKS_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.TRUST_MARK_ISSUERS_ENV, "[]"), FederationRuntimeConfig.TRUST_MARK_ISSUERS_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.TRUST_MARK_OWNERS_ENV, "[]"), FederationRuntimeConfig.TRUST_MARK_OWNERS_ENV);
    }

    @Test
    void noKeyHistoryIsKeptUnlessAskedForAndARetiredKeyStaysValidForADay() {
        assertEquals(FederationRuntimeConfig.KeyHistorySettings.DEFAULTS, of(Map.of(), Map.of()).keyHistory());
        FederationRuntimeConfig.KeyHistorySettings on = of(Map.of(FederationRuntimeConfig.HISTORICAL_KEYS_ENV, "true"),
                Map.of("oidf.federation.key.history.grace.seconds", "3600")).keyHistory();
        assertTrue(on.enabled());
        assertEquals(3600L, on.graceSeconds());
        assertRefused(Map.of(FederationRuntimeConfig.HISTORICAL_KEYS_ENV, "yes"), FederationRuntimeConfig.HISTORICAL_KEYS_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.KEY_HISTORY_GRACE_ENV, "-1"), FederationRuntimeConfig.KEY_HISTORY_GRACE_ENV);
    }

    @Test
    void theDomainDefaultPolicyAndTheSubordinateConstraintsAreCheckedAtStartUp() {
        FederationRuntimeConfig config = of(Map.of(FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV,
                "{\"oauth_client\": {\"scope\": {\"subset_of\": [\"read\"]}}}"),
                Map.of("oidf.federation.subordinate.constraints", "{\"max_path_length\": 0}"));

        assertEquals(java.util.List.of("oauth_client"), java.util.List.copyOf(config.authorityMetadataPolicy().keySet()));
        assertEquals(Map.of("max_path_length", 0), config.subordinateConstraints());
        assertEquals(Map.of(), of(Map.of(), Map.of()).authorityMetadataPolicy());
        assertEquals(Map.of(), of(Map.of(FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV, " "), Map.of()).authorityMetadataPolicy());
        assertEquals(null, of(Map.of(), Map.of()).subordinateConstraints());
        assertRefused(Map.of(FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV, "[]"), FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV, "{\"oauth_client\": 1}"),
                FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV, "{\"oauth_client\": {\"scope\": {\"value\": \"a\", \"one_of\": [\"b\"]}}}"),
                FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.SUBORDINATE_CONSTRAINTS_ENV, "{\"max_path_length\": -1}"),
                FederationRuntimeConfig.SUBORDINATE_CONSTRAINTS_ENV);
    }
}
