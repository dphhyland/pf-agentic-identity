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
        assertTrue(of(Map.of(FederationRuntimeConfig.IGNORE_SSL_ENV, "true"), Map.of()).ignoreSslErrors());
        // Strict from 0.6.0 (plan item ST-5): the reader before read anything but true as false; now anything but true or
        // false is refused, naming it - and under development a legacy spelling is read as it was, false, with a warning.
        assertRefused(Map.of(FederationRuntimeConfig.IGNORE_SSL_ENV, "no"), FederationRuntimeConfig.IGNORE_SSL_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.IGNORE_SSL_ENV, "sometimes", "OIDF_DEPLOYMENT_PROFILE", "development"),
                FederationRuntimeConfig.IGNORE_SSL_ENV);
        FederationRuntimeConfig legacy = of(Map.of(FederationRuntimeConfig.IGNORE_SSL_ENV, "yes", "OIDF_DEPLOYMENT_PROFILE", "development"), Map.of());
        assertFalse(legacy.ignoreSslErrors());
        assertTrue(legacy.deprecationWarnings().get(0).contains("a spelling only the reader before 0.6.0 took"), legacy.deprecationWarnings().toString());
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

    /** The switches that guard something are true or false as well: a typo stops the deployment, never switches one off. */
    @Test
    void theGuardingSwitchesAreTrueOrFalseAndNothingElse() {
        for (String guard : java.util.List.of(FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV,
                FederationRuntimeConfig.REQUIRE_ATTESTER_BINDING_ENV)) {
            assertRefused(Map.of(guard, "yes"), guard);
            assertRefused(Map.of(guard, "1"), guard);
        }
        // OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY is OIDF_ATTESTATION_AUTH_ENABLED's superseded name (S9A): refused under the
        // switch's name, whichever name held the value.
        assertRefused(Map.of(FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV, "yes"), "OIDF_ATTESTATION_AUTH_ENABLED");
        assertRefused(Map.of(FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV, "1"), "OIDF_ATTESTATION_AUTH_ENABLED");
        FederationRuntimeConfig off = of(Map.of(FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV, " False ",
                FederationRuntimeConfig.REQUIRE_BRIDGE_KEY_ENV, "false", FederationRuntimeConfig.REQUIRE_ATTESTER_BINDING_ENV, "FALSE"), Map.of());
        assertFalse(off.requireMetadataPolicy());
        assertFalse(off.requireBridgeKey());
        assertFalse(off.requireAttesterBinding());
        FederationRuntimeConfig unset = of(Map.of(FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV, " "), Map.of());
        assertTrue(unset.requireMetadataPolicy(), "blank is the default: on");
        assertTrue(unset.requireBridgeKey());
        assertTrue(unset.requireAttesterBinding());
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
        assertEquals(Map.of("max_path_length", java.math.BigDecimal.ZERO), config.subordinateConstraints(),
                "a number is the BigDecimal platform.json reads; it was the Integer Jackson read until ST-1");
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

    // ---- the JSON settings: platform.json in place of Jackson (plan item ST-1) ------------------------------

    /** The read FederationRuntimeConfig made until ST-1, kept here to compare against. */
    private static Object jacksonRead(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readValue(json,
                    new com.fasterxml.jackson.core.type.TypeReference<java.util.LinkedHashMap<String, Object>>() {});
        } catch (Exception e) {
            return REFUSED;
        }
    }

    private static final Object REFUSED = new Object();

    private static Object platformRead(String json) {
        try {
            return com.pingidentity.ps.oidf.platform.settings.Parsers.jsonObject(json);
        } catch (IllegalArgumentException e) {
            assertEquals("not a JSON object", e.getMessage());
            return REFUSED;
        }
    }

    /** Both reads, compared by value: the same members in the same order, and numbers equal as decimals, as MetadataPolicy compares them. */
    private static void assertSameValue(String json) {
        Object before = jacksonRead(json);
        Object after = platformRead(json);
        org.junit.jupiter.api.Assertions.assertNotSame(REFUSED, before, json);
        org.junit.jupiter.api.Assertions.assertNotSame(REFUSED, after, json);
        assertTrue(sameValue(before, after), json + ": " + before + " against " + after);
    }

    private static boolean sameValue(Object a, Object b) {
        if (a instanceof Map<?, ?> x && b instanceof Map<?, ?> y) {
            if (!java.util.List.copyOf(x.keySet()).equals(java.util.List.copyOf(y.keySet()))) {
                return false;
            }
            return x.keySet().stream().allMatch(k -> sameValue(x.get(k), y.get(k)));
        }
        if (a instanceof java.util.List<?> x && b instanceof java.util.List<?> y) {
            return x.size() == y.size() && java.util.stream.IntStream.range(0, x.size()).allMatch(i -> sameValue(x.get(i), y.get(i)));
        }
        if (a instanceof Number x && b instanceof Number y) {
            return new java.math.BigDecimal(x.toString()).compareTo(new java.math.BigDecimal(y.toString())) == 0;
        }
        return java.util.Objects.equals(a, b);
    }

    private static String nested(int depth) {
        return "{\"a\":" + "[".repeat(depth - 1) + "]".repeat(depth - 1) + "}";
    }

    @Test
    void theJsonSettingsReadTheValuesJacksonRead() {
        for (String json : java.util.List.of(
                "{}",
                "{\"oauth_client\": {\"scope\": {\"subset_of\": [\"read\"]}}}",
                "{\"max_path_length\": 0}",
                "{\"max_path_length\": -1}",
                "{\"oauth_client\": {\"scope\": {\"value\": \"a\", \"one_of\": [\"b\"]}}}",
                "{\"n\": 12345678901234567890, \"m\": 2147483648, \"z\": -0}",
                "{\"n\": " + "9".repeat(123) + "}",
                "{\"n\": 1E3, \"m\": 1.5e1, \"f\": 1.0, \"e\": 2.5e-3}",
                "{\"s\": \"caf\\u00e9 \\ud83d\\ude00\", \"t\": true, \"u\": null}",
                nested(32))) {
            assertSameValue(json);
        }
    }

    @Test
    void theJsonSettingsRefuseWhatJacksonRefused() {
        for (String json : java.util.List.of("[]", "\"text\"", "5", "true", "{'a': 1}", "{\"a\": NaN}", "{\"a\": 01}", "{\"a\": 1,}",
                "// comment\n{}", "{\"a\": \"x\u0001\"}", "{\"n\": " + "9".repeat(1001) + "}", "{")) {
            org.junit.jupiter.api.Assertions.assertSame(REFUSED, jacksonRead(json), json);
            org.junit.jupiter.api.Assertions.assertSame(REFUSED, platformRead(json), json);
        }
        for (String unset : new String[] {null, "", " ", "null", " null "}) {
            assertEquals(null, jacksonRead(unset));
            assertEquals(null, platformRead(unset), "unset, blank and the literal null all read as unset, as they did");
        }
        // Through platform.settings (plan item ST-5) the literal null is a value that is not a JSON object, and refused, naming
        // the setting; unset and blank are still unset.
        assertRefused(Map.of(FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV, "null"), FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV);
        assertRefused(Map.of(FederationRuntimeConfig.SUBORDINATE_CONSTRAINTS_ENV, "null"), FederationRuntimeConfig.SUBORDINATE_CONSTRAINTS_ENV);
        assertEquals(Map.of(), of(Map.of(FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV, " "), Map.of()).authorityMetadataPolicy());
        assertEquals(null, of(Map.of(FederationRuntimeConfig.SUBORDINATE_CONSTRAINTS_ENV, " "), Map.of()).subordinateConstraints());
    }

    /**
     * What Jackson let through and platform.json refuses. Each stops PingFederate starting, naming the setting, where
     * Jackson read something: the last of two members of one name, the first of two documents, a nesting or a number
     * past platform.json's limits, a string holding half a surrogate pair. The release note lists them.
     */
    @Test
    void theJsonSettingsRefuseWhatJacksonLetThrough() {
        for (String json : java.util.List.of(
                "{\"max_path_length\": 5, \"max_path_length\": 0}",
                "{\"max_path_length\": 0} {\"max_path_length\": 5}",
                "{\"max_path_length\": 0} trailing",
                nested(33),
                nested(600),
                "{\"n\": " + "9".repeat(129) + "}",
                "{\"s\": \"\\ud800\"}")) {
            org.junit.jupiter.api.Assertions.assertNotSame(REFUSED, jacksonRead(json), json);
            org.junit.jupiter.api.Assertions.assertSame(REFUSED, platformRead(json), json);
            IllegalStateException e = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> of(Map.of(FederationRuntimeConfig.SUBORDINATE_CONSTRAINTS_ENV, json), Map.of()));
            assertEquals(FederationRuntimeConfig.SUBORDINATE_CONSTRAINTS_ENV + ": not a JSON object", e.getMessage());
        }
        assertEquals(FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV + ": not a JSON object", org.junit.jupiter.api.Assertions.assertThrows(
                IllegalStateException.class, () -> of(Map.of(FederationRuntimeConfig.AUTHORITY_METADATA_POLICY_ENV,
                        "{\"oauth_client\": {}, \"oauth_client\": {\"scope\": {\"value\": \"x\"}}}"), Map.of())).getMessage());
    }

    /** An exponent past a double's range: Jackson read Infinity, platform.json the exact number; the constraint checks the same. */
    @Test
    void anExponentPastADoubleIsKeptExactly() {
        String json = "{\"max_path_length\": 1e400}";
        assertEquals(Double.POSITIVE_INFINITY, ((Map<?, ?>) jacksonRead(json)).get("max_path_length"));
        assertEquals(new java.math.BigDecimal("1E+400"), ((Map<?, ?>) platformRead(json)).get("max_path_length"));
        com.pingidentity.ps.oidf.federation.Constraints.requireValid(jacksonRead(json));
        assertEquals(new java.math.BigDecimal("1E+400"), of(Map.of(FederationRuntimeConfig.SUBORDINATE_CONSTRAINTS_ENV, json), Map.of())
                .subordinateConstraints().get("max_path_length"), "accepted by the same check as before");
    }
}
