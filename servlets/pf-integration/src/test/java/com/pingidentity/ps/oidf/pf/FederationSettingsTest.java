/*
 * Plan item ST-5 for federation: every reader of a federation variable reads one catalogue entry, strictly.
 */
package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.federation.FederationConfiguration;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogues;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The federation settings as ST5F reads them: {@code OIDF_FEDERATION_IGNORE_SSL_ERRORS} one Setting for the federation
 * servlet and the runtime configuration (F-0197), the automatic-registration limits read as ints within their range
 * (F-0198), strict parsing with the development escape, where each value came from, and which components an unknown
 * name under the federation families refuses.
 */
class FederationSettingsTest {

    private static final String DEV = "OIDF_DEPLOYMENT_PROFILE";

    private static Sources sources(Map<String, String> env, Map<String, String> props) {
        return Sources.of(env::get, props::get, null);
    }

    /** What each reader makes of these sources: its value, or the class of what it refused with. */
    private static Object servlet(Sources sources) {
        try {
            return FederationConfiguration.ignoreSslErrors(sources);
        } catch (SettingRefused e) {
            return e.getClass();
        }
    }

    private static Object runtime(Sources sources) {
        try {
            return FederationRuntimeConfig.from(sources).ignoreSslErrors();
        } catch (SettingRefused e) {
            return e.getClass();
        }
    }

    /**
     * F-0197's acceptance test: one table of environments and system properties, and both readers of the switch give the
     * same answer for every row - the system property before the environment variable, the superseded name only when
     * neither is set and refused when it disagrees, strict in production, the legacy spelling read in development.
     */
    @Test
    void theServletAndTheRuntimeReadTheSwitchTheSameWay() {
        String prop = "oidf.federation.ignore.ssl.errors";
        String env = FederationRuntimeConfig.IGNORE_SSL_ENV;
        String oldEnv = FederationRuntimeConfig.DEPRECATED_IGNORE_SSL_ENV;
        String oldProp = "oidf.trust.controller.ignore.ssl";
        record Row(String why, Map<String, String> env, Map<String, String> props, Object expected) {
        }
        List<Row> table = List.of(
                new Row("unset", Map.of(), Map.of(), false),
                new Row("the environment", Map.of(env, "true"), Map.of(), true),
                new Row("the system property alone - the servlet ignored it before 0.6.0", Map.of(), Map.of(prop, "true"), true),
                new Row("the property before the environment", Map.of(env, "true"), Map.of(prop, "false"), false),
                new Row("the superseded name alone - the servlet ignored it before 0.6.0", Map.of(oldEnv, "TRUE"), Map.of(), true),
                new Row("the superseded property", Map.of(), Map.of(oldProp, "true"), true),
                new Row("the superseded name agreeing", Map.of(env, "true", oldEnv, "true"), Map.of(), true),
                new Row("the superseded name disagreeing", Map.of(env, "false", oldEnv, "true"), Map.of(), SettingRefused.class),
                new Row("not a switch", Map.of(env, "maybe"), Map.of(), SettingRefused.class),
                new Row("a legacy spelling in production", Map.of(env, "yes"), Map.of(), SettingRefused.class),
                new Row("a legacy spelling in development", Map.of(env, "yes", DEV, "development"), Map.of(), false),
                new Row("padded", Map.of(env, " TRUE "), Map.of(), true));
        for (Row row : table) {
            Sources sources = sources(row.env(), row.props());
            assertEquals(row.expected(), servlet(sources), row.why() + " (the servlet)");
            assertEquals(row.expected(), runtime(sources), row.why() + " (the runtime)");
        }
    }

    /** The servlet alone has init-params, read first; the runtime has none, so a deployment sets the switch once, in the environment. */
    @Test
    void onlyTheServletHasAnInitParam() {
        Map<String, String> env = Map.of(DEV, "development", FederationRuntimeConfig.IGNORE_SSL_ENV, "false");
        Sources withInitParam = Sources.of(env::get, name -> null, Map.of("ignoreSslErrors", "true")::get);
        assertTrue(FederationConfiguration.ignoreSslErrors(withInitParam));
        // The runtime reads the process (get()), which has no init-params: the same entry, without its first source.
        FederationRuntimeConfig runtime = FederationRuntimeConfig.from(sources(env, Map.of()));
        assertFalse(runtime.ignoreSslErrors());
        assertTrue(runtime.provenance().contains("OIDF_FEDERATION_IGNORE_SSL_ERRORS from env OIDF_FEDERATION_IGNORE_SSL_ERRORS"),
                runtime.provenance().toString());
    }

    /**
     * F-0198: the two limits are ints within the catalogue's range, 1 to 2147483647; a number past an int is refused,
     * never wrapped - 4294967297 was read as 1 before 0.6.0, and accepted.
     */
    @Test
    void theAutoRegistrationLimitsAreIntsInTheirRange() {
        for (String name : List.of(FederationRuntimeConfig.AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES_ENV,
                FederationRuntimeConfig.AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS_ENV)) {
            Function<String, Integer> read = value -> {
                FederationRuntimeConfig.AutoRegistrationSettings a = FederationRuntimeConfig.from(sources(Map.of(name, value), Map.of()))
                        .autoRegistration();
                return name.equals(FederationRuntimeConfig.AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES_ENV) ? a.maxRequestObjectBytes()
                        : a.maxConcurrentResolutions();
            };
            assertEquals(1, read.apply("1"), name);
            assertEquals(Integer.MAX_VALUE, read.apply("2147483647"), name);
            for (String wrong : List.of("0", "-1", "2147483648", "4294967297", "9223372036854775808", "8 KiB")) {
                SettingRefused refused = assertThrows(SettingRefused.class, () -> read.apply(wrong), name + " " + wrong);
                assertEquals(name, refused.setting(), wrong);
            }
        }
    }

    /** Every boolean the runtime reads is strict in production, and reads a legacy spelling as false in development, with a warning. */
    @Test
    void theRuntimeSwitchesAreStrictWithTheDevelopmentEscape() {
        for (String name : List.of(FederationRuntimeConfig.TRUST_MARK_STATUS_CHECK_ENV, FederationRuntimeConfig.HISTORICAL_KEYS_ENV,
                FederationRuntimeConfig.PDP_DISCOVER_ENV, FederationRuntimeConfig.PDP_SURFACE_USER_REASON_ENV,
                FederationRuntimeConfig.AUTO_REGISTRATION_FRONT_CHANNEL_ENV, FederationRuntimeConfig.AUTO_REGISTRATION_REQUIRE_PAR_ENV)) {
            assertEquals(name, assertThrows(SettingRefused.class, () -> FederationRuntimeConfig.from(sources(Map.of(name, "on"),
                    Map.of()))).setting());
            FederationRuntimeConfig development = FederationRuntimeConfig.from(sources(Map.of(name, "on", DEV, "development"), Map.of()));
            assertTrue(development.deprecationWarnings().stream().anyMatch(w -> w.startsWith(name + " is 'on'")), name);
        }
    }

    /**
     * The banner's provenance: each setting that is set, with the source and the name that supplied it, a superseded name
     * and a secret's file included, and never a value.
     */
    @Test
    void theProvenanceNamesEachSourceAndNeverAValue(@TempDir Path dir) throws Exception {
        Path token = Files.writeString(dir.resolve("pdp-token"), "s3cr3t-token\n");
        Map<String, String> env = new HashMap<>();
        env.put(FederationRuntimeConfig.DEPRECATED_HOST_ENV, "https://anchor.example");
        env.put(FederationRuntimeConfig.PDP_AUTH_TOKEN_ENV + "_FILE", token.toString());
        FederationRuntimeConfig config = FederationRuntimeConfig.from(sources(env, Map.of("oidf.pdp.mode", "local")));

        assertEquals("s3cr3t-token", config.pdp().authToken());
        assertEquals(List.of("OIDF_FEDERATION_TRUST_CONTROLLER_HOST from env OIDF_TRUST_CONTROLLER_HOST",
                "OIDF_PDP_AUTH_TOKEN from env OIDF_PDP_AUTH_TOKEN_FILE (" + token + ")",
                "OIDF_PDP_MODE from system-property oidf.pdp.mode"), config.provenance(), "in the order they are read");
        assertFalse(config.provenance().toString().contains("s3cr3t"));
        assertTrue(FederationRuntimeConfig.from(sources(Map.of(), Map.of())).provenance().isEmpty());
    }

    /** OIDF_FETCH_ALLOW_HTTP is oidf-jose's entry, read by the runtime for a plaintext development PDP. */
    @Test
    void aPlaintextPdpNeedsTheFetchSwitchReadStrictly() {
        Map<String, String> env = new HashMap<>(Map.of(FederationRuntimeConfig.PDP_URL_ENV, "http://pdp.internal"));
        assertEquals(FederationRuntimeConfig.PDP_URL_ENV, assertThrows(SettingRefused.class,
                () -> FederationRuntimeConfig.from(sources(env, Map.of()))).setting());
        env.put("OIDF_FETCH_ALLOW_HTTP", "yes");
        assertEquals("OIDF_FETCH_ALLOW_HTTP", assertThrows(SettingRefused.class,
                () -> FederationRuntimeConfig.from(sources(env, Map.of()))).setting());
        env.put("OIDF_FETCH_ALLOW_HTTP", "true");
        assertEquals("http://pdp.internal", FederationRuntimeConfig.from(sources(env, Map.of())).pdp().url());
    }

    /**
     * Decision 5: an unknown name under a federation family refuses the components of the catalogues that own the family,
     * and no other: {@code OIDF_FEDERATION_*} (federation-runtime and federation-entity), {@code OIDF_AUTO_REGISTRATION_*}
     * and the rest of federation-runtime's families. SSF, the attestation issuer and the operator API are never refused
     * for one.
     */
    @Test
    void anUnknownFederationNameRefusesTheFederationComponentsOnly() {
        Catalogues.Loaded catalogues = Catalogues.onClassPath(FederationSettingsTest.class.getClassLoader());
        Map<String, Set<String>> expected = Map.of(
                "OIDF_FEDERATION_TRUST_ANCHOR", Set.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH", "HOSTING"),
                "OIDF_AUTO_REGISTRATION_MAX_BYTES", Set.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH"),
                "OIDF_REGISTRATION_MAX_TTL", Set.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH"),
                "OIDF_PDP_URI", Set.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH"),
                "OIDF_BRIDGE_SIGNING_KEY", Set.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH"),
                "OIDF_FAPI2_CLIENT", Set.of("FAPI"),
                "OIDF_AUTHORITY_ENTITYID", Set.of("HOSTING", "OPERATOR_API"),
                "OIDF_FETCH_ALLOW_HTTPS", Set.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH", "ATTESTATION_ISSUER", "HOSTING"));
        for (Map.Entry<String, Set<String>> name : expected.entrySet()) {
            ProfileAudit.Result result = ProfileAudit.evaluate(Sources.of(Map.of(name.getKey(), "x"), Map.of()), catalogues,
                    DeploymentProfile.PRODUCTION, AcceptedRisks.none());
            List<ProfileAudit.Violation> unknown = result.violations().stream().filter(v -> v.kind() == ProfileAudit.Kind.UNKNOWN_KEY)
                    .toList();
            assertEquals(1, unknown.size(), name.getKey() + ": " + result.violations());
            assertEquals(name.getValue(), Set.copyOf(unknown.get(0).components()), name.getKey());
        }
    }
}
