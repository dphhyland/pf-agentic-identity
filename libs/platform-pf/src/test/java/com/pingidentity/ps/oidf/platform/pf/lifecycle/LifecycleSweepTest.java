/*
 * The listener's sweep: evaluated once before any init, published for Startup, logged once, listed in the banner and
 * audited per violation; the engine's copy, evaluating for itself, gives the same answer.
 */
package com.pingidentity.ps.oidf.platform.pf.lifecycle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.net.URL;
import java.net.URLClassLoader;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LifecycleSweepTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 9, 30);
    static final List<String> EVERY = List.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH", "ATTESTATION_ISSUER", "HOSTING",
            "SSF", "SSF_RECEIVER", "OPERATOR_API", "FAPI");

    private final List<Event> emitted = new ArrayList<>();

    @BeforeEach
    void capture() {
        ProfileRefusals.resetForTests();
        Events.reset();
        Events.configure(this.emitted::add);
    }

    @AfterEach
    void forget() {
        ProfileRefusals.resetForTests();
        Events.reset();
    }

    private static LifecycleListener listener(Map<String, String> env, Map<String, String> properties) {
        Map<String, String> all = new HashMap<>(env);
        return new LifecycleListener(all::get, Sources.of(all, properties), () -> TODAY, LifecycleListener.class.getClassLoader());
    }

    @Test
    void aForbiddenSwitchInProductionRefusesItsComponentBeforeAnyInitAndIsAuditedOnce() {
        LifecycleListener listener = listener(Map.of("OIDF_OPERATOR_INSECURE_TLS", "true"), Map.of());
        ProfileAudit.Result result = listener.sweep("/ (pf-runtime)");
        assertTrue(result.refuses());
        assertSame(result, ProfileRefusals.current(), "published for Startup");
        ProfileAudit.Violation v = result.violations().stream().filter(x -> x.setting().equals("OIDF_OPERATOR_INSECURE_TLS"))
                .findFirst().orElseThrow();
        assertEquals(List.of("OPERATOR_API"), v.components());
        ComponentParts.Part part = Startup.begin(Startup.OPERATOR_API, "LifecycleSweepTestPart");
        assertEquals(ComponentState.REFUSED, part.status().state());
        assertTrue(part.status().reason().startsWith("refused by the production profile: OIDF_OPERATOR_INSECURE_TLS=true"),
                part.status().reason());
        leave(part);
        assertThrows(ProfileRefused.class, () -> ProfileRefusals.refuse("SSF", "the stream store is in memory"));

        String banner = listener.audit("/ (pf-runtime)").orElseThrow();
        assertTrue(banner.contains(" ".repeat(18) + "REFUSED: OIDF_OPERATOR_INSECURE_TLS=true, which the production profile forbids"),
                banner);
        assertTrue(banner.contains("  violations:     not refused (not switched on): OIDF_OPERATOR_AUDIENCE is unset"), banner);
        assertTrue(banner.contains("  code refusals:  REFUSED: SSF: the stream store is in memory"), banner);
        List<Event> refused = this.emitted.stream().filter(e -> e.code().equals(LifecycleListener.PROFILE_REFUSED)).toList();
        long refusing = result.violations().stream().filter(LifecycleListener.refusing(result)).count();
        assertTrue(refusing < result.violations().size(), "the operator API's required settings refuse nothing unswitched");
        assertEquals(refusing + 1, refused.size(), "one event per violation that refuses, the sweep's and the code's");
        Event first = refused.get(0);
        assertTrue(first.audit());
        assertTrue(first.isFailure());
        assertEquals("platform", first.component());
        assertTrue(refused.stream().anyMatch(e -> e.fields().equals(Map.of("setting", "OIDF_OPERATOR_INSECURE_TLS",
                "violation", "FORBIDDEN", "components", "OPERATOR_API"))), refused.toString());
    }

    @Test
    void theJvmHostnameFlagRefusesEveryComponentWhateverItsValue() {
        for (String value : List.of("", "true", "false")) {
            ProfileAudit.Result result = listener(Map.of(), Map.of("jdk.internal.httpclient.disableHostnameVerification", value))
                    .sweep("/");
            ProfileAudit.Violation v = result.violations().stream()
                    .filter(x -> x.setting().equals("jdk.internal.httpclient.disableHostnameVerification")).findFirst().orElseThrow();
            assertEquals(EVERY, v.components(), value);
            for (String component : EVERY) {
                assertTrue(ProfileRefusals.refused(component, false), component + " with the flag '" + value + "'");
            }
        }
    }

    @Test
    void developmentRefusesNothingAndSaysWhatProductionWould() {
        ProfileAudit.Result result = listener(Map.of("OIDF_DEPLOYMENT_PROFILE", "development", "OIDF_OPERATOR_INSECURE_TLS", "true"),
                Map.of()).sweep("/");
        assertFalse(result.refuses());
        assertFalse(ProfileRefusals.refused("OPERATOR_API", true));
        String log = LifecycleListener.sweepLog("/", result, LifecycleListener.refusing(result));
        assertTrue(log.startsWith("Deployment profile development for / - " + result.violations().size() + " violation(s) the"
                + " production profile would refuse; the development profile refuses nothing:"), log);
        assertTrue(log.contains(System.lineSeparator() + "  not refused (development): OIDF_OPERATOR_INSECURE_TLS=true"), log);
        ComponentParts.Part part = Startup.begin(Startup.OPERATOR_API, "LifecycleSweepTestPart");
        assertEquals(ComponentState.STARTING, part.status().state());
        leave(part);
    }

    /**
     * Takes a part this test registered in the process-wide registry out of readiness: disabled, it no longer counts, so
     * a health test that runs after this one in the same JVM reads the components it registered itself.
     */
    private static void leave(ComponentParts.Part part) {
        assertTrue(part.disabled());
    }

    @Test
    void theSweepsLogSaysNothingForAQuietDeploymentAndListsWarningsAlone() {
        assertNull(LifecycleListener.sweepLog("/", ProfileAudit.Result.empty(DeploymentProfile.PRODUCTION), v -> true));
        String warnings = LifecycleListener.sweepLog("/", new ProfileAudit.Result(DeploymentProfile.PRODUCTION, List.of(),
                List.of("OIDF_ELSEWHERE is set\nand forged")), v -> true);
        assertEquals("Deployment profile production for / - nothing refused:" + System.lineSeparator()
                + "  warning: OIDF_ELSEWHERE is set?and forged", warnings);
        String refusing = LifecycleListener.sweepLog("/", new ProfileAudit.Result(DeploymentProfile.PRODUCTION,
                List.of(new ProfileAudit.Violation(ProfileAudit.Kind.UNKNOWN_KEY, "OIDF_FAPI2_CLIENT", "x".repeat(600), "Fix it",
                        List.of("FAPI"))), List.of()), v -> true);
        assertTrue(refusing.startsWith("Deployment profile production for / - 1 violation(s) refuse the components they name,"
                + " which answer 503; PingFederate's own endpoints keep serving:"), refusing);
        assertTrue(refusing.contains("REFUSED: " + "x".repeat(600) + ". Fix it [FAPI]"), "a violation is never cut in the log");
        ProfileAudit.Violation required = new ProfileAudit.Violation(ProfileAudit.Kind.REQUIRED, "OIDF_OPERATOR_AUDIENCE",
                "OIDF_OPERATOR_AUDIENCE is unset", "Set it", List.of("OPERATOR_API"));
        String unswitched = LifecycleListener.sweepLog("/", new ProfileAudit.Result(DeploymentProfile.PRODUCTION, List.of(required),
                List.of()), v -> false);
        assertEquals("Deployment profile production for / - nothing refused:" + System.lineSeparator()
                + "  not refused (not switched on): OIDF_OPERATOR_AUDIENCE is unset. Set it [OPERATOR_API]", unswitched);
        listener(Map.of("OIDF_ACCEPTED_RISKS", "nope"), Map.of()).sweep("/");
        ProfileAudit.Result clean = listener(Map.of("OIDF_OPERATOR_AUDIENCE", "https://pf/operators", "OIDF_OPERATOR_BASE_URL",
                "https://pf.example.com"), Map.of()).sweep("/");
        assertEquals(List.of(), clean.violations(), "a production deployment with its required settings: nothing to log");
        assertEquals(List.of(), clean.warnings());
    }

    @Test
    void aSweepThatFailsRefusesEveryComponentInProduction() {
        ClassLoader broken = new ClassLoader(LifecycleListener.class.getClassLoader()) {
            @Override
            public URL getResource(String name) {
                throw new IllegalStateException("the class path cannot be read");
            }
        };
        ProfileAudit.Result result = new LifecycleListener(Map.<String, String>of()::get, Sources.of(Map.of(), Map.of()), () -> TODAY,
                broken).sweep("/");
        ProfileAudit.Violation v = result.violations().get(0);
        assertEquals(ProfileAudit.Kind.CATALOGUE, v.kind());
        assertTrue(v.reason().startsWith("The production profile's start-up sweep failed (java.lang.IllegalStateException: the class"
                + " path cannot be read)"), v.reason());
        assertEquals(EVERY, v.components());
        assertTrue(ProfileRefusals.refused("FAPI", false));
    }

    @Test
    void theEnginesCopyEvaluatingForItselfGivesTheWebappCopysAnswer() throws Exception {
        String property = "oidf.redis.url";
        String before = System.getProperty(property);
        System.setProperty(property, "redis://cache:6379");
        try (URLClassLoader webapp = copy(); URLClassLoader engine = copy()) {
            Object listener = webapp.loadClass(LifecycleListener.class.getName()).getConstructor().newInstance();
            java.lang.reflect.Method sweep = listener.getClass().getDeclaredMethod("sweep", String.class);
            sweep.setAccessible(true);
            Object published = sweep.invoke(listener, "/ (pf-runtime)");
            Object lazy = engine.loadClass(ProfileRefusals.class.getName()).getMethod("current").invoke(null);
            List<String> webapps = lines(published);
            assertTrue(webapps.stream().anyMatch(l -> l.startsWith("OIDF_REDIS_URL is a redis:// URL")), webapps.toString());
            assertEquals(webapps, lines(lazy), "the OGNL criteria see the listener's answer");
        } finally {
            if (before == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, before);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> lines(Object result) throws Exception {
        List<String> out = new ArrayList<>();
        for (Object v : (List<Object>) result.getClass().getMethod("violations").invoke(result)) {
            out.add((String) v.getClass().getMethod("line").invoke(v));
        }
        return out;
    }

    /** A copy of platform and platform-pf of its own, as LifecycleListenerTest builds one. */
    private static URLClassLoader copy() {
        URL platform = Lifecycle.class.getProtectionDomain().getCodeSource().getLocation();
        URL platformPf = LifecycleListener.class.getProtectionDomain().getCodeSource().getLocation();
        ClassLoader test = LifecycleSweepTest.class.getClassLoader();
        ClassLoader container = new ClassLoader(ClassLoader.getPlatformClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (name.startsWith("jakarta.servlet.")) {
                    return test.loadClass(name);
                }
                throw new ClassNotFoundException(name);
            }
        };
        return new URLClassLoader(new URL[] {platform, platformPf}, container);
    }

    @Test
    void theBannerListsTheSweepsNotes() {
        LifecycleListener listener = listener(Map.of("OIDF_ELSEWHERE", "x"), Map.of());
        listener.sweep("/");
        String banner = listener.audit("/").orElseThrow();
        assertTrue(banner.contains("  profile notes:  OIDF_ELSEWHERE is set and no settings catalogue declares it"), banner);
        assertTrue(banner.contains("  violations:     not refused (not switched on): OIDF_OPERATOR_AUDIENCE is unset"), banner);
        assertEquals(Optional.empty(), listener.audit("/"), "once");
    }
}
