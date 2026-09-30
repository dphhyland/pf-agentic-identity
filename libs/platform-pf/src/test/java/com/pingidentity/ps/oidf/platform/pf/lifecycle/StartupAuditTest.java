/*
 * The banner says each fact on its own labelled line, and nothing an operator set can break a line.
 */
package com.pingidentity.ps.oidf.platform.pf.lifecycle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import java.time.Instant;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class StartupAuditTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 9, 28);
    private static final Instant T0 = Instant.parse("2026-09-28T01:02:03Z");
    private static final String NL = System.lineSeparator();

    private static Map<String, Object> versions(String own, String commit, String pf) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("agentic-identity", own);
        v.put("commit", commit);
        v.put("pingfederate", pf);
        v.put("java", "21.0.12.1+1");
        return v;
    }

    private static final ProfileAudit.Result NONE = ProfileAudit.Result.empty(DeploymentProfile.PRODUCTION);
    private static final ProfileAudit.Violation CODE = new ProfileAudit.Violation(ProfileAudit.Kind.CODE, "SSF",
            "the store is in memory", "The start-up audit lists it", List.of("SSF"));
    private static final ProfileAudit.Result DEVELOPMENT_AUDIT = new ProfileAudit.Result(DeploymentProfile.DEVELOPMENT, List.of(
            new ProfileAudit.Violation(ProfileAudit.Kind.FORBIDDEN, "OIDF_X", "OIDF_X=true, which is forbidden", "Unset it", List.of("FAPI")),
            new ProfileAudit.Violation(ProfileAudit.Kind.REQUIRED, "OIDF_Y", "OIDF_Y is unset", "Set it", List.of("OPERATOR_API"))),
            List.of("OIDF_ELSEWHERE is set"));

    @Test
    void aViolationIsLabelledByWhetherItRefuses() {
        ProfileAudit.Violation required = DEVELOPMENT_AUDIT.violations().get(1);
        ProfileAudit.Result production = new ProfileAudit.Result(DeploymentProfile.PRODUCTION, List.of(required), List.of());
        assertEquals("REFUSED: ", StartupAudit.label(required, production, v -> true));
        assertEquals("not refused (not switched on): ", StartupAudit.label(required, production, v -> false));
        assertEquals("not refused (development): ", StartupAudit.label(required, DEVELOPMENT_AUDIT, v -> false));
    }

    private static Map<String, String> env(String profile, String risks) {
        Map<String, String> env = new HashMap<>();
        env.put(DeploymentProfile.SETTING, profile);
        env.put("OIDF_ACCEPTED_RISKS", risks);
        return env;
    }

    @Test
    void aQuietProductionDeploymentSaysNoneAndUnknownWhereItHasNothing() {
        StartupAudit.Facts f = StartupAudit.collect("/", versions(null, null, null), env(null, null)::get, TODAY, NONE, v -> true, List.of(), List.of(), List.of(), false,
                List.of(), List.of(), Optional.empty(), "file:/opt/lib/platform.jar");
        String expected = String.join(NL,
                "Start-up audit for /:",
                "  version:        unknown",
                "  commit:         " + StartupAudit.UNKNOWN_COMMIT,
                "  PingFederate:   unknown",
                "  Java:           21.0.12.1+1",
                "  profile:        production (OIDF_DEPLOYMENT_PROFILE is unset, which is production)",
                "  topology:       standalone",
                "  accepted risks: none",
                "  risk refusals:  none",
                "  violations:     none",
                "  code refusals:  none",
                "  profile notes:  none",
                "  legacy values:  none",
                "  insecure TLS:   none",
                "  JDK host names: checked",
                "  components:     none",
                "  executors:      none",
                "  metrics MXBean: not registered",
                "  platform:       file:/opt/lib/platform.jar");
        assertEquals(expected, StartupAudit.banner(f));
        assertEquals(DeploymentProfile.PRODUCTION, f.profile());
        assertEquals(StartupAudit.STANDALONE, f.topology());
    }

    @Test
    void everyFactIsListedOnePerLineUnderItsLabel() {
        List<InsecureTls.Use> tls = List.of(new InsecureTls.Use("OIDF_SSF_INSECURE_TLS", InsecureTls.Kind.TRUST_ALL_CERTIFICATES, T0),
                new InsecureTls.Use("insecureTls", InsecureTls.Kind.JDK_HOSTNAME_VERIFICATION_OFF, T0));
        List<ComponentStatus> components = List.of(new ComponentStatus("FEDERATION", true, ComponentState.READY, "", T0),
                new ComponentStatus("SSF_RECEIVER", true, ComponentState.FAILED_CONFIG, "no audience", T0));
        List<ManagedExecutor.Status> executors = List.of(new ManagedExecutor.Status("registration-sweeper", false, 0, 0),
                new ManagedExecutor.Status("ssf-push", true, 3, 1));
        StartupAudit.Facts f = StartupAudit.collect("/gm-api (Grant Management API)", versions("0.5.0", "abc123", "13.1.3.0"),
                env("Development", "pkce-off, expiry-log-mode@2026-12-31, nope, pkce-off2")::get, TODAY, DEVELOPMENT_AUDIT, v -> false,
                List.of(CODE), List.of("OIDF_X = 'yes', read as false"), tls, true, components,
                executors, Optional.of("com.pingidentity.ps.oidf:type=Metrics,copy=x"), "file:/w/WEB-INF/lib/platform.jar");
        String banner = StartupAudit.banner(f);
        String indent = " ".repeat(18);
        assertTrue(banner.startsWith("Start-up audit for /gm-api (Grant Management API):" + NL + "  version:        0.5.0" + NL
                + "  commit:         abc123" + NL + "  PingFederate:   13.1.3.0" + NL), banner);
        assertTrue(banner.contains(NL + "  profile:        development (OIDF_DEPLOYMENT_PROFILE is 'Development')" + NL), banner);
        assertTrue(banner.contains(NL + "  accepted risks: expiry-log-mode (until 2026-12-31): an expired registration is logged and"
                + " still served" + NL + indent + "pkce-off (no expiry): front-channel relying parties are registered without"
                + " requiring PKCE" + NL), banner);
        assertTrue(banner.contains(NL + "  risk refusals:  2, each logged at WARN; those risks are not accepted" + NL), banner);
        assertTrue(banner.contains(NL + "  violations:     not refused (development): OIDF_X=true, which is forbidden. Unset it [FAPI]" + NL
                + indent + "not refused (development): OIDF_Y is unset. Set it [OPERATOR_API]" + NL), banner);
        assertTrue(banner.contains(NL + "  code refusals:  REFUSED: SSF: the store is in memory" + NL), banner);
        assertTrue(banner.contains(NL + "  profile notes:  OIDF_ELSEWHERE is set" + NL), banner);
        assertTrue(banner.contains(NL + "  legacy values:  OIDF_X = 'yes', read as false" + NL), banner);
        assertTrue(banner.contains(NL + "  insecure TLS:   OIDF_SSF_INSECURE_TLS: TRUST_ALL_CERTIFICATES since 2026-09-28T01:02:03Z" + NL
                + indent + "insecureTls: JDK_HOSTNAME_VERIFICATION_OFF since 2026-09-28T01:02:03Z" + NL), banner);
        assertTrue(banner.contains(NL + "  JDK host names: NOT checked by any java.net.http client in this JVM"
                + " (jdk.internal.httpclient.disableHostnameVerification)" + NL), banner);
        assertTrue(banner.contains(NL + "  components:     FEDERATION READY" + NL + indent + "SSF_RECEIVER FAILED_CONFIG: no audience" + NL),
                banner);
        assertTrue(banner.contains(NL + "  executors:      registration-sweeper, ssf-push (closed)" + NL), banner);
        assertTrue(banner.endsWith(NL + "  metrics MXBean: com.pingidentity.ps.oidf:type=Metrics,copy=x" + NL
                + "  platform:       file:/w/WEB-INF/lib/platform.jar"), banner);
        assertEquals(2, f.risks().refusals().size());
        assertTrue(f.risks().refusals().get(0).contains("'nope'"), f.risks().refusals().toString());
    }

    @Test
    void whatAnOperatorSetCannotStartANewLine() {
        StartupAudit.Facts f = StartupAudit.collect("/", versions(null, null, null),
                env("prod\nINFO forged line", null)::get, TODAY, NONE, v -> true, List.of(), List.of(), List.of(), false, List.of(), List.of(), Optional.empty(), "x");
        String banner = StartupAudit.banner(f);
        assertTrue(banner.contains("'prod?INFO forged line'"), banner);
        assertEquals(19, banner.split(NL, -1).length, "the heading and eighteen facts, nothing more");
    }

    @Test
    void oneLineReplacesSeparatorsAndCutsLongValues() {
        assertEquals("", StartupAudit.oneLine(null));
        assertEquals("a?b?c?d", StartupAudit.oneLine("  a\rb c​d  "));
        assertEquals("a?b", StartupAudit.oneLine("a b"));
        String longValue = "x".repeat(StartupAudit.MAX_VALUE + 10);
        assertEquals("x".repeat(StartupAudit.MAX_VALUE) + "...", StartupAudit.oneLine(longValue));
        String exact = "y".repeat(StartupAudit.MAX_VALUE);
        assertEquals(exact, StartupAudit.oneLine(exact));
        String split = "z".repeat(StartupAudit.MAX_VALUE - 1) + "😀" + "tail";
        assertEquals("z".repeat(StartupAudit.MAX_VALUE - 1) + "...", StartupAudit.oneLine(split), "never half a surrogate pair");
    }
}
