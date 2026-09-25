package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpAuth;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpMode;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The policy decision point settings: what each defaults to, and the combinations that stop a deployment starting. */
class FederationRuntimeConfigPdpTest {

    private static PdpSettings pdp(Map<String, String> env) {
        return FederationRuntimeConfig.from(env::get, name -> null).pdp();
    }

    private static String refusal(Map<String, String> env) {
        return assertThrows(IllegalStateException.class, () -> pdp(env)).getMessage();
    }

    @Test
    void byDefaultTheDeploymentsOwnPolicyDecidesAndNoPdpIsAsked() {
        PdpSettings settings = pdp(Map.of());

        assertEquals(PdpSettings.DEFAULTS, settings);
        assertEquals(PdpMode.LOCAL, settings.mode());
        assertNull(settings.allowedScopes(), "no list: the local policy narrows nothing");
        assertFalse(settings.failOpen(), "no decision is a refusal unless the deployment says otherwise");
        assertEquals(EnumSet.of(DecisionPoint.EXPLICIT_REGISTRATION, DecisionPoint.AUTOMATIC_REGISTRATION), settings.decisionPoints(),
                "enrolment is asked about only when listed");
        assertFalse(settings.asksExternally(DecisionPoint.AUTOMATIC_REGISTRATION));
    }

    @Test
    void anAuthZenPdpIsConfiguredInFull() {
        Map<String, String> env = new HashMap<>();
        env.put(FederationRuntimeConfig.PDP_MODE_ENV, "AuthZEN");
        env.put(FederationRuntimeConfig.PDP_URL_ENV, "https://pdp.example.com/tenant1");
        env.put(FederationRuntimeConfig.PDP_EVALUATION_URL_ENV, "https://pdp.example.com/tenant1/eval");
        env.put(FederationRuntimeConfig.PDP_DISCOVER_ENV, "true");
        env.put(FederationRuntimeConfig.PDP_AUTH_ENV, "header");
        env.put(FederationRuntimeConfig.PDP_AUTH_TOKEN_ENV, "s3cret");
        env.put(FederationRuntimeConfig.PDP_AUTH_HEADER_ENV, "X-PDP-Secret");
        env.put(FederationRuntimeConfig.PDP_FAIL_OPEN_ENV, "true");
        env.put(FederationRuntimeConfig.PDP_UNKNOWN_CONTEXT_ENV, "reject");
        env.put(FederationRuntimeConfig.PDP_CACHE_TTL_ENV, "30");
        env.put(FederationRuntimeConfig.PDP_CONNECT_TIMEOUT_ENV, "500");
        env.put(FederationRuntimeConfig.PDP_REQUEST_TIMEOUT_ENV, "900");
        env.put(FederationRuntimeConfig.PDP_SURFACE_USER_REASON_ENV, "true");
        env.put(FederationRuntimeConfig.REGISTRATION_ALLOWED_SCOPES_ENV, " openid, profile  email ");
        env.put(FederationRuntimeConfig.PDP_DECISION_POINTS_ENV, "automatic_registration,HOSTED_ENTITY_ENROL");

        PdpSettings settings = pdp(env);

        assertEquals(new PdpSettings(PdpMode.AUTHZEN, "https://pdp.example.com/tenant1", "https://pdp.example.com/tenant1/eval", true,
                PdpAuth.HEADER, "s3cret", "X-PDP-Secret", true, true, 30L, 500L, 900L, true, Set.of("openid", "profile", "email"),
                Set.of(DecisionPoint.AUTOMATIC_REGISTRATION, DecisionPoint.HOSTED_ENTITY_ENROL)), settings);
        assertTrue(settings.asksExternally(DecisionPoint.AUTOMATIC_REGISTRATION));
        assertFalse(settings.asksExternally(DecisionPoint.EXPLICIT_REGISTRATION), "only the decisions listed go to the PDP");
    }

    @Test
    void aSystemPropertyWinsOverTheEnvironment() {
        Map<String, String> props = Map.of("oidf.pdp.mode", "off", "oidf.pdp.auth.header", "X-From-Props");

        PdpSettings settings = FederationRuntimeConfig.from(Map.of(FederationRuntimeConfig.PDP_MODE_ENV, "local")::get, props::get).pdp();

        assertEquals(PdpMode.OFF, settings.mode());
        assertEquals("X-From-Props", settings.authHeader());
    }

    @Test
    void anAuthZenPdpNeedsSomewhereToAsk() {
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_MODE_ENV, "authzen")).contains(FederationRuntimeConfig.PDP_URL_ENV));
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_DISCOVER_ENV, "true", FederationRuntimeConfig.PDP_EVALUATION_URL_ENV,
                "https://pdp.example.com/eval")).contains("identifier"), "discovery starts from the PDP's identifier");
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_AUTH_ENV, "bearer")).contains(FederationRuntimeConfig.PDP_AUTH_TOKEN_ENV));
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §10.1", "AUTHZEN-1.0 §11.1"})
    void aPdpIsAskedOverHttpsUnlessPlaintextFetchesAreAllowed() {
        Map<String, String> env = new HashMap<>(Map.of(FederationRuntimeConfig.PDP_MODE_ENV, "authzen",
                FederationRuntimeConfig.PDP_URL_ENV, "http://pdp.internal:8080"));
        assertTrue(refusal(env).contains("https"));
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_EVALUATION_URL_ENV, "ftp://pdp.example.com/eval")).contains("https"));

        env.put(OutboundUrlPolicy.ALLOW_HTTP_ENV, "true");
        assertEquals("http://pdp.internal:8080", pdp(env).url(), "a development PDP, where the deployment allows plaintext at all");
        env.put(FederationRuntimeConfig.PDP_URL_ENV, "ftp://pdp.internal");
        assertTrue(refusal(env).contains("https"), "plaintext means http, nothing else");
    }

    @Test
    void aPdpUrlHasAHost() {
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_URL_ENV, "https:///access")).contains("not a URL with a host"));
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_EVALUATION_URL_ENV, "https://pdp example/eval")).contains("not a URL with a host"));
    }

    @Test
    void settingsOutOfRangeOrMisspeltStopTheDeploymentStarting() {
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_MODE_ENV, "remote")).contains("off, local, authzen"));
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_AUTH_ENV, "basic")).contains("none, bearer, header"));
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_UNKNOWN_CONTEXT_ENV, "warn")).contains("ignore, reject"));
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_CACHE_TTL_ENV, "-1")).contains("positive"));
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_CONNECT_TIMEOUT_ENV, "0")).contains("positive"));
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_REQUEST_TIMEOUT_ENV, "0")).contains("positive"));
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_CACHE_TTL_ENV, "soon")).contains("whole number"));
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_DECISION_POINTS_ENV, "resolve")).contains("resolve"));
        assertEquals(Set.of(DecisionPoint.TOKEN_ISSUANCE), pdp(Map.of(FederationRuntimeConfig.PDP_DECISION_POINTS_ENV, "token_issuance"))
                .decisionPoints());
    }

    @Test
    void anAllowListIsTheLocalPolicySoOffCannotSitBesideIt() {
        String refused = refusal(Map.of(FederationRuntimeConfig.PDP_MODE_ENV, "off", FederationRuntimeConfig.REGISTRATION_ALLOWED_SCOPES_ENV,
                "openid"));

        assertTrue(refused.contains(FederationRuntimeConfig.REGISTRATION_ALLOWED_SCOPES_ENV), refused);
    }

    @Test
    void aListOfNothingIsASlipNotAPolicy() {
        assertTrue(refusal(Map.of(FederationRuntimeConfig.REGISTRATION_ALLOWED_SCOPES_ENV, " , ")).contains("lists nothing"),
                "neither no limit nor no scope: the deployment does not start");
        assertTrue(refusal(Map.of(FederationRuntimeConfig.PDP_DECISION_POINTS_ENV, ",")).contains("lists nothing"));
        assertEquals(Set.of("openid"), pdp(Map.of(FederationRuntimeConfig.REGISTRATION_ALLOWED_SCOPES_ENV, ",openid,")).allowedScopes());
        assertNull(pdp(Map.of(FederationRuntimeConfig.REGISTRATION_ALLOWED_SCOPES_ENV, "   ")).allowedScopes(), "blank is unset, as everywhere");
    }
}
