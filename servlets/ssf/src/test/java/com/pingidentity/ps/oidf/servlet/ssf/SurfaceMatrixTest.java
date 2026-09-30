/*
 * S-9's per-surface table (S9b), every row in every state, for every servlet and filter pf-runtime.war maps from this
 * module and the ones below it.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.pingidentity.ps.oidf.clientattestation.servlet.ChallengeEndpointServlet;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.servlet.trustanchor.OpenIdFederationServlet;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The surfaces are found, not listed (the Phase 3 plan's risk 4: a surface the gate misses serves half-configured):
 * every {@code @WebServlet} class in the ssf, pf-integration, client-attestation and platform-pf classes, and every
 * filter in build/pingfederate/filters.xml. The attester's servlets are in attestation-issuer, which this module does
 * not depend on; its own SurfaceMatrixTest drives them the same way.
 */
class SurfaceMatrixTest {

    private static final List<SurfaceMatrix.Surface> SURFACES = new ArrayList<>();
    private static Map<SurfaceMatrix.Surface, Object> started;

    @BeforeAll
    static void startEverySurface() throws Exception {
        SURFACES.addAll(SurfaceMatrix.servlets(SsfConfigurationServlet.class, OpenIdFederationServlet.class, ChallengeEndpointServlet.class,
                ComponentGate.class));
        SURFACES.addAll(SurfaceMatrix.filters(SurfaceMatrix.filtersXml()));
        started = SurfaceMatrix.start(SURFACES);
    }

    @AfterAll
    static void reset() {
        ProfileRefusals.resetForTests();
        SsfComponents.resetForTests();
    }

    @Test
    void theSurfacesAreFoundNotListed() {
        Set<String> found = new TreeSet<>();
        SURFACES.forEach(s -> found.add(s.type().getSimpleName()));
        // A floor, not the list: each of these must be among what was found, so a scan that finds nothing fails.
        for (String expected : List.of("OpenIdFederationServlet", "OpenIdRegistrationServlet", "HostedEntityServlet", "FederationAdminServlet",
                "SsfConfigurationServlet", "SsfPollServlet", "SsfReceiverServlet", "ClientAttestationChallengeServlet",
                "TokenEndpointAutoRegistrationFilter", "FrontChannelAutoRegistrationFilter", "ClientAttestationAuthFilter",
                "Fapi2ProfileFilter", "LogoutEventFilter", "HealthServlet")) {
            assertTrue(found.contains(expected), expected + " not found in " + found);
        }
    }

    @Test
    void everySurfaceIsAComponentsOrSaysWhyItIsNot() throws Exception {
        for (Map.Entry<SurfaceMatrix.Surface, Object> e : started.entrySet()) {
            SurfaceMatrix.Surface s = e.getKey();
            SurfaceMatrix.Named part = SurfaceMatrix.partOf(s, e.getValue());
            if (SurfaceMatrix.NOT_COMPONENTS.containsKey(s.name())) {
                assertEquals(null, part, s.name() + " is listed as no component's, but it holds a part");
                continue;
            }
            assertNotNull(part, s.name() + " is mapped by the war but has no part for a gate to read: register one in its init,"
                    + " name the part it shares in SurfaceMatrix.SHARED, or say in NOT_COMPONENTS why it is none");
            SurfaceMatrix.kind(part.component(), s.filter());
        }
    }

    @Test
    void everyRowOfTheTableHoldsInEveryState() throws Exception {
        List<String> failures = new ArrayList<>();
        int driven = 0;
        for (Map.Entry<SurfaceMatrix.Surface, Object> e : started.entrySet()) {
            SurfaceMatrix.Surface s = e.getKey();
            if (SurfaceMatrix.NOT_COMPONENTS.containsKey(s.name())) {
                continue;
            }
            SurfaceMatrix.Named part = SurfaceMatrix.partOf(s, e.getValue());
            SurfaceMatrix.Kind kind = SurfaceMatrix.kind(part.component(), s.filter());
            for (ComponentState state : SurfaceMatrix.STATES) {
                // What an init did to the profile's refusals (an in-memory store refused in production, say) is not this state.
                ProfileRefusals.resetForTests();
                SurfaceMatrix.siblingsReady(part.component(), part.part());
                SurfaceMatrix.put(part.component(), part.part(), state);
                driven++;
                String where = s.type().getSimpleName() + " (" + part.component() + ", " + kind + ") " + state + ": ";
                try {
                    check(kind, s, e.getValue(), part.component(), state);
                } catch (AssertionError failure) {
                    failures.add(where + failure.getMessage());
                }
            }
            SurfaceMatrix.put(part.component(), part.part(), ComponentState.READY);
        }
        assertTrue(driven > 100, "driven " + driven);
        if (!failures.isEmpty()) {
            fail(failures.size() + " rows do not hold:\n" + String.join("\n", failures));
        }
    }

    private static boolean serving(ComponentState state) {
        return state == ComponentState.READY || state == ComponentState.DEGRADED;
    }

    private static void check(SurfaceMatrix.Kind kind, SurfaceMatrix.Surface s, Object instance, String component, ComponentState state)
            throws Exception {
        String path = s.paths().get(0).replace("*", "probe-1");
        String unavailable = "{\"error\":\"temporarily_unavailable\",\"error_description\":\"" + component + " is not available\"}";
        switch (kind) {
            case FEDERATION_ENDPOINT, OAUTH_ENDPOINT -> {
                // Every method, PATCH included (two SSF servlets route it in their own service). A method the servlet
                // declares a handler for must meet the gate; one it does not may get HttpServlet's own answer instead - a
                // 405, a 501 for a method it does not know (PATCH), or OPTIONS' list of methods - which serves nothing of the
                // component's.
                List<String> declared = SurfaceMatrix.declaredMethods(s.type());
                int gatedCount = 0;
                for (String method : List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")) {
                    SurfaceMatrix.Answer a = SurfaceMatrix.drive(instance, SurfaceMatrix.request(method, path, Map.of(), Map.of()));
                    boolean gated = gatedEndpoint(kind, a, unavailable, state);
                    if (serving(state)) {
                        // A servlet's own answer may look like the gate's (HostedEntityServlet's 404 for an unknown id),
                        // but the gate never reads the request.
                        assertFalse(gated && !a.readTheRequest(), method + " answered by the gate while serving: " + a);
                        continue;
                    }
                    if (gated) {
                        gatedCount++;
                        assertFalse(a.readTheRequest(), method + " read the request before the gate answered");
                    } else {
                        assertFalse(declared.contains(method), method + " has a handler but was not answered by the gate: " + a);
                        assertTrue(a.error == 405 || a.error == 501 || method.equals("OPTIONS") && a.status == -1 && a.error == -1,
                                method + " neither gated nor HttpServlet's own answer: " + a);
                    }
                }
                assertTrue(serving(state) || gatedCount > 0, "no method met the gate");
            }
            case AUTO_REGISTRATION -> {
                // A federation client: an assertion carrying a trust chain (no store lookup needed to say so).
                HttpServletRequest federation = SurfaceMatrix.request("POST", path, Map.of("grant_type", "client_credentials",
                        "client_assertion", SurfaceMatrix.jwt("{\"alg\":\"ES256\",\"trust_chain\":[\"a.b.c\"]}", "{\"sub\":\"https://rp.example\"}")),
                        Map.of());
                HttpServletRequest ordinary = SurfaceMatrix.request("POST", path, Map.of("grant_type", "client_credentials",
                        "client_id", "an-ordinary-client"), Map.of());
                filterRow(instance, state, federation, ordinary, 401, "invalid_client", unavailable);
            }
            case ATTESTATION -> {
                String token = s.paths().contains("/as/token.oauth2") ? "/as/token.oauth2" : path;
                HttpServletRequest attested = SurfaceMatrix.request("POST", token, Map.of("grant_type", "client_credentials"),
                        Map.of("OAuth-Client-Attestation", "a.b.c", "DPoP", "d.e.f"));
                // No client named, so nothing is looked up: the gate's pass-through, not a policy decision.
                HttpServletRequest plain = SurfaceMatrix.request("POST", token, Map.of("grant_type", "client_credentials"), Map.of());
                filterRow(instance, state, attested, plain, 401, "invalid_client", unavailable);
            }
            case EVERY_REQUEST -> {
                SurfaceMatrix.Answer a = SurfaceMatrix.drive(instance, SurfaceMatrix.request("POST", path, Map.of("client_id", "x"), Map.of()));
                if (state == ComponentState.DISABLED) {
                    assertTrue(a.passed && a.status == -1, "disabled must pass every request on: " + a);
                } else if (!serving(state)) {
                    assertTrue(!a.passed && a.status == 503 && a.body().equals(unavailable), "failed must answer every request 503: " + a);
                } else {
                    assertFalse(a.status == 503 && a.body().equals(unavailable), "serving answered as the gate: " + a);
                }
            }
            case EMISSION -> {
                SurfaceMatrix.Answer a = SurfaceMatrix.drive(instance, SurfaceMatrix.request("GET", path, Map.of("id_token_hint", "a.b.c"), Map.of()));
                assertTrue(a.passed, "the logout must always go on: " + a);
                assertEquals(-1, a.status, "the logout filter never answers: " + a);
                if (!serving(state)) {
                    assertFalse(a.readTheRequest(), "a disabled or failed SSF reads nothing to emit: " + a);
                }
            }
            default -> fail("no row for " + kind);
        }
    }

    /** Whether a servlet's answer is the gate's for the state. */
    private static boolean gatedEndpoint(SurfaceMatrix.Kind kind, SurfaceMatrix.Answer a, String unavailable, ComponentState state) {
        if (a.status == 503 && a.body().equals(unavailable) && "no-store".equals(a.headers.get("Cache-Control"))) {
            return true;
        }
        if (a.status != 404 || !"no-store".equals(a.headers.get("Cache-Control")) || a.error != -1) {
            return false;
        }
        return kind == SurfaceMatrix.Kind.FEDERATION_ENDPOINT
                ? a.body().equals("{\"error\":\"not_found\",\"error_description\":\"no such endpoint\"}")
                : a.body().isEmpty() && Integer.valueOf(0).equals(a.contentLength);
    }

    /** A filter's row: its own traffic refused while disabled, 503 while failed; every other request passed on. */
    private static void filterRow(Object instance, ComponentState state, HttpServletRequest own, HttpServletRequest other, int disabledStatus,
            String disabledError, String unavailable) throws Exception {
        SurfaceMatrix.Answer a = SurfaceMatrix.drive(instance, own);
        SurfaceMatrix.Answer b = SurfaceMatrix.drive(instance, other);
        if (serving(state)) {
            assertFalse(a.status == 503 && a.body().equals(unavailable), "serving answered its traffic as the gate: " + a);
            assertFalse(a.status == disabledStatus && a.body().startsWith("{\"error\":\"" + disabledError + "\"") && !a.passed,
                    "serving refused its traffic as the gate: " + a);
            return;
        }
        if (state == ComponentState.DISABLED) {
            assertTrue(!a.passed && a.status == disabledStatus && a.body().startsWith("{\"error\":\"" + disabledError + "\""),
                    "disabled must refuse its own traffic " + disabledStatus + " " + disabledError + ": " + a);
        } else {
            assertTrue(!a.passed && a.status == 503 && a.body().equals(unavailable), "failed must answer its own traffic 503: " + a);
        }
        assertTrue(b.passed && b.status == -1 && b.thrown == null, "every other request goes on to PingFederate: " + b);
    }
}
