package com.pingidentity.ps.oidf.platform.pf.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.net.URI;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** The operator-auth catalogue read and checked; the route table and the scopes. */
class OperatorAuthConfigTest {
    private static final DeploymentProfile PROD = DeploymentProfile.PRODUCTION;
    private static final DeploymentProfile DEV = DeploymentProfile.DEVELOPMENT;

    private static Map<String, String> jwt() {
        Map<String, String> env = new HashMap<>();
        env.put(OperatorAuthConfig.AUDIENCE, "https://operator.example.com");
        env.put(OperatorAuthConfig.BASE_URL, "https://pf.example.com/");
        env.put(OperatorAuthConfig.JWKS_URL, "https://pf.example.com/pf/JWKS");
        return env;
    }

    private static OperatorAuthConfig read(Map<String, String> env, DeploymentProfile profile, boolean redis) {
        return OperatorAuthConfig.from(OperatorFixture.settings(env), profile, AcceptedRisks.none(), redis);
    }

    @Test
    void aJwtDeploymentWithRedisIsUsableWithTheCataloguesDefaults() {
        OperatorAuthConfig c = read(jwt(), PROD, true);
        assertTrue(c.usable(), c.problem());
        assertEquals(OperatorAuthConfig.Mode.JWT, c.mode());
        assertEquals("https://pf.example.com", c.baseUrl(), "the trailing slash goes");
        assertEquals("at+jwt", c.tokenTyp());
        assertEquals(10, c.authFailuresPerMinute());
        assertEquals(60, c.mutationsPerMinute());
        assertFalse(c.insecureTls());
        assertNull(c.introspectionClientSecret());
    }

    @Test
    void anIntrospectionDeploymentNeedsItsEndpointClientAndSecret() {
        Map<String, String> env = jwt();
        env.put(OperatorAuthConfig.MODE, "introspection");
        OperatorAuthConfig missing = read(env, PROD, true);
        assertTrue(missing.problem().contains(OperatorAuthConfig.INTROSPECTION_ENDPOINT), missing.problem());
        env.put(OperatorAuthConfig.INTROSPECTION_ENDPOINT, "https://pf.example.com/as/introspect.oauth2");
        assertFalse(read(env, PROD, true).usable());
        env.put(OperatorAuthConfig.INTROSPECTION_CLIENT_ID, "rs");
        assertFalse(read(env, PROD, true).usable());
        env.put(OperatorAuthConfig.INTROSPECTION_CLIENT_SECRET, "s3cret");
        OperatorAuthConfig c = read(env, PROD, true);
        assertTrue(c.usable(), c.problem());
        assertEquals("s3cret", c.introspectionClientSecret().get());
        assertEquals(OperatorAuthConfig.Mode.INTROSPECTION, c.mode());
    }

    @Test
    void everyProblemIsNamed() {
        Map<String, String> env = jwt();
        env.remove(OperatorAuthConfig.AUDIENCE);
        assertTrue(read(env, PROD, true).problem().startsWith(OperatorAuthConfig.AUDIENCE));
        env = jwt();
        env.remove(OperatorAuthConfig.JWKS_URL);
        assertTrue(read(env, PROD, true).problem().startsWith(OperatorAuthConfig.JWKS_URL));
        env = jwt();
        env.remove(OperatorAuthConfig.BASE_URL);
        assertTrue(read(env, DEV, true).problem().startsWith(OperatorAuthConfig.BASE_URL));
        env = jwt();
        env.put(OperatorAuthConfig.INSECURE_TLS, "true");
        assertEquals(OperatorAuthConfig.INSECURE_TLS + " is forbidden in production", read(env, PROD, true).problem());
        assertTrue(read(env, DEV, true).usable());
        env = jwt();
        env.put(OperatorAuthConfig.MODE, "opaque");
        assertFalse(read(env, DEV, true).usable(), "a value outside the choice");
        env = jwt();
        env.put(OperatorAuthConfig.MUTATIONS_PER_MINUTE, "0");
        assertFalse(read(env, DEV, true).usable(), "below the catalogue's minimum");
    }

    @Test
    void anEmptyAudienceIsNoAudience() {
        assertTrue(OperatorAuthConfig.problem(OperatorAuthConfig.Mode.JWT, "", URI.create("https://pf.example.com"),
                URI.create("https://pf.example.com/pf/JWKS"), null, null, false, false, PROD, AcceptedRisks.none(), true)
                .startsWith(OperatorAuthConfig.AUDIENCE));
    }

    /** PLAN.md decision 9: production keeps DPoP proofs in one JVM only under the in-memory-state accepted risk. */
    @Test
    void productionWithoutRedisNeedsTheInMemoryStateRisk() {
        OperatorAuthConfig none = read(jwt(), PROD, false);
        assertTrue(none.problem().contains("in-memory-state"), none.problem());
        assertTrue(read(jwt(), DEV, false).usable());
        OperatorAuthConfig accepted = OperatorAuthConfig.from(OperatorFixture.settings(jwt()), PROD,
                AcceptedRisks.parse("in-memory-state", LocalDate.now(ZoneOffset.UTC)), false);
        assertTrue(accepted.usable(), accepted.problem());
    }

    @Test
    void theBaseUrlIsAnOriginAndHttpsInProduction() {
        assertNull(OperatorAuthConfig.baseUrlProblem(URI.create("https://pf.example.com"), PROD));
        assertNull(OperatorAuthConfig.baseUrlProblem(URI.create("https://pf.example.com:8443/"), PROD));
        assertNull(OperatorAuthConfig.baseUrlProblem(URI.create("http://localhost:9031"), DEV));
        assertTrue(OperatorAuthConfig.baseUrlProblem(URI.create("http://pf.example.com"), PROD).contains("https"));
        for (String bad : List.of("https://pf.example.com/admin", "https://pf.example.com/?a=1",
                "https://pf.example.com/#f", "https://user@pf.example.com", "ftp://pf.example.com", "urn:x:y",
                "/relative", "https:pf.example.com")) {
            assertTrue(OperatorAuthConfig.baseUrlProblem(URI.create(bad), DEV).contains("origin"), bad);
        }
        assertTrue(OperatorAuthConfig.baseUrlProblem(null, DEV).contains("not set"));
    }

    // ---- routes and scopes ------------------------------------------------------------------------------------------

    @Test
    void aRouteTableMatchesTheFirstEntryWithTheExactMethodAndItsPathOrPrefix() {
        OperatorRoute list = OperatorRoute.read("hosted-entities.list", OperatorScopes.ADMIN_READ);
        OperatorRoute update = OperatorRoute.mutation("hosted-entities.update", OperatorScopes.ADMIN_ENTITIES);
        OperatorRoute any = OperatorRoute.read("metrics", OperatorScopes.METRICS_READ);
        OperatorRoutes routes = OperatorRoutes.builder()
                .route("GET", "/hosted-entities", list)
                .route("PUT", "/hosted-entities/*", update)
                .route("*", "/metrics", any)
                .build();
        assertEquals(Optional.of(list), routes.match("GET", "/hosted-entities"));
        assertEquals(Optional.empty(), routes.match("GET", "/hosted-entities/x"), "no prefix without /*");
        assertEquals(Optional.of(update), routes.match("PUT", "/hosted-entities/x/y"));
        assertEquals(Optional.of(update), routes.match("PUT", "/hosted-entities"));
        assertEquals(Optional.empty(), routes.match("PUT", "/hosted-entitiesX"));
        assertEquals(Optional.empty(), routes.match("put", "/hosted-entities/x"), "RFC 9110 §9.1: case-sensitive");
        assertEquals(Optional.of(any), routes.match("HEAD", "/metrics"));
        assertEquals(Optional.empty(), routes.match(null, "/metrics"));
        assertEquals(Optional.empty(), routes.match("GET", null));
        assertTrue(update.mutation());
        assertFalse(list.mutation());
        assertThrows(IllegalArgumentException.class, () -> OperatorRoutes.builder().route("GET", "metrics", any));
        assertThrows(IllegalArgumentException.class, () -> OperatorRoutes.builder().route("GET", null, any));
        assertThrows(NullPointerException.class, () -> OperatorRoutes.builder().route(null, "/m", any));
    }

    @Test
    void aRouteNeedsANameAndOneOfTheOperatorScopes() {
        assertThrows(IllegalArgumentException.class, () -> OperatorRoute.read("Hosted Entities", OperatorScopes.ADMIN_READ));
        assertThrows(IllegalArgumentException.class, () -> OperatorRoute.read(null, OperatorScopes.ADMIN_READ));
        assertThrows(IllegalArgumentException.class, () -> OperatorRoute.read("x", "openid"));
        assertThrows(NullPointerException.class, () -> OperatorRoute.read("x", null));
        assertEquals(10, OperatorScopes.ALL.size());
        assertEquals(List.of("oidf.admin.read", "oidf.admin.entities", "oidf.admin.trust_marks", "oidf.admin.keys",
                "oidf.admin.subordinates", "oidf.admin.subordinates.approve", "oidf.admin.clients.read", "ssf.admin",
                "oidf.metrics.read", "oidf.health.read"), OperatorScopes.ALL);
    }
}
