/*
 * The static bearer: development's escape beside OAuth, refused in production, and one rule in one place.
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StaticBearerTest {
    private static final String TOKEN = "static-admin-token-0123";

    private OperatorFixture fixture;

    @BeforeEach
    void setUp() throws Exception {
        this.fixture = new OperatorFixture();
    }

    @AfterEach
    void tearDown() {
        this.fixture.close();
        OperatorAuthenticator.resetShared();
    }

    private static OperatorAuthenticator development() {
        return OperatorTestKit.unconfigured(DeploymentProfile.DEVELOPMENT).withStaticBearer(TOKEN);
    }

    @Test
    void developmentLetsTheStaticBearerThroughForEveryRouteAsAnAdminActor() {
        OperatorAuthenticator auth = development();
        OperatorFixture.Request request = OperatorFixture.bearer(TOKEN);
        request.actorHeader = "Dave <dave@example.com>";
        OperatorAuthenticator.Decision decision = auth.authenticate(request.mock(), OperatorFixture.UPDATE);

        Operator operator = assertInstanceOf(OperatorAuthenticator.Authorised.class, decision).operator();
        assertEquals(OperatorAuthenticator.staticActor(TOKEN), operator.actor());
        assertTrue(operator.actor().matches("admin:[0-9a-f]{8}"), operator.actor());
        assertEquals(OperatorAuthenticator.STATIC_BINDING, operator.binding());
        assertEquals(OperatorScopes.ALL, operator.scopes());
        assertEquals("Dave <dave@example.com>", operator.claimedLabel());
        assertSame(operator, request.attributes.get(OperatorAuthenticator.OPERATOR_ATTRIBUTE));
        Event event = this.fixture.last();
        assertEquals(OperatorAuthenticator.AUTHORISED, event.code());
        assertEquals("static-bearer", event.fields().get("binding"));
        assertEquals("hosted-entities.update", event.fields().get("route"));
    }

    @Test
    void aWrongStaticBearerIsAFailedAuthenticationThatCountsAgainstTheLimit() {
        OperatorAuthenticator auth = development();
        for (int i = 0; i < 10; i++) {
            OperatorAuthenticator.Refused refused = assertInstanceOf(OperatorAuthenticator.Refused.class,
                    auth.authenticate(OperatorFixture.bearer(TOKEN + "x").mock(), OperatorFixture.READ));
            assertEquals(401, refused.status(), "attempt " + i);
            assertEquals("invalid_token", refused.reason());
        }
        OperatorAuthenticator.Refused limited = assertInstanceOf(OperatorAuthenticator.Refused.class,
                auth.authenticate(OperatorFixture.bearer(TOKEN).mock(), OperatorFixture.READ));
        assertEquals(429, limited.status(), "even the right token waits once the address has failed ten times");
    }

    @Test
    void theStaticBearerCountsAgainstTheChangeLimit() {
        OperatorAuthenticator auth = development();
        for (int i = 0; i < 60; i++) {
            assertInstanceOf(OperatorAuthenticator.Authorised.class,
                    auth.authenticate(OperatorFixture.bearer(TOKEN).mock(), OperatorFixture.UPDATE));
        }
        OperatorAuthenticator.Refused refused = assertInstanceOf(OperatorAuthenticator.Refused.class,
                auth.authenticate(OperatorFixture.bearer(TOKEN).mock(), OperatorFixture.UPDATE));
        assertEquals(429, refused.status());
        assertEquals("too_many_changes", refused.reason());
        assertInstanceOf(OperatorAuthenticator.Authorised.class,
                auth.authenticate(OperatorFixture.bearer(TOKEN).mock(), OperatorFixture.READ), "reads are not changes");
    }

    @Test
    void developmentAcceptsOAuthBesideTheStaticBearer() throws Exception {
        OperatorTestKit kit = new OperatorTestKit();
        OperatorAuthenticator auth = kit.authenticator(DeploymentProfile.DEVELOPMENT).withStaticBearer(TOKEN);
        assertInstanceOf(OperatorAuthenticator.Authorised.class,
                auth.authenticate(OperatorFixture.bearer(TOKEN).mock(), OperatorFixture.READ));
        String token = kit.token(OperatorScopes.ADMIN_READ);
        OperatorFixture.Request request = new OperatorFixture.Request();
        request.authorization.add("DPoP " + token);
        request.dpop.add(kit.proof(token, "GET", OperatorFixture.PATH));
        Operator operator = assertInstanceOf(OperatorAuthenticator.Authorised.class,
                auth.authenticate(request.mock(), OperatorFixture.READ)).operator();
        assertEquals(OperatorTestKit.CLIENT, operator.actor());
        assertEquals("dpop", operator.binding());
    }

    @Test
    void theStaticBearerIsNotAToken68ButStillMatchesAndOtherSchemesNeverDo() {
        OperatorAuthenticator auth = OperatorTestKit.unconfigured(DeploymentProfile.DEVELOPMENT).withStaticBearer("a:b c");
        assertInstanceOf(OperatorAuthenticator.Authorised.class,
                auth.authenticate(OperatorFixture.bearer("a:b c").mock(), OperatorFixture.READ));
        OperatorFixture.Request dpop = new OperatorFixture.Request();
        dpop.authorization.add("DPoP " + TOKEN);
        OperatorAuthenticator other = development();
        assertEquals(401, assertInstanceOf(OperatorAuthenticator.Refused.class,
                other.authenticate(dpop.mock(), OperatorFixture.READ)).status(), "only the Bearer scheme carries it");
        OperatorFixture.Request bare = new OperatorFixture.Request();
        bare.authorization.add("Bearer");
        assertEquals(400, assertInstanceOf(OperatorAuthenticator.Refused.class,
                other.authenticate(bare.mock(), OperatorFixture.READ)).status());
    }

    @Test
    void productionRefusesEveryRequestWhileAStaticBearerIsSetAndSaysToRemoveIt() throws Exception {
        OperatorTestKit kit = new OperatorTestKit();
        OperatorAuthenticator auth = kit.authenticator(DeploymentProfile.PRODUCTION).withStaticBearer(TOKEN);
        String reason = auth.productionRefusal();
        assertNotNull(reason);
        assertTrue(reason.startsWith("OIDF_AUTHORITY_ADMIN_TOKEN is set, and production never accepts the static bearer:"
                + " remove it"), reason);
        assertFalse(auth.usable());
        assertEquals(reason, auth.problem());
        assertTrue(auth.configured());
        for (String presented : new String[] {"Bearer " + TOKEN, "Bearer other"}) {
            OperatorFixture.Request request = new OperatorFixture.Request();
            request.authorization.add(presented);
            OperatorAuthenticator.Refused refused = assertInstanceOf(OperatorAuthenticator.Refused.class,
                    auth.authenticate(request.mock(), OperatorFixture.READ));
            assertEquals(503, refused.status(), presented);
            assertEquals("static_bearer_in_production", refused.reason());
        }
        String token = kit.token(OperatorScopes.ADMIN_READ);
        OperatorFixture.Request good = new OperatorFixture.Request();
        good.authorization.add("DPoP " + token);
        good.dpop.add(kit.proof(token, "GET", OperatorFixture.PATH));
        assertEquals(503, assertInstanceOf(OperatorAuthenticator.Refused.class,
                auth.authenticate(good.mock(), OperatorFixture.READ)).status(), "a good token too, until it is removed");
        assertEquals("static_bearer_in_production", this.fixture.last().reason());
    }

    @Test
    void whatASurfacesInitAsks() throws Exception {
        OperatorAuthenticator nothing = OperatorTestKit.unconfigured(DeploymentProfile.PRODUCTION);
        assertFalse(nothing.configured());
        assertFalse(nothing.usable());
        assertNull(nothing.productionRefusal());
        assertNotNull(nothing.problem());

        OperatorAuthenticator developmentStatic = development();
        assertTrue(developmentStatic.configured());
        assertTrue(developmentStatic.usable());
        assertNull(developmentStatic.problem());
        assertNull(developmentStatic.productionRefusal());

        OperatorAuthenticator oauth = new OperatorTestKit().authenticator(DeploymentProfile.PRODUCTION);
        assertTrue(oauth.configured());
        assertTrue(oauth.usable());
        assertNull(oauth.problem());

        assertTrue(developmentStatic.developmentStaticBearer());
        assertFalse(OperatorTestKit.unconfigured(DeploymentProfile.PRODUCTION).withStaticBearer(TOKEN).developmentStaticBearer());
        assertFalse(OperatorTestKit.unconfigured(DeploymentProfile.DEVELOPMENT).developmentStaticBearer());

        assertSame(oauth, oauth.withStaticBearer(null));
        assertSame(oauth, oauth.withStaticBearer("  "));
    }

    @Test
    void theStaticBearerIsReadFromThePropertyThenTheEnvironment() {
        Map<String, String> props = Map.of(OperatorAuthenticator.STATIC_BEARER_PROPERTY, " from-property ");
        Map<String, String> env = Map.of(OperatorAuthenticator.STATIC_BEARER_ENV, "from-env");
        assertEquals("from-property", OperatorAuthenticator.staticBearer(props::get, env::get));
        assertEquals("from-env", OperatorAuthenticator.staticBearer(n -> " ", env::get));
        assertNull(OperatorAuthenticator.staticBearer(n -> null, n -> "\t"));
        assertNull(OperatorAuthenticator.staticBearer(n -> null, n -> null));
    }

    @Test
    void theSharedAuthenticatorIsBuiltOnceFromTheProcess() {
        OperatorAuthenticator.resetShared();
        OperatorAuthenticator first = OperatorAuthenticator.shared();
        assertSame(first, OperatorAuthenticator.shared());
        assertFalse(first.configured(), "this JVM sets no operator settings and no static bearer");
        OperatorAuthenticator.resetShared();
        assertFalse(first == OperatorAuthenticator.shared());
    }

    @Test
    void sameSecretComparesTheWholeValue() {
        assertTrue(OperatorAuthenticator.sameSecret("abc", "abc"));
        assertFalse(OperatorAuthenticator.sameSecret("abc", "abcd"));
        assertFalse(OperatorAuthenticator.sameSecret("abd", "abc"));
    }
}
