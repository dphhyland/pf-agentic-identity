package com.pingidentity.ps.oidf.platform.pf.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.pingidentity.ps.oidf.platform.json.Json;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The authenticator against a running PingFederate: the conformance rig (conformance/up.sh) with tokens minted there.
 * Skipped unless {@code OIDF_TEST_OPERATOR_RIG} names a JSON file holding the issuer, the audience, the JWKS and
 * introspection URLs, an introspecting client, the proof key (a private JWK) and three access tokens carrying
 * {@code oidf.admin.read}: {@code jwt} and {@code ref}, DPoP-bound to that key from a JWT and a reference token
 * manager, and {@code plain}, a bearer token. The rig's certificate is self-signed, so this runs in development with
 * {@code OIDF_OPERATOR_INSECURE_TLS}.
 */
class OperatorAuthenticatorRigTest {
    private static final String FILE = System.getenv("OIDF_TEST_OPERATOR_RIG");
    private static final String PATH = "/federation-admin/hosted-entities";

    private Map<String, Object> rig;
    private PublicJsonWebKey key;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void read() throws Exception {
        assumeTrue(FILE != null && !FILE.isBlank(), "set OIDF_TEST_OPERATOR_RIG to run against a PingFederate rig");
        this.rig = (Map<String, Object>) Json.parse(Files.readString(Path.of(FILE)));
        this.key = PublicJsonWebKey.Factory.newPublicJwk((Map<String, Object>) this.rig.get("jwk"));
        com.pingidentity.ps.oidf.platform.events.Events.reset();
    }

    @AfterEach
    void reset() {
        com.pingidentity.ps.oidf.platform.events.Events.reset();
    }

    private String rig(String name) {
        return (String) this.rig.get(name);
    }

    private OperatorAuthenticator authenticator(String mode) {
        Map<String, String> env = new HashMap<>();
        env.put(OperatorAuthConfig.MODE, mode);
        env.put(OperatorAuthConfig.AUDIENCE, this.rig("audience"));
        env.put(OperatorAuthConfig.BASE_URL, this.rig("issuer"));
        env.put(OperatorAuthConfig.JWKS_URL, this.rig("jwks"));
        env.put(OperatorAuthConfig.INTROSPECTION_ENDPOINT, this.rig("introspection"));
        env.put(OperatorAuthConfig.INTROSPECTION_CLIENT_ID, this.rig("introspect_id"));
        env.put(OperatorAuthConfig.INTROSPECTION_CLIENT_SECRET, this.rig("introspect_secret"));
        env.put(OperatorAuthConfig.INSECURE_TLS, "true");
        OperatorAuthConfig config = OperatorAuthConfig.from(OperatorFixture.settings(env), DeploymentProfile.DEVELOPMENT,
                AcceptedRisks.none(), false);
        assertEquals(null, config.problem());
        return OperatorAuthenticator.from(config, null, request -> this.rig("issuer"), Clock.systemUTC());
    }

    private OperatorAuthenticator.Decision dpop(OperatorAuthenticator a, String token, OperatorRoute route)
            throws Exception {
        OperatorFixture.Request r = new OperatorFixture.Request();
        r.authorization.add("DPoP " + token);
        r.dpop.add(OperatorFixture.proof(this.key, token, "GET", this.rig("issuer") + PATH, c -> { }));
        return a.authenticate(r.mock(), route);
    }

    @Test
    void aDpopBoundJwtFromPingFederateIsLetThroughInJwtMode() throws Exception {
        Operator o = assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.dpop(this.authenticator("jwt"), this.rig("jwt"), OperatorFixture.READ)).operator();
        assertEquals("s8a-live-jwt", o.actor());
        assertEquals("dpop", o.binding());
        assertEquals(403, assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.dpop(this.authenticator("jwt"), this.rig("jwt"), OperatorFixture.UPDATE)).status());
    }

    @Test
    void aDpopBoundJwtAndAReferenceTokenAreLetThroughInIntrospectionMode() throws Exception {
        OperatorAuthenticator a = this.authenticator("introspection");
        Operator jwt = assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.dpop(a, this.rig("jwt"), OperatorFixture.READ)).operator();
        assertEquals("s8a-live-jwt", jwt.actor());
        assertEquals("dpop", jwt.binding());
        Operator ref = assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.dpop(a, this.rig("ref"), OperatorFixture.READ)).operator();
        assertEquals("s8a-live-ref", ref.actor());
        assertEquals("dpop", ref.binding());
    }

    @Test
    void anUnboundTokenFromPingFederateIsBoundToNothing() throws Exception {
        OperatorFixture.Request r = OperatorFixture.bearer(this.rig("plain"));
        assertEquals("none", assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.authenticator("jwt").authenticate(r.mock(), OperatorFixture.READ)).operator().binding(),
                "development only");
        OperatorFixture.Request asDpop = new OperatorFixture.Request();
        asDpop.authorization.add("DPoP " + this.rig("plain"));
        asDpop.dpop.add(OperatorFixture.proof(this.key, this.rig("plain"), "GET", this.rig("issuer") + PATH, c -> { }));
        assertEquals(401, assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.authenticator("introspection").authenticate(asDpop.mock(), OperatorFixture.READ)).status());
    }
}
