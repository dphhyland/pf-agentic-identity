package com.pingidentity.ps.oidf.platform.pf.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The authenticator in introspection mode against a stub of PingFederate's introspection endpoint, answering as
 * PingFederate 13.1.3 answered on the rig on 2026-09-29: {@code active}, {@code cnf.jkt} and {@code token_type}
 * {@code DPoP} for a DPoP-bound token, and no {@code iss} for a reference token.
 */
class OperatorIntrospectionTest {
    private static final String REFERENCE = "Kc0qR8mX2bVtLw5nPz3YhA9uEs1o";

    private final OperatorFixture f;

    OperatorIntrospectionTest() throws Exception {
        this.f = new OperatorFixture();
    }

    @AfterEach
    void close() {
        this.f.close();
    }

    /**
     * RFC 9449 §6.2: "the resource server uses the data of the introspection response to validate the access token
     * binding itself locally" - the proof's key against the answer's {@code cnf.jkt}, its {@code ath} against the
     * opaque token.
     */
    @Test
    @Requirement("RFC9449 §6.2")
    void aReferenceTokenPingFederateSaysIsActiveAndDpopBoundIsLetThroughWithItsProof() throws Exception {
        JwtClaims claims = this.f.claims("oidf.admin.read oidf.admin.entities");
        claims.unsetClaim("iss");
        this.f.introspects(claims);
        OperatorAuthenticator a = this.f.introspecting();
        Operator operator = assertInstanceOf(OperatorAuthenticator.Authorised.class,
                a.authenticate(this.f.dpop(REFERENCE, "POST").mock(), OperatorFixture.UPDATE)).operator();
        assertEquals(OperatorFixture.CLIENT, operator.actor());
        assertEquals("dpop", operator.binding());
        // client_secret_basic, as the introspecting client
        String basic = this.f.lastIntrospectionAuthorization.get();
        assertTrue(basic.startsWith("Basic "), basic);
        assertEquals(OperatorFixture.INTROSPECTION_CLIENT + ":introspection-secret", new String(
                Base64.getDecoder().decode(basic.substring("Basic ".length())), StandardCharsets.UTF_8));
    }

    /** RFC 7662 §2.2: "active" false - the token is not one PingFederate stands behind, so it is invalid. */
    @Test
    @Requirement("RFC7662 §2.2")
    void aTokenPingFederateSaysIsNotActiveIsInvalid() throws Exception {
        this.f.introspection.set("{\"active\":false}");
        OperatorAuthenticator.Refused r = assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.f.introspecting().authenticate(this.f.dpop(REFERENCE, "GET").mock(), OperatorFixture.READ));
        assertEquals(401, r.status());
        assertEquals("invalid_token", r.reason());
    }

    @Test
    @Requirement("RFC7662 §2.2")
    void anAnswerForAnotherIssuerOrAudienceOrScopeIsRefused() throws Exception {
        JwtClaims claims = this.f.claims("oidf.admin.read");
        claims.setIssuer("https://other.example.com");
        this.f.introspects(claims);
        assertEquals(401, assertInstanceOf(OperatorAuthenticator.Refused.class, this.f.introspecting()
                .authenticate(this.f.dpop(REFERENCE, "GET").mock(), OperatorFixture.READ)).status());
        JwtClaims audience = this.f.claims("oidf.admin.read");
        audience.setAudience("https://another.example.com");
        this.f.introspects(audience);
        assertEquals(401, assertInstanceOf(OperatorAuthenticator.Refused.class, this.f.introspecting()
                .authenticate(this.f.dpop(REFERENCE, "GET").mock(), OperatorFixture.READ)).status());
        this.f.introspects(this.f.claims("oidf.admin.read"));
        assertEquals(403, assertInstanceOf(OperatorAuthenticator.Refused.class, this.f.introspecting()
                .authenticate(this.f.dpop(REFERENCE, "POST").mock(), OperatorFixture.UPDATE)).status());
    }

    /** A proof by a key other than the one the answer's cnf.jkt names is refused, as in jwt mode. */
    @Test
    @Requirement("RFC9449 §6.2")
    void aProofWhoseKeyIsNotTheAnswersCnfIsRefused() throws Exception {
        JwtClaims claims = this.f.claims("oidf.admin.read");
        claims.setClaim("cnf", Map.of("jkt", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        this.f.introspects(claims);
        OperatorAuthenticator.Refused r = assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.f.introspecting().authenticate(this.f.dpop(REFERENCE, "GET").mock(), OperatorFixture.READ));
        assertEquals(401, r.status());
        assertEquals("invalid_token", r.reason());
    }

    /** An endpoint that cannot answer is a 503, never a pass and never a failure counted against the caller. */
    @Test
    void anIntrospectionEndpointThatFailsIs503() throws Exception {
        this.f.introspects(this.f.claims("oidf.admin.read"));
        this.f.introspectionStatus.set(500);
        OperatorAuthenticator a = this.f.introspecting();
        for (int i = 0; i < 12; i++) {
            OperatorAuthenticator.Refused r = assertInstanceOf(OperatorAuthenticator.Refused.class,
                    a.authenticate(this.f.dpop(REFERENCE, "GET").mock(), OperatorFixture.READ));
            assertEquals(503, r.status());
            assertEquals("unavailable", r.reason());
        }
        Map<String, String> env = this.f.introspectionSettings();
        env.put(OperatorAuthConfig.INTROSPECTION_ENDPOINT, "http://127.0.0.1:1/as/introspect.oauth2");
        OperatorAuthenticator unreachable = this.f.authenticator(env, DeploymentProfile.PRODUCTION);
        assertEquals(503, assertInstanceOf(OperatorAuthenticator.Refused.class,
                unreachable.authenticate(this.f.dpop(REFERENCE, "GET").mock(), OperatorFixture.READ)).status());
    }

    @Test
    void anUnboundAnswerIsRefusedInProductionAndLetThroughInDevelopment() throws Exception {
        JwtClaims claims = this.f.claims("oidf.admin.read");
        claims.unsetClaim("cnf");
        this.f.introspects(claims);
        assertEquals(401, assertInstanceOf(OperatorAuthenticator.Refused.class, this.f.introspecting()
                .authenticate(OperatorFixture.bearer(REFERENCE).mock(), OperatorFixture.READ)).status());
        OperatorAuthenticator dev = this.f.authenticator(this.f.introspectionSettings(), DeploymentProfile.DEVELOPMENT);
        assertEquals("none", assertInstanceOf(OperatorAuthenticator.Authorised.class,
                dev.authenticate(OperatorFixture.bearer(REFERENCE).mock(), OperatorFixture.READ)).operator().binding());
    }
}
