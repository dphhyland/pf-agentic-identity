package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.FederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.NarrowingObligations;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecision;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionException;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionRequest;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.pf.FederationPolicySupport;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpAuth;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpMode;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import com.pingidentity.ps.oidf.pf.testkit.FakeClientStore;
import com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationService.Admission;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;

/**
 * A registration waits for the deployment's policy decision, over a real federation: a permit narrows the client it
 * becomes - never widens it - a denial or no decision at all registers nothing, and explicit registration reports what
 * was actually registered. The last test goes through the AuthZEN client itself, as PingFederate wires it.
 */
class RegistrationPdpTest {
    private static final String TA = "https://ta.example.com";
    private static final String AGENT = "https://agent.example.com";
    private static final String OP = "https://op.example.com";
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    private final MutableClock clock = MutableClock.startingNow();
    private final FakeClientStore store = new FakeClientStore();
    private final List<PolicyDecisionRequest> asked = new ArrayList<>();
    private final Federation federation = Federation.builder(this.clock).anchor(TA).leaf(AGENT, TA)
            .metadata(AGENT, "oauth_client", Map.of(
                    "client_registration_types", List.of("automatic", "explicit"),
                    "grant_types", List.of("client_credentials", TOKEN_EXCHANGE),
                    "response_types", List.of("code", "token"),
                    "token_endpoint_auth_method", "private_key_jwt",
                    "scope", "read write admin",
                    "client_name", "Agent"))
            .build();
    private EventCapture events;

    @BeforeEach
    void setUp() {
        this.events = EventCapture.install();
        Map<String, String> env = new HashMap<>();
        env.put(FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV, "false");
        FederationRuntimeConfig.install(FederationRuntimeConfig.from(env::get, name -> null));
    }

    @AfterEach
    void tearDown() {
        this.events.close();
        FederationRuntimeConfig.resetForTests();
        FederationPolicySupport.resetForTests();
    }

    private static PdpSettings settings(PdpMode mode, boolean failOpen) {
        PdpSettings d = PdpSettings.DEFAULTS;
        return new PdpSettings(mode, mode == PdpMode.AUTHZEN ? "https://pdp.example.com" : null, null, false, PdpAuth.NONE, null,
                d.authHeader(), failOpen, false, 0L, d.connectTimeoutMs(), d.requestTimeoutMs(), false, null,
                EnumSet.allOf(DecisionPoint.class));
    }

    private RegistrationService service(RegistrationPolicy policy) throws Exception {
        return new RegistrationService(new RegistrationConfiguration(TA, false),
                this.federation.validator(ValidatorOptions.defaults().withClock(this.clock), TA), this.store, RegistrationFixtures.signer(),
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock),
                new RpKeyMaterial((url, accept) -> {
                    throw new java.io.IOException("no RP key fetch expected: " + url);
                }, this.clock), RegistrationService.coordinatorFor(AutoRegistrationSettings.DEFAULTS), (url, contentType, body, headers, accept) -> {
                    throw new java.io.IOException("no status check expected: " + url);
                }, policy);
    }

    private RegistrationService service(FederationPolicyDecisionPoint pdp, boolean failOpen) throws Exception {
        return this.service(new RegistrationPolicy(point -> request -> {
            this.asked.add(request);
            return pdp.decide(request);
        }, settings(PdpMode.LOCAL, failOpen)));
    }

    private Admission admit(RegistrationService service) throws Exception {
        return service.admit(AGENT, this.federation.chain(AGENT, TA), OP);
    }

    private static long expiresAt(Client client) {
        return Long.parseLong(RegistrationFixtures.param(client, FederationClientParams.EXPIRES_AT));
    }

    @Test
    @Requirement("AUTHZEN-1.0 §5.5")
    void aPermitNarrowsTheClientItRegistersAndNeverWidensIt() throws Exception {
        NarrowingObligations narrow = new NarrowingObligations(Set.of("read", "write", "billing"), Set.of("client_credentials"), null, 600L,
                Set.of());

        assertEquals(Admission.REGISTERED, this.admit(this.service(request -> PolicyDecision.permit(narrow), false)));

        Client client = this.store.get(AGENT);
        assertEquals(List.of("read", "write"), client.getRestrictedScopes(), "billing was never asked for, so it is not given");
        assertEquals(Set.of("client_credentials"), client.getGrantTypes());
        assertEquals(List.of("code", "token"), client.getRestrictedResponseTypes(), "what the permit does not mention stays as it was");
        assertEquals(this.clock.epochSecond() + 600L, expiresAt(client));
        assertEquals(DecisionPoint.AUTOMATIC_REGISTRATION, this.asked.get(0).point());
        assertEquals("token", this.asked.get(0).actionProperties().get("endpoint"));
    }

    @Test
    void aDenialRegistersNothing() throws Exception {
        RegistrationService service = this.service(request -> PolicyDecision.deny("not on the list", null), false);

        RegistrationRejectedException refused = assertThrows(RegistrationRejectedException.class, () -> this.admit(service));

        assertEquals(RegistrationRejectedException.Kind.POLICY, refused.kind());
        assertNull(this.store.get(AGENT));
        assertTrue(this.store.writes().isEmpty());
    }

    @Test
    @Requirement("AUTHZEN-1.0 §10.1.2")
    void noDecisionRegistersNothingUnlessTheDeploymentFailsOpen() throws Exception {
        FederationPolicyDecisionPoint down = request -> {
            throw new PolicyDecisionException("the policy decision point could not be reached");
        };

        RegistrationRejectedException refused = assertThrows(RegistrationRejectedException.class, () -> this.admit(this.service(down, false)));
        assertEquals(503, refused.status());
        assertNull(this.store.get(AGENT));

        assertEquals(Admission.REGISTERED, this.admit(this.service(down, true)));
        assertEquals(List.of("read", "write", "admin"), this.store.get(AGENT).getRestrictedScopes(), "unnarrowed: there was no decision");
        assertEquals(1, this.events.withCode(FederationEvents.PDP_FAIL_OPEN).size());
    }

    @Test
    void aPolicyThatAllowsLessThanTheMinimumLifeRefusesTheRegistration() throws Exception {
        long tooShort = RegistrationSettings.DEFAULTS.minTtlSeconds() - 1;
        RegistrationService service = this.service(request -> PolicyDecision.permit(new NarrowingObligations(null, null, null, tooShort,
                Set.of())), false);

        RegistrationRejectedException refused = assertThrows(RegistrationRejectedException.class, () -> this.admit(service));

        assertEquals("invalid_client_metadata", refused.error());
        assertEquals(RegistrationRejectedException.Kind.POLICY, refused.kind());
        assertNull(this.store.get(AGENT));
    }

    @Test
    void aPolicyCanBringTheEndForwardButNeverPushItBack() throws Exception {
        this.admit(this.service(request -> PolicyDecision.permit(new NarrowingObligations(null, null, null, 10L * 365 * 86400, Set.of())), false));

        Client client = this.store.get(AGENT);
        assertTrue(expiresAt(client) <= this.clock.epochSecond() + RegistrationSettings.DEFAULTS.maxTtlSeconds(),
                "a policy can bring a registration's end forward, never push it back");
    }

    @Test
    @Requirement({"OIDFED §12.2.3(3)", "OIDFED §12.2.3(4)"})
    void explicitRegistrationReportsWhatWasActuallyRegistered() throws Exception {
        NarrowingObligations narrow = new NarrowingObligations(Set.of("read"), Set.of(TOKEN_EXCHANGE), Set.of("code"), 900L, Set.of());
        RegistrationService service = this.service(request -> PolicyDecision.permit(narrow), false);

        RegisteredClient registered = service.explicitRegister(new ExplicitRegistrationRequest(AGENT, AGENT, this.federation.chain(AGENT, TA),
                Map.of()), OP);

        JwtClaims response = JwtCodec.parseUnverifiedClaims(registered.signedJwt());
        Map<?, ?> metadata = (Map<?, ?>) ((Map<?, ?>) response.getClaimValue("metadata")).get("oauth_client");
        assertEquals("read", metadata.get("scope"));
        assertEquals(List.of(TOKEN_EXCHANGE), metadata.get("grant_types"));
        assertEquals(List.of("code"), metadata.get("response_types"));
        assertEquals(this.clock.epochSecond() + 900L, response.getExpirationTime().getValue(), "exp is the registration's end (§12.2.3)");
        assertEquals(List.of("read"), this.store.get(AGENT).getRestrictedScopes());
        assertEquals(DecisionPoint.EXPLICIT_REGISTRATION, this.asked.get(0).point());
        assertEquals("registration", this.asked.get(0).actionProperties().get("endpoint"));
    }

    @Test
    void anExplicitRegistrationThePolicyRefusesIsNotRegistered() throws Exception {
        RegistrationService service = this.service(request -> PolicyDecision.deny(null, null), false);

        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(new ExplicitRegistrationRequest(AGENT, AGENT,
                this.federation.chain(AGENT, TA), Map.of()), OP));

        assertTrue(this.store.writes().isEmpty());
    }

    @Test
    @Requirement({"AUTHZEN-1.0 §6.1", "AUTHZEN-1.0 §10.1", "AUTHZEN-1.0 §10.1.3"})
    void throughTheAuthZenClientAsPingFederateWiresIt() throws Exception {
        List<Map<String, Object>> bodies = new ArrayList<>();
        HttpPostClient pdp = (url, contentType, body, headers, accept) -> {
            assertEquals("https://pdp.example.com/access/v1/evaluation", url);
            assertEquals("application/json", contentType);
            bodies.add(JsonUtil.parseJson(body));
            return new HttpPostClient.Response(200, "{\"decision\":true,\"context\":{\"scope\":\"read\",\"registration_ttl_seconds\":900}}",
                    Map.of());
        };
        FederationPolicySupport.configure(settings(PdpMode.AUTHZEN, false), pdp, (url, accept) -> {
            throw new java.io.IOException("no discovery expected");
        }, this.clock);

        assertEquals(Admission.REGISTERED, this.admit(this.service(RegistrationPolicy.fromEnvironment())));

        Map<String, Object> sent = bodies.get(0);
        assertEquals(Map.of("type", "federation_entity", "id", AGENT), Map.of("type", ((Map<?, ?>) sent.get("subject")).get("type"),
                "id", ((Map<?, ?>) sent.get("subject")).get("id")));
        assertEquals("federation.register.automatic", ((Map<?, ?>) sent.get("action")).get("name"));
        assertEquals(Map.of("type", "openid_provider", "id", OP), sent.get("resource"));
        assertEquals("read write admin", ((Map<?, ?>) sent.get("context")).get("scope"), "what it asks for, before narrowing");
        Client client = this.store.get(AGENT);
        assertEquals(List.of("read"), client.getRestrictedScopes());
        assertEquals(this.clock.epochSecond() + 900L, expiresAt(client));
        assertEquals("permit", this.events.only(FederationEvents.PDP_CONSULTED).fields().get("decision"));
    }
}
