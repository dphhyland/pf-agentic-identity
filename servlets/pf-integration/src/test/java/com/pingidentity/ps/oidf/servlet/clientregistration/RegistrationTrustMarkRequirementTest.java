package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustMarkValidator;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import com.pingidentity.ps.oidf.federation.policy.FederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.NarrowingObligations;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecision;
import com.pingidentity.ps.oidf.federation.policy.PolicyDecisionRequest;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.pf.FederationPolicySupport;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import com.pingidentity.ps.oidf.pf.testkit.FakeClientStore;
import com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationService.Admission;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A deployment can require Trust Marks before it registers an entity ({@code OIDF_FEDERATION_REQUIRED_TRUST_MARKS}).
 * These tests run registration over a real federation: the agent's chain, the anchor that says whose marks it
 * recognises, and the issuer whose chain has to validate before its mark counts.
 */
class RegistrationTrustMarkRequirementTest {
    private static final String TA = "https://ta.example.com";
    private static final String AGENT = "https://agent.example.com";
    private static final String TMI = "https://tmi.example.com";
    private static final String OP = "https://op.example.com";
    private static final String CERTIFIED = "https://ta.example.com/marks/certified";

    private final MutableClock clock = MutableClock.startingNow();
    private final PublicJsonWebKey tmiKey = Keys.ec("tmi-1");
    private final FakeClientStore store = new FakeClientStore();
    private final List<String> statusAsked = new ArrayList<>();
    private final List<PolicyDecisionRequest> asked = new ArrayList<>();
    private EventCapture events;

    @BeforeEach
    void setUp() {
        this.events = EventCapture.install();
    }

    @AfterEach
    void tearDown() {
        this.events.close();
        FederationRuntimeConfig.resetForTests();
        FederationPolicySupport.resetForTests();
    }

    private static void configure(String requiredMarks, boolean statusCheck) {
        Map<String, String> env = new HashMap<>();
        env.put(FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV, "false");
        env.put(FederationRuntimeConfig.REQUIRED_TRUST_MARKS_ENV, requiredMarks);
        env.put(FederationRuntimeConfig.TRUST_MARK_STATUS_CHECK_ENV, Boolean.toString(statusCheck));
        FederationRuntimeConfig.install(FederationRuntimeConfig.from(env::get, name -> null));
    }

    private String mark(PublicJsonWebKey signer) {
        return Statements.spec(TrustMarkValidator.TRUST_MARK_TYP).claim("iss", TMI).claim("sub", AGENT).claim("trust_mark_type", CERTIFIED)
                .sign(signer, this.clock);
    }

    /** The agent, carrying {@code marks}; the anchor recognises TMI for CERTIFIED; TMI answers status with {@code status}. */
    private Federation federation(List<String> marks) {
        Map<String, Object> metadata = new HashMap<>(RegistrationFixtures.agentMetadata("automatic", "explicit"));
        List<Map<String, Object>> entries = marks.stream().map(m -> Map.<String, Object>of("trust_mark_type", CERTIFIED, "trust_mark", m)).toList();
        Consumer<Statements.Spec> agent = s -> {
            if (!entries.isEmpty()) {
                s.claim("trust_marks", entries);
            }
        };
        return Federation.builder(this.clock).anchor(TA).leaf(AGENT, TA).leaf(TMI, TA).keys(TMI, this.tmiKey)
                .metadata(AGENT, "oauth_client", metadata)
                .metadata(TMI, "federation_entity", Map.of("federation_trust_mark_status_endpoint", TMI + "/status"))
                .entityConfiguration(TA, s -> s.claim("trust_mark_issuers", Map.of(CERTIFIED, List.of(TMI))))
                .entityConfiguration(AGENT, agent)
                .build();
    }

    private RegistrationService service(Federation f, String status) throws Exception {
        return this.service(f, status, RegistrationPolicy.fromEnvironment());
    }

    /** A service whose policy decisions come from {@code pdp}, which records what it was asked. */
    private RegistrationService service(Federation f, FederationPolicyDecisionPoint pdp) throws Exception {
        return this.service(f, "active", new RegistrationPolicy(point -> request -> {
            this.asked.add(request);
            return pdp.decide(request);
        }, PdpSettings.DEFAULTS));
    }

    private RegistrationService service(Federation f, String status, RegistrationPolicy policy) throws Exception {
        HttpPostClient statusClient = (url, contentType, body, headers, accept) -> {
            this.statusAsked.add(url);
            String answer = Statements.spec(TrustMarkValidator.STATUS_RESPONSE_TYP).claim("iss", TMI)
                    .claim("trust_mark", java.net.URLDecoder.decode(body.substring("trust_mark=".length()), java.nio.charset.StandardCharsets.UTF_8))
                    .claim("status", status).withoutExp().sign(this.tmiKey, this.clock);
            return new HttpPostClient.Response(200, answer, Map.of());
        };
        return new RegistrationService(new RegistrationConfiguration(TA, false), f.validator(ValidatorOptions.defaults().withClock(this.clock), TA),
                this.store, RegistrationFixtures.signer(), new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock),
                new RpKeyMaterial((url, accept) -> {
                    throw new java.io.IOException("no RP key fetch expected: " + url);
                }, this.clock), RegistrationService.coordinatorFor(AutoRegistrationSettings.DEFAULTS), statusClient, policy);
    }

    private Admission admit(Federation f) throws Exception {
        return this.service(f, "active").admit(AGENT, f.chain(AGENT, TA), OP);
    }

    @Test
    @Requirement("OIDFED §7.3(3)")
    void anAgentCarryingTheRequiredMarkIsRegistered() throws Exception {
        configure("{\"*\": [\"" + CERTIFIED + "\"]}", false);

        assertEquals(Admission.REGISTERED, this.admit(this.federation(List.of(this.mark(this.tmiKey)))));
        assertNotNull(this.store.get(AGENT));
        assertEquals(List.of(), this.statusAsked, "status is not checked unless the deployment asks for it");
    }

    @Test
    void anAgentWithoutItIsNotRegistered() throws Exception {
        configure("{\"oauth_client\": [\"" + CERTIFIED + "\"]}", false);

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> this.admit(this.federation(List.of())));

        assertEquals(400, e.status());
        assertEquals("invalid_client_metadata", e.error());
        assertEquals(RegistrationRejectedException.Kind.POLICY, e.kind());
        assertTrue(e.getMessage().contains(CERTIFIED), e.getMessage());
        assertNull(this.store.get(AGENT));
        FederationEvent refused = this.events.withCode(FederationEvents.REGISTRATION_REFUSED).get(0);
        assertEquals(AGENT, refused.subject());
        assertTrue(refused.audit(), "a refusal belongs in the audit log");
        assertEquals(CERTIFIED, refused.fields().get("missing_trust_marks"));
        assertEquals("oauth_client", refused.fields().get("entity_type"));
        this.events.assertNoJwtIn();
    }

    @Test
    @Requirement("OIDFED §7.3(5.7)")
    void aMarkThatDoesNotVerifyDoesNotCount() throws Exception {
        configure("{\"*\": [\"" + CERTIFIED + "\"]}", false);

        assertThrows(RegistrationRejectedException.class, () -> this.admit(this.federation(List.of(this.mark(Keys.ec("tmi-1"))))));
        assertNull(this.store.get(AGENT));
    }

    @Test
    void onlyTheListsForTheTypeBeingRegisteredApply() throws Exception {
        configure("{\"openid_relying_party\": [\"" + CERTIFIED + "\"]}", false);

        assertEquals(Admission.REGISTERED, this.admit(this.federation(List.of())), "an agent registers as oauth_client");
    }

    @Test
    @Requirement({"OIDFED §7.3(7)", "OIDFED §8.4.2(5.8)"})
    void aMarkItsIssuerHasRevokedDoesNotCountWhenStatusIsChecked() throws Exception {
        configure("{\"*\": [\"" + CERTIFIED + "\"]}", true);
        Federation f = this.federation(List.of(this.mark(this.tmiKey)));

        assertThrows(RegistrationRejectedException.class, () -> this.service(f, "revoked").admit(AGENT, f.chain(AGENT, TA), OP));
        assertEquals(List.of(TMI + "/status"), this.statusAsked.subList(0, 1));
        assertNull(this.store.get(AGENT));

        this.statusAsked.clear();
        assertEquals(Admission.REGISTERED, this.service(f, "active").admit(AGENT, f.chain(AGENT, TA), OP));
        assertEquals(List.of(TMI + "/status"), this.statusAsked);
    }

    @Test
    void explicitRegistrationRequiresTheMarksToo() throws Exception {
        configure("{\"*\": [\"" + CERTIFIED + "\"]}", false);
        Federation without = this.federation(List.of());
        Federation with = this.federation(List.of(this.mark(this.tmiKey)));

        assertThrows(RegistrationRejectedException.class, () -> this.service(without, "active")
                .explicitRegister(new ExplicitRegistrationRequest(AGENT, AGENT, without.chain(AGENT, TA), Map.of()), OP));
        assertEquals(AGENT, this.service(with, "active")
                .explicitRegister(new ExplicitRegistrationRequest(AGENT, AGENT, with.chain(AGENT, TA), Map.of()), OP).clientId());
    }

    @Test
    @Requirement("AUTHZEN-1.0 §5.5")
    void aPolicyDecisionCanRequireAMarkTheDeploymentDoesNot() throws Exception {
        configure(null, false);
        FederationPolicyDecisionPoint certifiedOnly = request -> PolicyDecision.permit(new NarrowingObligations(null, null, null, null,
                Set.of(CERTIFIED)));
        Federation without = this.federation(List.of());
        Federation with = this.federation(List.of(this.mark(this.tmiKey)));

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> this.service(without, certifiedOnly).admit(AGENT, without.chain(AGENT, TA), OP));
        assertTrue(e.getMessage().endsWith("which the policy decision requires"), e.getMessage());
        assertEquals(CERTIFIED, this.events.withCode(FederationEvents.REGISTRATION_REFUSED).get(0).fields().get("missing_trust_marks"));
        assertNull(this.store.get(AGENT));

        assertEquals(Admission.REGISTERED, this.service(with, certifiedOnly).admit(AGENT, with.chain(AGENT, TA), OP));
        assertNull(this.asked.get(0).subjectProperties().get("trust_marks"), "nothing was verified before the PDP asked for it");
    }

    @Test
    void theMarksAreValidatedOnceHoweverManyThingsRequireThem() throws Exception {
        configure("{\"oauth_client\": [\"" + CERTIFIED + "\"]}", true);
        Federation f = this.federation(List.of(this.mark(this.tmiKey)));

        assertEquals(Admission.REGISTERED, this.service(f, request -> PolicyDecision.permit(new NarrowingObligations(null, null, null, null,
                Set.of(CERTIFIED)))).admit(AGENT, f.chain(AGENT, TA), OP));

        assertEquals(List.of(TMI + "/status"), this.statusAsked, "the deployment and the policy decision both required it; its issuer was asked once");
    }

    @Test
    void thePdpHearsWhichMarksVerifiedWhenTheDeploymentChecked() throws Exception {
        configure("{\"oauth_client\": [\"" + CERTIFIED + "\"]}", false);
        Federation f = this.federation(List.of(this.mark(this.tmiKey)));

        this.service(f, request -> PolicyDecision.permit(NarrowingObligations.NONE)).admit(AGENT, f.chain(AGENT, TA), OP);

        assertEquals(List.of(CERTIFIED), this.asked.get(0).subjectProperties().get("trust_marks"));
    }
}
