package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustMarkValidator;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import com.pingidentity.ps.oidf.pf.testkit.FakeClientStore;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A required Trust Mark is validated from the registration's own budget (plan item S5c). When that budget runs out -
 * of requests or of time - before the mark is checked, the entity has not been shown to lack it: the registration is
 * refused as a federation that could not be answered in time, 503, not as an entity without the mark, 400.
 */
class RegistrationTrustMarkBudgetTest {
    private static final String TA = "https://ta.example.com";
    private static final String AGENT = "https://agent.example.com";
    private static final String TMI = "https://tmi.example.com";
    private static final String OP = "https://op.example.com";
    private static final String CERTIFIED = "https://ta.example.com/marks/certified";

    private final MutableClock clock = MutableClock.startingNow();
    private final PublicJsonWebKey tmiKey = Keys.ec("tmi-1");
    private final FakeClientStore store = new FakeClientStore();
    private EventCapture events;

    @BeforeEach
    void setUp() {
        this.events = EventCapture.install();
    }

    @AfterEach
    void tearDown() {
        this.events.close();
        FederationRuntimeConfig.resetForTests();
    }

    private static void requireCertified(boolean statusCheck) {
        Map<String, String> env = new HashMap<>();
        env.put(FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV, "false");
        env.put(FederationRuntimeConfig.REQUIRED_TRUST_MARKS_ENV, "{\"*\": [\"" + CERTIFIED + "\"]}");
        env.put(FederationRuntimeConfig.TRUST_MARK_STATUS_CHECK_ENV, Boolean.toString(statusCheck));
        FederationRuntimeConfig.install(FederationRuntimeConfig.from(env::get, name -> null));
    }

    private Federation federation() {
        String mark = Statements.spec(TrustMarkValidator.TRUST_MARK_TYP).claim("iss", TMI).claim("sub", AGENT).claim("trust_mark_type", CERTIFIED)
                .sign(this.tmiKey, this.clock);
        return Federation.builder(this.clock).anchor(TA).leaf(AGENT, TA).leaf(TMI, TA).keys(TMI, this.tmiKey)
                .metadata(AGENT, "oauth_client", RegistrationFixtures.agentMetadata("automatic", "explicit"))
                .metadata(TMI, "federation_entity", Map.of("federation_trust_mark_status_endpoint", TMI + "/status"))
                .entityConfiguration(TA, s -> s.claim("trust_mark_issuers", Map.of(CERTIFIED, List.of(TMI))))
                .entityConfiguration(AGENT, s -> s.claim("trust_marks", List.of(Map.of("trust_mark_type", CERTIFIED, "trust_mark", mark))))
                .build();
    }

    /** A service whose registrations get {@code requests} requests and {@code deadline}; the status endpoint answers after {@code delay}. */
    private RegistrationService service(Federation f, int requests, Duration deadline, Duration delay, String status) throws Exception {
        ValidatorOptions options = ValidatorOptions.defaults().withClock(this.clock);
        HttpPostClient statusClient = (url, contentType, body, headers, accept) -> {
            Thread.sleep(delay.toMillis());
            String answer = Statements.spec(TrustMarkValidator.STATUS_RESPONSE_TYP).claim("iss", TMI)
                    .claim("trust_mark", java.net.URLDecoder.decode(body.substring("trust_mark=".length()), java.nio.charset.StandardCharsets.UTF_8))
                    .claim("status", status).withoutExp().sign(this.tmiKey, this.clock);
            return new HttpPostClient.Response(200, answer, Map.of());
        };
        return new RegistrationService(new RegistrationConfiguration(TA, false), f.validator(options, TA), this.store, RegistrationFixtures.signer(),
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((url, accept) -> {
                    throw new java.io.IOException("no RP key fetch expected: " + url);
                }, this.clock), new RegistrationCoordinator(8, 0L, options.withMaxFetches(requests), deadline, System::nanoTime), statusClient,
                RegistrationPolicy.fromEnvironment());
    }

    private static void assertNotChecked(RegistrationRejectedException e) {
        assertEquals(503, e.status());
        assertEquals("temporarily_unavailable", e.error());
        assertEquals(RegistrationRejectedException.Kind.TRANSPORT, e.kind());
        assertTrue(e.getMessage().contains("could not be checked") && e.getMessage().contains(CERTIFIED), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aMarkTheBudgetsRequestsDidNotReachIsNotAMarkTheEntityLacks() throws Exception {
        requireCertified(false);
        Federation f = this.federation();

        // The chain validates within two requests; the issuer's own chain needs more than are left.
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> this.service(f, 2, Duration.ofSeconds(25),
                Duration.ZERO, "active").explicitRegister(new ExplicitRegistrationRequest(AGENT, AGENT, f.chain(AGENT, TA), Map.of()), OP));

        assertNotChecked(e);
        assertNull(this.store.get(AGENT));
        assertEquals("temporarily_unavailable", this.events.withCode(FederationEvents.REGISTRATION_REFUSED).get(0).reason());
        assertEquals(0, this.events.withCode(FederationEvents.REGISTRATION_CREATED).size());
        assertNotNull(this.service(f, 3, Duration.ofSeconds(25), Duration.ZERO, "active")
                .explicitRegister(new ExplicitRegistrationRequest(AGENT, AGENT, f.chain(AGENT, TA), Map.of()), OP), "one request more is enough");
    }

    @Test
    void theAutomaticPathsBudgetRunningOutOnAMarkIsATransportFailure() throws Exception {
        requireCertified(false);
        Federation f = this.federation();

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> this.service(f, 1, Duration.ofSeconds(25), Duration.ZERO, "active").admit(AGENT, f.chain(AGENT, TA), OP));

        assertEquals(503, e.status());
        assertEquals(RegistrationRejectedException.Kind.TRANSPORT, e.kind());
        assertTrue(this.events.withCode(FederationEvents.REGISTRATION_REFUSED).stream()
                .anyMatch(event -> event.description().contains("before the Trust Marks were checked")), "the mark was left unchecked");
        assertNull(this.store.get(AGENT));
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aMarkWhoseCheckOutlastedTheDeadlineIsNotAMarkTheEntityLacks() throws Exception {
        requireCertified(true);
        Federation f = this.federation();

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> this.service(f, 24, Duration.ofMillis(300),
                Duration.ofMillis(500), "revoked").explicitRegister(new ExplicitRegistrationRequest(AGENT, AGENT, f.chain(AGENT, TA), Map.of()), OP));

        assertNotChecked(e);
        assertNull(this.store.get(AGENT));
    }

    @Test
    void withTheBudgetToSpareAMissingMarkIsStillTheEntitys() throws Exception {
        requireCertified(true);
        Federation f = this.federation();

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> this.service(f, 24, Duration.ofSeconds(25),
                Duration.ZERO, "revoked").admit(AGENT, f.chain(AGENT, TA), OP));

        assertEquals(400, e.status());
        assertEquals(RegistrationRejectedException.Kind.POLICY, e.kind());
    }
}
