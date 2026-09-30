package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.platform.component.ComponentRegistry;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import com.pingidentity.ps.oidf.platform.metrics.MetricSnapshot;
import com.pingidentity.ps.oidf.platform.metrics.SeriesSnapshot;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * The client attestation policy (plan item S4c): each {@code attestation_*} property parsed strictly and able only to
 * tighten the server's policy, the 30 s cache, the 503 when PingFederate cannot be asked, the start-up scan and the
 * events.
 */
class AttestationPolicyResolverTest {
    private static final String CLIENT = "https://rp.example.com/agent-1";
    private static final String ISSUER = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = ISSUER + "/as/token.oauth2";
    private static final ClientAttestationConfig GLOBAL = ClientAttestationUtils.defaultConfig(ISSUER, TOKEN_ENDPOINT);
    private static final Set<String> ALIASES = Set.of(TOKEN_ENDPOINT);

    private final List<Event> events = new ArrayList<>();

    @BeforeEach
    void capture() {
        Events.reset();
        Events.configure(this.events::add);
    }

    @AfterEach
    void release() {
        Events.reset();
        AttestationPolicyScan.resetForTests();
    }

    private static ClientAttestationPolicy parse(Map<String, String> properties) {
        Map<String, List<String>> values = new LinkedHashMap<>();
        properties.forEach((k, v) -> values.put(k, List.of(v)));
        return ClientAttestationPolicy.parse(CLIENT, values, false, w -> { });
    }

    private static ClientAttestationConfig effective(Map<String, String> properties) throws AttestationPolicyException {
        return parse(properties).apply(GLOBAL, ALIASES);
    }

    private static AttestationPolicyException refused(Map<String, String> properties) {
        return assertThrows(AttestationPolicyException.class, () -> effective(properties));
    }

    // ---- each property: tighten only --------------------------------------------------------------------------

    @Test
    void noPropertiesIsTheServersPolicy() throws Exception {
        ClientAttestationConfig config = effective(Map.of());
        assertEquals(AttestationPolicyResolver.fingerprint(GLOBAL), AttestationPolicyResolver.fingerprint(config));
        assertFalse(parse(Map.of()).attestationRequired());
        assertTrue(parse(Map.of()).known());
        assertEquals(CLIENT, parse(Map.of()).clientId());
    }

    @Test
    void aProofAgeCanOnlyShrink() throws Exception {
        assertEquals(30L, effective(Map.of(ClientAttestationPolicy.POP_MAX_AGE, "30")).popMaxAgeSeconds());
        assertEquals(30L, effective(Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "30")).dpopMaxAgeSeconds());
        assertEquals(300L, effective(Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "300")).dpopMaxAgeSeconds());
        for (String property : List.of(ClientAttestationPolicy.POP_MAX_AGE, ClientAttestationPolicy.DPOP_MAX_AGE)) {
            AttestationPolicyException e = refused(Map.of(property, "301"));
            assertEquals("loosens", e.problem());
            assertEquals(property, e.property());
            assertEquals(CLIENT, e.clientId());
            assertFalse(e.getMessage().contains("301"), "the value is never in the message: " + e.getMessage());
            // 0 and less read as "no limit" in the verifier: the loosest value of all, refused as out of range.
            assertEquals("unparsable", refused(Map.of(property, "0")).problem());
            assertEquals("unparsable", refused(Map.of(property, "-1")).problem());
            assertEquals("unparsable", refused(Map.of(property, "5m")).problem());
        }
    }

    @Test
    void aServerWithNoProofAgeLimitTakesAnyLimit() throws Exception {
        ClientAttestationConfig unlimited = ClientAttestationConfig.builder().popMaxAgeSeconds(0L).build();
        assertEquals(900L, parse(Map.of(ClientAttestationPolicy.POP_MAX_AGE, "900")).apply(unlimited, Set.of()).popMaxAgeSeconds());
    }

    @Test
    void theClockSkewCanOnlyShrink() throws Exception {
        assertEquals(0, effective(Map.of(ClientAttestationPolicy.CLOCK_SKEW, "0")).allowedClockSkewSeconds());
        assertEquals(10, effective(Map.of(ClientAttestationPolicy.CLOCK_SKEW, "10")).allowedClockSkewSeconds());
        assertEquals("loosens", refused(Map.of(ClientAttestationPolicy.CLOCK_SKEW, "61")).problem());
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.CLOCK_SKEW, "-1")).problem());
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.CLOCK_SKEW, "2147483648")).problem());
        ClientAttestationConfig noSkew = ClientAttestationConfig.builder().allowedClockSkewSeconds(0).build();
        assertEquals("loosens", assertThrows(AttestationPolicyException.class,
                () -> parse(Map.of(ClientAttestationPolicy.CLOCK_SKEW, "1")).apply(noSkew, Set.of())).problem());
    }

    @Test
    void theChallengeCanOnlyTurnOn() throws Exception {
        assertTrue(effective(Map.of(ClientAttestationPolicy.CHALLENGE_REQUIRED, "true")).challengeRequired());
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.CHALLENGE_REQUIRED, "TRUE")).problem());
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.CHALLENGE_REQUIRED, "true ")).problem());
        assertFalse(effective(Map.of(ClientAttestationPolicy.CHALLENGE_REQUIRED, "false")).challengeRequired());
        ClientAttestationConfig challenged = ClientAttestationConfig.builder().challengeRequired(true).build();
        assertTrue(parse(Map.of(ClientAttestationPolicy.CHALLENGE_REQUIRED, "false")).apply(challenged, Set.of()).challengeRequired(),
                "false leaves a server that requires a challenge requiring one");
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.CHALLENGE_REQUIRED, "yes")).problem());
    }

    @Test
    void anAlgorithmSetCanOnlyNarrow() throws Exception {
        assertEquals(Set.of("ES256"), effective(Map.of(ClientAttestationPolicy.ACCEPTED_ALGS, "ES256, HS256")).attestationAlgorithms());
        assertEquals(Set.of("PS256", "ES256"), effective(Map.of(ClientAttestationPolicy.POP_ALGS, "PS256 ES256")).popAlgorithms());
        assertEquals(Set.of("ES256"), effective(Map.of(ClientAttestationPolicy.DPOP_ALGS, "ES256")).dpopAlgorithms());
        assertEquals(Set.of("ES256"), effective(Map.of(ClientAttestationPolicy.DPOP_ALGS, ",ES256")).dpopAlgorithms());
        for (String property : List.of(ClientAttestationPolicy.ACCEPTED_ALGS, ClientAttestationPolicy.POP_ALGS,
                ClientAttestationPolicy.DPOP_ALGS)) {
            assertEquals("empty_intersection", refused(Map.of(property, "HS256,none")).problem());
            assertEquals("unparsable", refused(Map.of(property, ", ,")).problem());
            assertEquals("unparsable", refused(Map.of(property, " ES256")).problem());
        }
    }

    @Test
    void requiredClaimsOnlyGrow() throws Exception {
        ClientAttestationConfig workload = ClientAttestationConfig.builder().requiredDisclosedClaims(Set.of("workload")).build();
        assertEquals(Set.of("workload", "authorization_details"),
                parse(Map.of(ClientAttestationPolicy.REQUIRED_CLAIMS, "authorization_details")).apply(workload, Set.of())
                        .requiredDisclosedClaims());
        assertEquals(Set.of("workload"), parse(Map.of()).apply(workload, Set.of()).requiredDisclosedClaims());
    }

    /**
     * RFC 9449 §4.3, item 9: "The htu claim matches the HTTP URI value for the HTTP request in which the JWT was
     * received, ignoring any query and fragment parts." A pin naming another URL could never be met.
     */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void anHtuPinMustNameAUrlThisServerAnswersAt() throws Exception {
        String base = "https://mtls.as.example.com:8443/as/token.oauth2";
        Set<String> aliases = Set.of(base, TOKEN_ENDPOINT);
        ClientAttestationPolicy pinnedToIssuer = parse(Map.of(ClientAttestationPolicy.EXPECTED_HTU, "HTTPS://AS.example.com:443/as/token.oauth2"));
        assertEquals("HTTPS://AS.example.com:443/as/token.oauth2", pinnedToIssuer.apply(GLOBAL, aliases).expectedHtu(),
                "RFC 3986 normalisation: case and the default port");
        assertEquals(base, parse(Map.of(ClientAttestationPolicy.EXPECTED_HTU, base)).apply(GLOBAL, aliases).expectedHtu());
        assertEquals("foreign_htu", refused(Map.of(ClientAttestationPolicy.EXPECTED_HTU, "https://other.example/as/token.oauth2")).problem());
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.EXPECTED_HTU, "/as/token.oauth2")).problem());
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.EXPECTED_HTU, TOKEN_ENDPOINT + "?x=1")).problem());
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.EXPECTED_HTU, TOKEN_ENDPOINT + "#f")).problem());
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.EXPECTED_HTU, "ftp://as.example.com/t")).problem());
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.EXPECTED_HTU, "https://exa mple/")).problem());
        assertEquals("unparsable", refused(Map.of(ClientAttestationPolicy.EXPECTED_HTU, "https:///as/token.oauth2")).problem());
        assertEquals("http://as.example.com/as/token.oauth2", parse(Map.of(ClientAttestationPolicy.EXPECTED_HTU,
                "http://as.example.com/as/token.oauth2")).apply(GLOBAL, Set.of("http://as.example.com/as/token.oauth2")).expectedHtu());
        // At another endpoint (PAR, from S4d) a token endpoint pin does not apply.
        assertEquals(TOKEN_ENDPOINT, parse(Map.of(ClientAttestationPolicy.EXPECTED_HTU, "https://other.example/as/token.oauth2"))
                .apply(GLOBAL, Set.of()).expectedHtu());
    }

    @Test
    void urlsAreComparedAfterNormalisation() {
        assertEquals("https://as.example.com/", ClientAttestationPolicy.normalise("HTTPS://As.Example.com:443"));
        assertEquals("http://as.example.com/a", ClientAttestationPolicy.normalise("http://as.example.com:80/b/../a?q#f"));
        assertEquals("https://as.example.com:8443/a", ClientAttestationPolicy.normalise("https://as.example.com:8443/a"));
        assertEquals("http://h:443/", ClientAttestationPolicy.normalise("http://h:443"));
        assertEquals("https://h:80/", ClientAttestationPolicy.normalise("https://h:80"));
        assertEquals("://h/", ClientAttestationPolicy.normalise("//h"));
        assertEquals("a b", ClientAttestationPolicy.normalise("a b"));
        assertEquals(":///a", ClientAttestationPolicy.normalise("/a"));
        assertEquals("mailto:///", ClientAttestationPolicy.normalise("mailto:x"));
    }

    @Test
    void attestationRequiredIsStrict() {
        assertTrue(parse(Map.of(ClientAttestationPolicy.REQUIRED, "true")).attestationRequired());
        assertFalse(parse(Map.of(ClientAttestationPolicy.REQUIRED, "false")).attestationRequired());
        AttestationPolicyException e = parse(Map.of(ClientAttestationPolicy.REQUIRED, "1")).invalid();
        assertNotNull(e);
        assertEquals(ClientAttestationPolicy.REQUIRED, e.property());
    }

    @Test
    void theDevelopmentProfileReadsTheOldBooleanSpellingsWithAWarning() throws Exception {
        List<String> warnings = new ArrayList<>();
        for (String yes : List.of("yes", "on", "1", "YES")) {
            ClientAttestationPolicy p = ClientAttestationPolicy.parse(CLIENT,
                    Map.of(ClientAttestationPolicy.CHALLENGE_REQUIRED, List.of(yes), ClientAttestationPolicy.REQUIRED, List.of(yes)),
                    true, warnings::add);
            assertTrue(p.apply(GLOBAL, ALIASES).challengeRequired());
            assertTrue(p.attestationRequired());
        }
        for (String no : List.of("no", "off", "0")) {
            assertFalse(ClientAttestationPolicy.parse(CLIENT, Map.of(ClientAttestationPolicy.REQUIRED, List.of(no)), true, warnings::add)
                    .attestationRequired());
        }
        assertTrue(warnings.get(0).contains("write true"), warnings.get(0));
        assertTrue(ClientAttestationPolicy.parse(CLIENT, Map.of(ClientAttestationPolicy.REQUIRED, List.of("TRUE ")), true,
                warnings::add).attestationRequired(), "a padded, upper-case true");
        assertFalse(ClientAttestationPolicy.parse(CLIENT, Map.of(ClientAttestationPolicy.REQUIRED, List.of("False")), true,
                warnings::add).attestationRequired());
        assertTrue(warnings.stream().anyMatch(w -> w.contains("remove them")), warnings.toString());
        assertNotNull(ClientAttestationPolicy.parse(CLIENT, Map.of(ClientAttestationPolicy.REQUIRED, List.of("maybe")), true,
                warnings::add).invalid(), "only the listed spellings");
    }

    @Test
    void aPropertyHoldingTwoValuesIsRefusedAndBlankIsUnset() throws Exception {
        Map<String, List<String>> two = Map.of(ClientAttestationPolicy.POP_MAX_AGE, List.of("30", "60"));
        assertEquals("unparsable", ClientAttestationPolicy.parse(CLIENT, two, false, w -> { }).invalid().problem());
        Map<String, List<String>> blank = new HashMap<>();
        blank.put(ClientAttestationPolicy.POP_MAX_AGE, java.util.Arrays.asList(" ", null));
        blank.put(ClientAttestationPolicy.DPOP_MAX_AGE, null);
        assertEquals(300L, ClientAttestationPolicy.parse(CLIENT, blank, false, w -> { }).apply(GLOBAL, ALIASES).popMaxAgeSeconds());
    }

    @Test
    void aPaddedValueIsRefusedInProductionAndReadTrimmedInDevelopment() throws Exception {
        Map<String, List<String>> padded = Map.of(ClientAttestationPolicy.POP_MAX_AGE, List.of(" 30 "));
        AttestationPolicyException e = ClientAttestationPolicy.parse(CLIENT, padded, false, w -> { }).invalid();
        assertEquals("unparsable", e.problem());
        assertEquals(ClientAttestationPolicy.POP_MAX_AGE, e.property());
        List<String> warnings = new ArrayList<>();
        assertEquals(30L, ClientAttestationPolicy.parse(CLIENT, padded, true, warnings::add).apply(GLOBAL, ALIASES).popMaxAgeSeconds());
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains(ClientAttestationPolicy.POP_MAX_AGE), warnings.get(0));
    }

    @Test
    void anUnknownClientHasTheServersPolicy() throws Exception {
        ClientAttestationPolicy unknown = ClientAttestationPolicy.unknown("nobody");
        assertFalse(unknown.known());
        assertNull(unknown.invalid());
        assertEquals(AttestationPolicyResolver.fingerprint(GLOBAL), AttestationPolicyResolver.fingerprint(unknown.apply(GLOBAL, ALIASES)));
    }

    @Test
    void theFingerprintCoversEveryMemberAndIgnoresOrder() {
        String base = AttestationPolicyResolver.fingerprint(GLOBAL);
        assertEquals(64, base.length());
        assertEquals(base, AttestationPolicyResolver.fingerprint(ClientAttestationUtils.defaultConfig(ISSUER, TOKEN_ENDPOINT)));
        assertNotEquals(base, AttestationPolicyResolver.fingerprint(ClientAttestationUtils.defaultConfig(ISSUER, TOKEN_ENDPOINT + "x")));
        assertNotEquals(base, AttestationPolicyResolver.fingerprint(ClientAttestationConfig.builder().expectedAudience(ISSUER)
                .expectedHtu(TOKEN_ENDPOINT).dpopMaxAgeSeconds(30L).build()));
    }

    // ---- the resolver: cache and failure ------------------------------------------------------------------------

    /** A clock the test moves. */
    private static final class TestClock extends Clock {
        Instant now = Instant.parse("2026-09-30T00:00:00Z");

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return this.now;
        }
    }

    @Test
    void aClientsPolicyIsKeptForThirtySeconds() throws Exception {
        TestClock clock = new TestClock();
        AtomicInteger lookups = new AtomicInteger();
        Map<String, List<String>> props = new HashMap<>(Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, List.of("30")));
        AttestationPolicyResolver resolver = AttestationPolicyResolver.over(id -> {
            lookups.incrementAndGet();
            return props;
        }, clock, () -> false);

        ClientAttestationPolicy first = resolver.policy(CLIENT);
        props.put(ClientAttestationPolicy.DPOP_MAX_AGE, List.of("20"));
        clock.now = clock.now.plus(AttestationPolicyResolver.TTL).minusMillis(1);
        assertSame(first, resolver.policy(CLIENT), "within 30 s the kept policy answers");
        assertEquals(1, lookups.get());
        clock.now = clock.now.plusMillis(1);
        assertEquals(20L, resolver.policy(CLIENT).apply(GLOBAL, ALIASES).dpopMaxAgeSeconds(), "at 30 s it is read again");
        assertEquals(2, lookups.get());
        resolver.invalidate(CLIENT);
        resolver.policy(CLIENT);
        assertEquals(3, lookups.get());
        resolver.invalidateAll();
        assertEquals(0, resolver.cached());
        assertEquals(Duration.ofSeconds(30), AttestationPolicyResolver.TTL);
    }

    @Test
    void anUnknownClientIsKeptTooAndABlankIdIsNotLookedUp() throws Exception {
        AtomicInteger lookups = new AtomicInteger();
        AttestationPolicyResolver resolver = AttestationPolicyResolver.over(id -> {
            lookups.incrementAndGet();
            return null;
        }, new TestClock(), () -> false);
        assertFalse(resolver.policy("nobody").known());
        assertFalse(resolver.policy("nobody").known());
        assertEquals(1, lookups.get());
        assertFalse(resolver.policy(" ").known());
        assertFalse(resolver.policy(null).known());
        assertEquals(1, lookups.get());
    }

    @Test
    void theCacheIsBounded() throws Exception {
        AttestationPolicyResolver resolver = AttestationPolicyResolver.over(id -> Map.of(), new TestClock(), () -> false);
        for (int i = 0; i < AttestationPolicyResolver.MAX_ENTRIES + 5; i++) {
            resolver.policy("client-" + i);
        }
        assertEquals(AttestationPolicyResolver.MAX_ENTRIES, resolver.cached());
    }

    @Test
    void aLookupThatFailsIsUnavailableAndNotKept() {
        AtomicInteger lookups = new AtomicInteger();
        AttestationPolicyResolver resolver = AttestationPolicyResolver.over(id -> {
            lookups.incrementAndGet();
            throw new IllegalStateException("database down");
        }, new TestClock(), () -> false);
        AttestationPolicyResolver.Unavailable e = assertThrows(AttestationPolicyResolver.Unavailable.class, () -> resolver.policy(CLIENT));
        assertTrue(e.getMessage().contains("IllegalStateException"), e.getMessage());
        assertThrows(AttestationPolicyResolver.Unavailable.class, () -> resolver.policy(CLIENT));
        assertEquals(2, lookups.get());
        AttestationPolicyResolver linkage = AttestationPolicyResolver.over(id -> {
            throw new NoClassDefFoundError("org/sourceid/saml20/domain/mgmt/MgmtFactory");
        }, new TestClock(), () -> false);
        assertThrows(AttestationPolicyResolver.Unavailable.class, () -> linkage.policy(CLIENT));
    }

    @Test
    void theSharedResolverAsksPingFederateAndIsUnavailableOutsideIt() {
        assertSame(AttestationPolicyResolver.shared(), AttestationPolicyResolver.shared());
        assertThrows(AttestationPolicyResolver.Unavailable.class, () -> AttestationPolicyResolver.shared().policy("no-pf-here"));
    }

    @Test
    void aClientsExtendedPropertiesAreReadAsTheyAreStored() throws Exception {
        Client client = client(CLIENT, Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "30"));
        client.getExtendedParams().put("empty", new ParamValues());
        client.getExtendedParams().put("null", null);
        Map<String, List<String>> read = AttestationPolicyResolver.properties(client);
        assertEquals(List.of("30"), read.get(ClientAttestationPolicy.DPOP_MAX_AGE));
        assertEquals(List.of(), read.get("empty"));
        assertEquals(List.of(), read.get("null"));
        Client none = new Client();
        none.setExtendedParams(null);
        assertEquals(Map.of(), AttestationPolicyResolver.properties(none));

        AttestationPolicyResolver resolver = AttestationPolicyResolver.over(AttestationPolicyResolver.from(store(client)),
                new TestClock(), () -> false);
        assertEquals(30L, resolver.policy(CLIENT).apply(GLOBAL, ALIASES).dpopMaxAgeSeconds());
        assertFalse(resolver.policy("other").known());
    }

    // ---- effective policy, as both routes build it ---------------------------------------------------------------

    @Test
    void theEffectivePolicyStartsFromTheRequiredClaimsAndPinsOnlyTheTokenEndpoint() throws Exception {
        AttestationPolicyResolver pinned = AttestationPolicyResolver.over(
                id -> Map.of(ClientAttestationPolicy.EXPECTED_HTU, List.of("https://as.example.com/as/token.oauth2")), new TestClock(), () -> false);
        String base = "https://mtls.as.example.com";
        assertEquals("https://as.example.com/as/token.oauth2",
                ClientAttestationUtils.effectivePolicy(pinned, CLIENT, ISSUER, base, "/as/token.oauth2").expectedHtu(),
                "the issuer's token endpoint is an alias of the base URL's");
        assertEquals(ISSUER + "/as/par.oauth2",
                ClientAttestationUtils.effectivePolicy(pinned, CLIENT, ISSUER, base, "/as/par.oauth2").expectedHtu());
        assertNull(ClientAttestationUtils.effectivePolicy(pinned, CLIENT, null, null, "/as/token.oauth2").expectedHtu(),
                "no issuer: no URL to pin to, and the verifier refuses a DPoP proof");
        System.setProperty("oidf.attestation.required.claims", "workload");
        try {
            assertEquals(Set.of("workload"), ClientAttestationUtils.effectivePolicy(CriterionTesting.NO_CLIENTS, CLIENT, ISSUER, null,
                    "/as/token.oauth2").requiredDisclosedClaims());
        } finally {
            System.clearProperty("oidf.attestation.required.claims");
        }
    }

    // ---- the start-up scan ---------------------------------------------------------------------------------------

    private static Client client(String id, Map<String, String> properties) {
        Client client = new Client();
        client.setClientId(id);
        Map<String, ParamValues> params = new HashMap<>();
        properties.forEach((k, v) -> {
            ParamValues values = new ParamValues();
            values.setElements(List.of(v));
            params.put(k, values);
        });
        client.setExtendedParams(params);
        return client;
    }

    private static ClientStore store(Client... clients) {
        return new ClientStore() {
            @Override
            public void add(Client client) {
            }

            @Override
            public void update(Client client) {
            }

            @Override
            public Client get(String clientId) {
                return java.util.Arrays.stream(clients).filter(c -> c.getClientId().equals(clientId)).findFirst().orElse(null);
            }

            @Override
            public Collection<Client> getAll() {
                return List.of(clients);
            }

            @Override
            public void disable(Client client) {
            }
        };
    }

    private static ComponentParts.Part part() {
        return new ComponentParts(new ComponentRegistry(), Clock.systemUTC()).begin("ATTESTATION_AUTH", AttestationPolicyScan.PART);
    }

    @Test
    void theScanPutsClientsWithRefusedPropertiesIntoHealthByIdAndNeverByValue() {
        ComponentParts.Part part = part();
        AttestationPolicyResolver resolver = AttestationPolicyResolver.over(id -> null, Clock.systemUTC(), () -> false);
        List<String> bad = AttestationPolicyScan.runOnce(part, store(
                client("good", Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "30")),
                client("loose", Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "3600")),
                client("garbled", Map.of(ClientAttestationPolicy.REQUIRED, "sometimes"))), resolver);

        assertEquals(List.of("loose", "garbled"), bad);
        assertEquals(ComponentState.DEGRADED, part.status().state());
        String detail = part.status().reason();
        assertTrue(detail.contains("loose (attestation_dpop_max_age)") && detail.contains("garbled (attestation_required)"), detail);
        assertFalse(detail.contains("3600") || detail.contains("sometimes"), "never a value: " + detail);
        assertEquals(2, this.events.stream().filter(e -> e.code().equals(AttestationEvents.POLICY_INVALID)).count());
        assertEquals(AttestationEvents.SCAN, this.events.get(0).fields().get("endpoint"));

        // Found again ten minutes later: still in health, not a second event.
        AttestationPolicyScan.runOnce(part, store(client("loose", Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "3600"))), resolver);
        assertEquals(2, this.events.size());

        // Fixed: the part is ready.
        assertEquals(List.of(), AttestationPolicyScan.runOnce(part, store(client("loose", Map.of())), resolver));
        assertEquals(ComponentState.READY, part.status().state());
    }

    @Test
    void theScanNamesAsManyClientsAsTheDetailHoldsAndCountsTheRest() {
        ComponentParts.Part part = part();
        Client[] clients = new Client[23];
        for (int i = 0; i < clients.length; i++) {
            clients[i] = client("c" + i, Map.of(ClientAttestationPolicy.CLOCK_SKEW, "x"));
        }
        AttestationPolicyScan.runOnce(part, store(clients), AttestationPolicyResolver.over(id -> null, Clock.systemUTC(), () -> false));
        String reason = part.status().reason();
        assertTrue(reason.startsWith("23 client(s)"), reason);
        assertTrue(reason.matches(".* and \\d+ more"), reason);
        assertTrue(reason.length() <= AttestationPolicyScan.DETAIL, reason);
        String one = AttestationPolicyScan.detail(List.of("x".repeat(300) + " (attestation_clock_skew)"));
        assertTrue(one.endsWith("1 not named here (see the log)"), one);
        assertEquals("1 client(s) with refused attestation properties, answered 401 invalid_client: a (attestation_required)",
                AttestationPolicyScan.detail(List.of("a (attestation_required)")));
    }

    @Test
    void aScanThatCannotReadTheClientsIsDegradedAndNeverThrows() {
        ComponentParts.Part part = part();
        ClientStore broken = new ClientStore() {
            @Override
            public void add(Client client) {
            }

            @Override
            public void update(Client client) {
            }

            @Override
            public Client get(String clientId) {
                return null;
            }

            @Override
            public Collection<Client> getAll() {
                throw new IllegalStateException("no PingFederate");
            }

            @Override
            public void disable(Client client) {
            }
        };
        assertNull(AttestationPolicyScan.runOnce(part, broken, CriterionTesting.NO_CLIENTS));
        assertEquals(ComponentState.DEGRADED, part.status().state());
        assertTrue(part.status().reason().contains("IllegalStateException"), part.status().reason());
        assertEquals(List.of(), AttestationPolicyScan.runOnce(part, store(), CriterionTesting.NO_CLIENTS));
        ClientStore none = store();
        assertEquals(List.of(), AttestationPolicyScan.runOnce(part, new ClientStore() {
            @Override
            public void add(Client client) {
            }

            @Override
            public void update(Client client) {
            }

            @Override
            public Client get(String clientId) {
                return none.get(clientId);
            }

            @Override
            public Collection<Client> getAll() {
                return null;
            }

            @Override
            public void disable(Client client) {
            }
        }, CriterionTesting.NO_CLIENTS));
    }

    /** The scan runs on the webapp copy's executor, started by the filter; a second start while it runs does nothing. */
    @Test
    void theScanStartsOnceOnTheManagedExecutor() throws Exception {
        AttestationPolicyScan.resetForTests();
        int before = AttestationPolicyScan.starts();
        AttestationPolicyScan.start(store(), CriterionTesting.NO_CLIENTS);
        AttestationPolicyScan.start(store(), CriterionTesting.NO_CLIENTS);
        assertEquals(before + 1, AttestationPolicyScan.starts());
        assertTrue(com.pingidentity.ps.oidf.platform.exec.ManagedExecutors.snapshot().stream()
                .anyMatch(s -> s.name().equals(AttestationPolicyScan.JOB) && !s.closed()));
        AttestationPolicyScan.resetForTests();
    }

    // ---- events counted ------------------------------------------------------------------------------------------

    private static long counted(String code, String outcome) {
        for (MetricSnapshot metric : Metrics.snapshot()) {
            if (metric.getName().equals("oidf_events_total")) {
                for (SeriesSnapshot series : metric.getSeries()) {
                    if (series.getLabelValues().contains(code) && series.getLabelValues().contains(outcome)) {
                        return (long) series.getValue();
                    }
                }
            }
        }
        return 0L;
    }

    @Test
    void everyDecisionIsAnEventAndCounted() {
        long invalid = counted(AttestationEvents.POLICY_INVALID, "failure");
        long verified = counted(AttestationEvents.VERIFIED, "success");
        long refused = counted(AttestationEvents.REFUSED, "failure");
        AttestationEvents.policyInvalid(AttestationEvents.FILTER, refused(Map.of(ClientAttestationPolicy.DPOP_MAX_AGE, "301")));
        AttestationEvents.verified(AttestationEvents.CRITERION, CLIENT, "https://attester.example.com");
        AttestationEvents.refused(AttestationEvents.FILTER, CLIENT, "invalid_client");

        assertEquals(invalid + 1, counted(AttestationEvents.POLICY_INVALID, "failure"));
        assertEquals(verified + 1, counted(AttestationEvents.VERIFIED, "success"));
        assertEquals(refused + 1, counted(AttestationEvents.REFUSED, "failure"));
        Event policy = this.events.get(0);
        assertEquals("attestation", policy.component());
        assertEquals(CLIENT, policy.subject());
        assertEquals("loosens", policy.reason());
        assertEquals(Map.of("property", ClientAttestationPolicy.DPOP_MAX_AGE, "endpoint", AttestationEvents.FILTER), policy.fields());
        assertEquals("https://attester.example.com", this.events.get(1).partner());
        assertEquals("federation", this.events.get(2).component());
        assertTrue(this.events.stream().allMatch(Event::audit));
    }

    @Test
    void theSubjectTokensSubAndActAreReadOnlyWhenTheyAreWhatTheySay() throws Exception {
        org.jose4j.jwt.JwtClaims claims = new org.jose4j.jwt.JwtClaims();
        assertNull(SubjectTokenVerifier.subject(null));
        assertNull(SubjectTokenVerifier.subject(claims));
        claims.setClaim("sub", " ");
        assertNull(SubjectTokenVerifier.subject(claims));
        claims.setClaim("sub", 7);
        assertNull(SubjectTokenVerifier.subject(claims));
        claims.setClaim("sub", "alice");
        assertEquals("alice", SubjectTokenVerifier.subject(claims));
        assertNull(SubjectTokenVerifier.act(null));
        claims.setClaim("act", " ");
        assertNull(SubjectTokenVerifier.act(claims));
        claims.setClaim("act", "{\"sub\":\"a\"}");
        assertEquals(Map.of("sub", "a"), SubjectTokenVerifier.act(claims));
    }

    @Test
    void aReusedVerificationMustNameTheClientAndCarryItsPolicy() {
        Map<String, Object> verified = Map.of("client_id", CLIENT, ClientAttestationUtils.POLICY_FINGERPRINT_KEY, "f");
        assertNull(ClientAttestationUtils.reusedVerificationProblem(verified, CLIENT, "f"));
        assertNotNull(ClientAttestationUtils.reusedVerificationProblem(verified, null, "f"));
        assertNotNull(ClientAttestationUtils.reusedVerificationProblem(verified, "other", "f"));
        assertNotNull(ClientAttestationUtils.reusedVerificationProblem(verified, CLIENT, "g"));
    }

    @Test
    void onlyATokenExchangeWithOneSubjectTokenIsLookedAt() {
        jakarta.servlet.http.HttpServletRequest request = org.mockito.Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        org.mockito.Mockito.when(request.getParameter("grant_type")).thenReturn(ClientAttestationUtils.TOKEN_EXCHANGE_GRANT);
        assertNull(ClientAttestationUtils.verifiedSubjectTokenSubject(request, ISSUER, CriterionTesting.NO_SUBJECT_TOKENS));
        org.mockito.Mockito.when(request.getParameterValues("subject_token")).thenReturn(new String[0]);
        assertNull(ClientAttestationUtils.verifiedSubjectTokenSubject(request, ISSUER, CriterionTesting.NO_SUBJECT_TOKENS));
    }
}
