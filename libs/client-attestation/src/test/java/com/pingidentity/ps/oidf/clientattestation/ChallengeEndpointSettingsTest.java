package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.servlet.ChallengeEndpointServlet;
import com.pingidentity.ps.oidf.clientattestation.servlet.ClientAttestationChallengeServlet;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.metrics.MetricSnapshot;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import com.pingidentity.ps.oidf.platform.metrics.SeriesSnapshot;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.ProfileAudit;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Each challenge endpoint's init-params reach its own namespace and no other: the authorization server's endpoint
 * sizes {@code oidf:as:challenge:*}, the attester's {@code oidf:cas:challenge:*}. Before plan item S4b there was one
 * endpoint and one store, so its settings were everybody's. From 0.6.0 they are read through the
 * {@code attestation-challenge} catalogue, strictly (plan item ST-5), each endpoint is a part of the component that
 * consumes its challenges (S-9), its in-memory stores need the {@code in-memory-state} risk in production (PR-2), and
 * every challenge issued or refused is an event, counted (O-2). Here rather than beside the servlets because
 * {@link AttestationSupport#reset()} is package-private, and these tests change process-wide state.
 */
class ChallengeEndpointSettingsTest {

    /** OIDF_ACCEPTED_RISKS=in-memory-state: a standalone node that has accepted keeping its state in memory. */
    private static final AcceptedRisks IN_MEMORY = AcceptedRisks.parse("in-memory-state", LocalDate.of(2026, 9, 30));

    private final List<Event> events = new CopyOnWriteArrayList<>();

    @BeforeEach
    void inMemoryStores() {
        assumeTrue(System.getenv("OIDF_REDIS_URL") == null && System.getenv("REDIS_URL") == null,
                "the environment configures a Redis URL, which these tests would not control");
        System.clearProperty("oidf.redis.url");
        AttestationSupport.reset();
        ProfileRefusals.resetForTests();
        AttestationSupport.acceptedRisksForTests(IN_MEMORY);
        Events.reset();
        // Only the challenge catalogue's events: a part's start also emits platform.component.changed.
        Events.configure(e -> {
            if (e.component().equals(ChallengeEndpointServlet.EVENTS)) {
                this.events.add(e);
            }
        });
    }

    @AfterEach
    void forget() {
        AttestationSupport.reset();
        ProfileRefusals.resetForTests();
        Events.reset();
    }

    private static ServletConfig config(Map<String, String> params) {
        ServletConfig config = mock(ServletConfig.class);
        params.forEach((name, value) -> when(config.getInitParameter(name)).thenReturn(value));
        return config;
    }

    /** An endpoint over the attester's namespace, as attestation-issuer's is; this module cannot see that class. */
    private static ChallengeEndpointServlet attesterEndpoint() {
        return new ChallengeEndpointServlet(StoreNamespace.CAS, "GET") {
            private static final long serialVersionUID = 1L;
        };
    }

    private static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    private static int status(ChallengeEndpointServlet servlet, String method, String address) throws Exception {
        return answer(servlet, method, address).status();
    }

    /** What an endpoint answered. */
    private record Answer(int status, String body) {
    }

    private static Answer answer(ChallengeEndpointServlet servlet, String method, String address) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn(method);
        when(req.getRemoteAddr()).thenReturn(address);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(body));
        when(resp.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(jakarta.servlet.WriteListener listener) {
            }

            @Override
            public void write(int b) {
                body.write(b);
            }
        });
        // The public entry point, as the container calls it: the HTTP overload is protected, in another package.
        servlet.service((jakarta.servlet.ServletRequest) req, (jakarta.servlet.ServletResponse) resp);
        org.mockito.ArgumentCaptor<Integer> status = org.mockito.ArgumentCaptor.forClass(Integer.class);
        verify(resp).setStatus(status.capture());
        return new Answer(status.getValue(), body.toString());
    }

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

    // ---- the settings, strictly -------------------------------------------------------------------------------------

    @Test
    void theAuthorizationServersTtlStaysWithItsOwnChallenges() throws Exception {
        new ClientAttestationChallengeServlet().init(config(Map.of("challengeTtlSeconds", " 90 ")));

        assertEquals(ComponentState.READY, part("ClientAttestationChallengeServlet").state());
        assertEquals(Startup.ATTESTATION_AUTH, part("ClientAttestationChallengeServlet").component());
        assertEquals(90L, AttestationSupport.challengeService(StoreNamespace.AS).ttlSeconds(), "a padded number is trimmed");
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, AttestationSupport.challengeService(StoreNamespace.CAS).ttlSeconds(),
                "the attester's challenges keep the default, whichever endpoint starts first");
    }

    @Test
    void theAttestersSizeAndTtlStayWithItsOwnChallenges() throws Exception {
        AttestationChallengeService before = AttestationSupport.challengeService(StoreNamespace.AS);
        attesterEndpoint().init(config(Map.of("challengeCacheMaxEntries", "2", "challengeTtlSeconds", " ")));

        assertEquals(Startup.ATTESTATION_ISSUER, part("ChallengeEndpointServlet").component());
        AttestationChallengeService cas = AttestationSupport.challengeService(StoreNamespace.CAS);
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, cas.ttlSeconds(), "a size with a blank TTL keeps the default TTL");
        String first = cas.issue();
        cas.issue();
        cas.issue();
        assertEquals(AttestationChallengeService.Consumption.UNKNOWN, cas.consumeChallenge(first), "a bound of two evicted the first");
        assertSame(before, AttestationSupport.challengeService(StoreNamespace.AS), "the authorization server's store is untouched");
    }

    @Test
    void noChallengeSettingConfiguresTheDefaults() throws Exception {
        AttestationChallengeService as = AttestationSupport.challengeService(StoreNamespace.AS);
        attesterEndpoint().init(config(Map.of()));
        assertEquals(ComponentState.READY, part("ChallengeEndpointServlet").state());
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, AttestationSupport.challengeService(StoreNamespace.CAS).ttlSeconds());
        assertSame(as, AttestationSupport.challengeService(StoreNamespace.AS));
    }

    @Test
    void aValueThatIsNotAWholeNumberFailsThePartNamingTheSettingAndConfiguresNothing() throws Exception {
        AttestationChallengeService before = AttestationSupport.challengeService(StoreNamespace.CAS);
        for (String name : List.of("challengeTtlSeconds", "challengeCacheMaxEntries", "challengeRateLimitPerWindow",
                "challengeRateLimitWindowSeconds", "challengeRateLimitMaxCallers")) {
            ChallengeEndpointServlet endpoint = attesterEndpoint();
            assertDoesNotThrow(() -> endpoint.init(config(Map.of(name, "soon"))), "init never throws (S-9)");
            PartStatus part = part("ChallengeEndpointServlet");
            assertEquals(ComponentState.FAILED_CONFIG, part.state(), name);
            assertTrue(part.reason().contains(name), part.reason());
            assertSame(before, AttestationSupport.challengeService(StoreNamespace.CAS), name + ": the store is the one it had");
            assertEquals(503, status(endpoint, "GET", "10.0.1.1"), "the gate answers first");
        }
        assertTrue(this.events.isEmpty(), "a gated request is not a challenge refused");
    }

    @Test
    void aTtlOrSizeOutsideItsRangeFailsThePartAndKeepsTheStoreItHad() throws Exception {
        AttestationChallengeService before = AttestationSupport.challengeService(StoreNamespace.CAS);
        attesterEndpoint().init(config(Map.of("challengeTtlSeconds", "0")));
        assertEquals(ComponentState.FAILED_CONFIG, part("ChallengeEndpointServlet").state());
        assertTrue(part("ChallengeEndpointServlet").reason().contains("challengeTtlSeconds"), part("ChallengeEndpointServlet").reason());
        attesterEndpoint().init(config(Map.of("challengeCacheMaxEntries", "0")));
        assertEquals(ComponentState.FAILED_CONFIG, part("ChallengeEndpointServlet").state(), "the in-memory store refuses 0");
        assertSame(before, AttestationSupport.challengeService(StoreNamespace.CAS));
    }

    @Test
    void eachRateSettingAloneTakesEffectWithTheOthersDefaulted() throws Exception {
        ChallengeEndpointServlet perWindow = attesterEndpoint();
        perWindow.init(config(Map.of("challengeRateLimitPerWindow", "1")));
        assertEquals(200, status(perWindow, "GET", "10.0.2.1"));
        assertEquals(429, status(perWindow, "GET", "10.0.2.1"));

        ChallengeEndpointServlet window = attesterEndpoint();
        window.init(config(Map.of("challengeRateLimitWindowSeconds", "1")));
        assertEquals(200, status(window, "GET", "10.0.2.2"));

        ChallengeEndpointServlet callers = attesterEndpoint();
        callers.init(config(Map.of("challengeRateLimitMaxCallers", "1")));
        assertEquals(200, status(callers, "GET", "10.0.2.3"));
        assertEquals(200, status(callers, "GET", "10.0.2.4"));
    }

    @Test
    void theAuthorizationServersEndpointStillSizesItsReplayCache() throws Exception {
        AttestationReplayCache before = AttestationSupport.replayCache(StoreNamespace.AS);
        new ClientAttestationChallengeServlet().init(config(Map.of("replayCacheMaxEntries", "16")));
        assertNotSame(before, AttestationSupport.replayCache(StoreNamespace.AS));

        AttestationReplayCache sized = AttestationSupport.replayCache(StoreNamespace.AS);
        new ClientAttestationChallengeServlet().init(config(Map.of("replayCacheMaxEntries", "sixteen")));
        assertEquals(ComponentState.FAILED_CONFIG, part("ClientAttestationChallengeServlet").state());
        assertTrue(part("ClientAttestationChallengeServlet").reason().contains("replayCacheMaxEntries"),
                part("ClientAttestationChallengeServlet").reason());
        assertSame(sized, AttestationSupport.replayCache(StoreNamespace.AS), "a value that is not a whole number configures nothing");
    }

    // ---- in-memory state under the production profile (PR-2) ---------------------------------------------------------

    @Test
    void eachNamespacesInMemoryStoresAreRefusedInProductionWithoutTheRisk() throws Exception {
        AttestationSupport.acceptedRisksForTests(AcceptedRisks.none());
        ClientAttestationChallengeServlet as = new ClientAttestationChallengeServlet();
        as.init(config(Map.of("challengeTtlSeconds", "90")));
        PartStatus asPart = part("ClientAttestationChallengeServlet");
        assertEquals(ComponentState.REFUSED, asPart.state(), asPart.reason());
        assertTrue(asPart.reason().contains("'in-memory-state'"), asPart.reason());
        assertTrue(asPart.reason().contains("OIDF_REDIS_URL"), asPart.reason());
        assertTrue(asPart.reason().contains("oidf:as:*"), asPart.reason());
        assertEquals(AttestationChallengeService.DEFAULT_TTL_SECONDS, AttestationSupport.challengeService(StoreNamespace.AS).ttlSeconds(),
                "a refused part configures nothing");
        assertEquals(503, status(as, "POST", "10.0.3.1"));

        ChallengeEndpointServlet cas = attesterEndpoint();
        cas.init(config(Map.of()));
        PartStatus casPart = part("ChallengeEndpointServlet");
        assertEquals(ComponentState.REFUSED, casPart.state());
        assertTrue(casPart.reason().contains("oidf:cas:*"), casPart.reason());
        assertTrue(ProfileRefusals.codeRefusals().stream().anyMatch(v -> v.components().equals(List.of(Startup.ATTESTATION_AUTH))));
        assertTrue(ProfileRefusals.codeRefusals().stream().anyMatch(v -> v.components().equals(List.of(Startup.ATTESTATION_ISSUER))));
    }

    @Test
    void theRiskAcceptedOrDevelopmentAllowsTheInMemoryStores() throws Exception {
        new ClientAttestationChallengeServlet().init(config(Map.of()));
        assertEquals(ComponentState.READY, part("ClientAttestationChallengeServlet").state(), "the risk accepted");

        AttestationSupport.acceptedRisksForTests(AcceptedRisks.none());
        ProfileRefusals.publish(ProfileAudit.Result.empty(DeploymentProfile.DEVELOPMENT));
        ChallengeEndpointServlet cas = attesterEndpoint();
        cas.init(config(Map.of()));
        assertEquals(ComponentState.READY, part("ChallengeEndpointServlet").state(), "development: a WARN, not a refusal");
        assertTrue(ProfileRefusals.codeRefusals().isEmpty());
        assertEquals(200, status(cas, "GET", "10.0.3.2"));
    }

    @Test
    void theRuleIsTheNamespacesOwnAndRedisNeedsNoRisk() {
        assertDoesNotThrow(() -> AttestationSupport.requireSharedState(StoreNamespace.AS, true, AcceptedRisks.none()));
        assertEquals(Startup.ATTESTATION_AUTH, AttestationSupport.componentOf(StoreNamespace.AS));
        assertEquals(Startup.ATTESTATION_ISSUER, AttestationSupport.componentOf(StoreNamespace.CAS));
        assertEquals(Startup.FEDERATION, AttestationSupport.componentOf(StoreNamespace.FED_ENDPOINT));
        assertEquals(Startup.OPERATOR_API, AttestationSupport.componentOf(StoreNamespace.ADMIN_DPOP));
        assertTrue(AttestationSupport.inMemoryStores(StoreNamespace.CAS).contains("evidence bindings"));
        assertFalse(AttestationSupport.inMemoryStores(StoreNamespace.AS).contains("evidence"));
        assertTrue(AttestationSupport.inMemoryStores(StoreNamespace.FED_ENDPOINT).contains("oidf:fed:endpoint:*"));
    }

    // ---- the challenge events (O-2) ----------------------------------------------------------------------------------

    @Test
    void everyChallengeIssuedOrRefusedIsAnEventAndCountedAndNoneCarriesTheChallenge() throws Exception {
        long issued = counted(ChallengeEndpointServlet.ISSUED, "success");
        long refused = counted(ChallengeEndpointServlet.REFUSED, "failure");
        ChallengeEndpointServlet cas = attesterEndpoint();
        cas.init(config(Map.of("challengeRateLimitPerWindow", "1")));

        Answer ok = answer(cas, "GET", "10.0.4.1");
        assertEquals(200, ok.status());
        assertEquals(429, status(cas, "GET", "10.0.4.1"));
        assertEquals(405, status(cas, "POST", "10.0.4.2"));

        assertEquals(issued + 1, counted(ChallengeEndpointServlet.ISSUED, "success"));
        assertEquals(refused + 2, counted(ChallengeEndpointServlet.REFUSED, "failure"));
        assertEquals(3, this.events.size());
        assertEquals(List.of("CAS", "CAS", "CAS"), this.events.stream().map(e -> e.fields().get("surface")).toList());
        assertEquals(List.of(ChallengeEndpointServlet.ISSUED, ChallengeEndpointServlet.REFUSED, ChallengeEndpointServlet.REFUSED),
                this.events.stream().map(Event::code).toList());
        assertEquals("rate_limited", this.events.get(1).reason());
        assertEquals("method_not_allowed", this.events.get(2).reason());
        assertTrue(this.events.stream().allMatch(e -> e.component().equals(ChallengeEndpointServlet.EVENTS)));
        String challenge = (String) org.jose4j.json.JsonUtil.parseJson(ok.body()).get("attestation_challenge");
        assertFalse(this.events.toString().contains(challenge), "the challenge value is never an event field");
    }

    @Test
    void theAuthorizationServersEventsNameItsSurface() throws Exception {
        ClientAttestationChallengeServlet as = new ClientAttestationChallengeServlet();
        as.init(config(Map.of()));
        assertEquals(200, status(as, "POST", "10.0.5.1"));
        assertEquals("AS", this.events.get(0).fields().get("surface"));
    }
}
