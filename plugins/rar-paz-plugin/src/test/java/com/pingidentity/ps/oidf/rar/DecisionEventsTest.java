package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.metrics.MetricSnapshot;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import com.pingidentity.ps.oidf.platform.metrics.SeriesSnapshot;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Phase 3 decision 7, plan item O-2: {@code enrich}'s decision step emits one {@code rar.decision.*} event per detail,
 * catalogued in the plugin's {@code rar} catalogue, with the principal hashed, and each one counted in
 * {@code oidf_events_total}.
 */
class DecisionEventsTest {

    private final List<Event> events = new ArrayList<>();

    @BeforeEach
    void capture() {
        Events.reset();
        Events.configure(events::add);
    }

    @AfterEach
    void release() {
        Events.reset();
    }

    private static AuthorizationDetailContext context() {
        return new AuthorizationDetailContext.Builder().withClientId("agent-client").withUserKey("alice").build();
    }

    private static AuthorizationDetail salesAgent(String... regions) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "sales_agent");
        detail.put("sales_regions", List.of(regions));
        return new AuthorizationDetail(detail);
    }

    private static AttestationAwareRarProcessor processor(PdpClient client, boolean failOpen) {
        return new AttestationAwareRarProcessor(client, GovernanceEngineConfig.builder().pdpUrl("https://pdp/decide")
                .failOpenOnError(failOpen).build());
    }

    private static PdpClient answering(DecisionResponse response) {
        return (type, detail, subject, owner, clientId, source) -> response;
    }

    private static long counted(String code, String outcome) {
        for (MetricSnapshot metric : Metrics.snapshot()) {
            if (metric.getName().equals("oidf_events_total")) {
                for (SeriesSnapshot series : metric.getSeries()) {
                    if (series.getLabelValues().equals(List.of(code, outcome))) {
                        return series.getCount() > 0 ? series.getCount() : (long) series.getValue();
                    }
                }
            }
        }
        return 0;
    }

    private Event only() {
        assertEquals(1, events.size(), events.toString());
        Event event = events.get(0);
        assertEquals("rar", event.component());
        assertEquals("sales_agent", event.fields().get("type"));
        assertEquals("authenticated", event.fields().get("principal_source"));
        assertEquals(PrincipalResolver.hashForLog("alice"), event.fields().get("principal"), "the principal is hashed");
        assertEquals("agent-client", event.fields().get("client_id"));
        assertFalse(event.toString().contains("alice"), "never the principal itself");
        assertFalse(event.toString().contains("EMEA"), "never a detail value");
        return event;
    }

    @Test
    void aPermitIsPermittedAndCounted() throws Exception {
        long before = counted(DecisionEvents.PERMITTED, "success");
        processor(answering(new DecisionResponse("PERMIT", true, List.of(), "{}")), false).enrich(salesAgent("EMEA"), context(), Map.of());
        Event event = only();
        assertEquals(DecisionEvents.PERMITTED, event.code());
        assertFalse(event.isFailure());
        assertEquals(before + 1, counted(DecisionEvents.PERMITTED, "success"), "counted in oidf_events_total");
    }

    @Test
    void eachWayADecisionIsRefusedHasItsReasonClass() {
        record Case(String reason, PdpClient client) { }
        List<Case> cases = List.of(
                new Case(DecisionEvents.REASON_DENY, answering(new DecisionResponse("DENY", false, List.of(), "{}"))),
                new Case(DecisionEvents.REASON_WIDENED, answering(new DecisionResponse("PERMIT", true,
                        List.of(new DecisionResponse.Statement("sales_regions", List.of("EMEA", "AMER"))), "{}"))),
                new Case(DecisionEvents.REASON_UNREACHABLE, (type, detail, subject, owner, clientId, source) -> {
                    throw new PdpUnavailableException("connection refused", null);
                }),
                new Case(DecisionEvents.REASON_FAILED, (type, detail, subject, owner, clientId, source) -> {
                    throw new IOException("malformed");
                }));
        for (Case c : cases) {
            events.clear();
            long before = counted(DecisionEvents.DENIED, "failure");
            assertThrows(AuthorizationDetailProcessingException.class,
                    () -> processor(c.client(), false).enrich(salesAgent("EMEA"), context(), Map.of()), c.reason());
            Event event = only();
            assertEquals(DecisionEvents.DENIED, event.code(), c.reason());
            assertTrue(event.isFailure());
            assertEquals(c.reason(), event.reason());
            assertEquals(before + 1, counted(DecisionEvents.DENIED, "failure"), c.reason());
        }
    }

    @Test
    void failingOpenIsItsOwnEvent() throws Exception {
        long before = counted(DecisionEvents.FAIL_OPEN, "success");
        processor((type, detail, subject, owner, clientId, source) -> {
            throw new PdpUnavailableException("connection refused", null);
        }, true).enrich(salesAgent("EMEA"), context(), Map.of());
        assertEquals(DecisionEvents.FAIL_OPEN, only().code());
        assertEquals(before + 1, counted(DecisionEvents.FAIL_OPEN, "success"));
    }

    /** A refusal before any PDP call - here the model's, for an undeclared field - is not a decision. */
    @Test
    void aRefusalBeforeThePdpIsNoDecision() {
        Map<String, Object> detail = new LinkedHashMap<>(Map.of("type", "sales_agent", "colour", "red"));
        assertThrows(AuthorizationDetailProcessingException.class, () -> processor(answering(
                new DecisionResponse("PERMIT", true, List.of(), "{}")), false).enrich(new AuthorizationDetail(detail), context(), Map.of()));
        assertEquals(List.of(), events);
    }
}
